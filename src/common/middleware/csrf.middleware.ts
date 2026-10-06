import { Injectable, NestMiddleware, ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response, NextFunction } from 'express';
import { randomBytes, timingSafeEqual } from 'crypto';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Double-submit-cookie CSRF protection.
 *
 * This service is Bearer-token/JWT-only today — a cross-site form or
 * <img> tag can't forge an Authorization header, so classic CSRF isn't
 * exploitable against it as-is. This middleware exists as a safety net
 * for the moment any endpoint starts trusting a cookie for auth (a
 * browser client storing the refresh token in an httpOnly cookie is a
 * common, reasonable choice — `COOKIE_SECURE`/`cookie-parser` are
 * already wired up in this codebase for exactly that), and it is
 * designed to cost pure API/Bearer clients nothing:
 *
 *  - Requests with no cookies at all skip this check entirely.
 *  - Requests authenticated purely via `Authorization: Bearer` (no
 *    session/auth cookie present) also skip it.
 *  - Only once a request carries a cookie this service issued
 *    (identified by the `csrf_token` cookie itself having been set,
 *    which happens automatically on any response) do state-changing
 *    requests (POST/PUT/PATCH/DELETE) need to echo that same value back
 *    in the `X-CSRF-Token` header — something only same-origin
 *    JavaScript can read, not a third-party site.
 */
@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  constructor(private readonly config: ConfigService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const existingToken = req.cookies?.[CSRF_COOKIE];

    if (!existingToken) {
      // First time we're seeing this client: issue a token. Deliberately
      // NOT httpOnly — the whole point is that same-origin JS can read
      // it and echo it back; a cross-site attacker cannot read cookies
      // set for this origin no matter what.
      res.cookie(CSRF_COOKIE, randomBytes(32).toString('hex'), {
        httpOnly: false,
        secure: this.config.get<boolean>('cookieSecure') ?? false,
        sameSite: 'lax',
        path: '/',
      });
      // Nothing to verify yet on this first request.
      return next();
    }

    if (SAFE_METHODS.has(req.method)) {
      return next();
    }

    const headerToken = req.headers[CSRF_HEADER];
    if (!headerToken || Array.isArray(headerToken) || !safeCompare(headerToken, existingToken)) {
      throw new ForbiddenException('Missing or invalid CSRF token');
    }

    return next();
  }
}

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
