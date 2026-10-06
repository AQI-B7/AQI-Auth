import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * HTTP 423 Locked — distinct from 401 (bad credentials) and 429 (generic
 * rate limit) so clients can show "your account is temporarily locked,
 * try again in Xs" instead of a generic auth error, and so it's not
 * silently retried by naive client-side retry-on-401 logic.
 */
export class LockedException extends HttpException {
  constructor(message: string, retryAfterSeconds: number) {
    super(
      {
        statusCode: HttpStatus.LOCKED,
        error: 'Locked',
        message,
        retryAfterSeconds,
      },
      HttpStatus.LOCKED,
    );
  }
}
