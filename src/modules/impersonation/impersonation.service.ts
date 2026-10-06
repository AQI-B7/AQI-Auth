import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';
import { AuthService } from '../auth/auth.service';
import { AuthUser } from '../../common/decorators/current-user.decorator';

/**
 * Support/admin impersonation, scoped to a single tenant: an admin
 * (permission `impersonate:*`) can act as another member of the SAME
 * tenant to reproduce a support issue. This is deliberately NOT a
 * cross-tenant platform-staff plane — see the schema comment on
 * ImpersonationSession for why.
 *
 * Safety properties, all enforced here rather than left to convention:
 *  - Every session requires a written reason and is permanently logged
 *    (ImpersonationSession + AuthEvent), independent of whether the
 *    session is ever explicitly ended.
 *  - The issued token is access-only (no refresh token), short-lived
 *    (IMPERSONATION_TTL_MINUTES, default 15), and carries an
 *    `impersonatedBy` claim on every request made with it — so any
 *    other service that logs actions can (and should) record who was
 *    really behind the wheel.
 *  - Impersonation cannot be chained: a request already carrying
 *    `impersonatedBy` cannot start a further impersonation.
 *  - An admin/wildcard-permission user cannot be impersonated — this
 *    tool is for reproducing a member's issue, not for one admin to act
 *    as another.
 *  - A session can be explicitly ended, which blacklists its JTI
 *    immediately (defense in depth beyond the short TTL).
 */
@Injectable()
export class ImpersonationService {
  private readonly logger = new Logger(ImpersonationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly redis: RedisService,
    private readonly authService: AuthService,
  ) {}

  async start(actor: AuthUser, targetUserId: string, reason: string, ip?: string, userAgent?: string) {
    if (actor.impersonatedBy) {
      throw new ForbiddenException('Cannot start a new impersonation session while already impersonating');
    }
    if (targetUserId === actor.userId) {
      throw new BadRequestException('Cannot impersonate yourself');
    }

    const target = await this.prisma.user.findFirst({
      where: { id: targetUserId, tenantId: actor.tenantId },
      include: { roles: { include: { role: true } } },
    });
    if (!target) {
      throw new NotFoundException('Target user not found in your tenant');
    }
    if (target.status !== 'ACTIVE') {
      throw new BadRequestException('Cannot impersonate an inactive user');
    }

    const targetPermissions = this.authService.collectPermissions(target.roles);
    if (targetPermissions.includes('*')) {
      throw new ForbiddenException('Cannot impersonate a user with administrative (wildcard) permissions');
    }

    const ttlMinutes = this.config.get<number>('impersonation.ttlMinutes') || 15;
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);

    // Create the audit record first so we have an id to bind the token's
    // own jti to — a session row always exists before any token that
    // could act as evidence of it, never the other way around.
    const session = await this.prisma.impersonationSession.create({
      data: {
        tenantId: actor.tenantId,
        actorUserId: actor.userId,
        targetUserId: target.id,
        reason,
        tokenJti: '', // filled in immediately below
        ipAddress: ip,
        userAgent,
        expiresAt,
      },
    });

    const { token, jti } = await this.authService.signAccessToken({
      userId: target.id,
      tenantId: target.tenantId,
      email: target.email,
      permissions: targetPermissions,
      sessionId: session.id,
      impersonatedBy: actor.userId,
      expiresInOverride: `${ttlMinutes}m`,
    });

    await this.prisma.impersonationSession.update({ where: { id: session.id }, data: { tokenJti: jti } });

    await this.prisma.authEvent.create({
      data: {
        userId: actor.userId,
        tenantId: actor.tenantId,
        type: 'impersonation.started',
        ipAddress: ip,
        userAgent,
        metadata: { targetUserId: target.id, targetEmail: target.email, reason, sessionId: session.id },
      },
    });

    this.logger.warn(
      `Impersonation started: actor=${actor.userId} target=${target.id} tenant=${actor.tenantId} reason="${reason}"`,
    );

    return {
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn: ttlMinutes * 60,
      expiresAt,
      impersonating: {
        id: target.id,
        email: target.email,
        firstName: target.firstName,
        lastName: target.lastName,
      },
      sessionId: session.id,
    };
  }

  /** Ends an impersonation session immediately by blacklisting its JTI,
   *  rather than waiting out the (already short) TTL. */
  async end(actor: AuthUser, sessionId: string) {
    const session = await this.prisma.impersonationSession.findFirst({
      where: { id: sessionId, tenantId: actor.tenantId },
    });
    if (!session) throw new NotFoundException('Impersonation session not found');

    // Only the actor who started it (or another holder of the
    // impersonate permission, for cleanup) can end it — checked by the
    // controller's permission guard; here we just enforce tenant scope.
    if (!session.endedAt) {
      const remainingTtl = Math.max(1, Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000));
      await this.redis.blacklistToken(session.tokenJti, remainingTtl);
      await this.prisma.impersonationSession.update({ where: { id: session.id }, data: { endedAt: new Date() } });

      await this.prisma.authEvent.create({
        data: {
          userId: session.actorUserId,
          tenantId: actor.tenantId,
          type: 'impersonation.ended',
          metadata: { targetUserId: session.targetUserId, sessionId: session.id },
        },
      });
    }

    return { success: true };
  }

  async listActive(tenantId: string) {
    return this.prisma.impersonationSession.findMany({
      where: { tenantId, endedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { startedAt: 'desc' },
    });
  }

  async listHistory(tenantId: string, limit = 50) {
    return this.prisma.impersonationSession.findMany({
      where: { tenantId },
      orderBy: { startedAt: 'desc' },
      take: Math.min(limit, 200),
    });
  }
}
