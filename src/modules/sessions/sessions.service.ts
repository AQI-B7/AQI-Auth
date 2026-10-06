import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { UAParser } from 'ua-parser-js';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';

interface SessionRow {
  id: string;
  userAgent: string | null;
  ipAddress: string | null;
  lastActive: Date;
  createdAt: Date;
  expiresAt: Date;
}

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  async listSessions(userId: string, currentSessionId?: string) {
    const sessions = await this.prisma.session.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
      select: {
        id: true,
        userAgent: true,
        ipAddress: true,
        lastActive: true,
        createdAt: true,
        expiresAt: true,
      },
      orderBy: { lastActive: 'desc' },
    });

    return sessions.map((s: SessionRow) => this.toSessionView(s, currentSessionId));
  }

  async revokeSession(userId: string, sessionId: string) {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId },
    });
    if (!session) throw new NotFoundException('Session not found');

    await this.revokeSessionRows([session.id], session.expiresAt);
    return { success: true };
  }

  async revokeAllSessions(userId: string, exceptSessionId?: string) {
    const where: any = { userId, revokedAt: null };
    if (exceptSessionId) {
      where.id = { not: exceptSessionId };
    }

    const sessions = await this.prisma.session.findMany({ where, select: { id: true, expiresAt: true } });
    if (sessions.length === 0) return { success: true, revoked: 0 };

    await this.revokeSessionRows(
      sessions.map((s: { id: string }) => s.id),
      undefined,
      sessions,
    );

    return { success: true, revoked: sessions.length };
  }

  // ── Admin: cross-user session management within the same tenant ──
  // (the "session management dashboard" API — no UI here, but every
  // primitive a dashboard would call is exposed: list any member's
  // sessions, revoke any of them, on behalf of a tenant admin helping
  // a user who, say, lost a device.)

  async adminListSessions(tenantId: string, targetUserId: string) {
    const user = await this.prisma.user.findFirst({ where: { id: targetUserId, tenantId } });
    if (!user) throw new NotFoundException('User not found in your tenant');
    return this.listSessions(targetUserId);
  }

  async adminRevokeSession(tenantId: string, sessionId: string) {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, user: { tenantId } },
    });
    if (!session) throw new NotFoundException('Session not found in your tenant');

    await this.revokeSessionRows([session.id], session.expiresAt);
    return { success: true };
  }

  private async revokeSessionRows(
    sessionIds: string[],
    singleExpiresAt?: Date,
    sessionsWithExpiry?: { id: string; expiresAt: Date }[],
  ) {
    await this.prisma.$transaction([
      this.prisma.session.updateMany({
        where: { id: { in: sessionIds } },
        data: { revokedAt: new Date() },
      }),
      this.prisma.refreshToken.updateMany({
        where: { sessionId: { in: sessionIds } },
        data: { revokedAt: new Date() },
      }),
    ]);

    // Immediately invalidate any already-issued access token carrying
    // this sessionId, not just future refreshes — see RedisService
    // .revokeSession for why this is a distinct, necessary step.
    if (singleExpiresAt) {
      const ttl = Math.max(1, Math.ceil((singleExpiresAt.getTime() - Date.now()) / 1000));
      await this.redis.revokeSession(sessionIds[0], ttl);
    } else if (sessionsWithExpiry) {
      await Promise.all(
        sessionsWithExpiry.map((s) => {
          const ttl = Math.max(1, Math.ceil((s.expiresAt.getTime() - Date.now()) / 1000));
          return this.redis.revokeSession(s.id, ttl);
        }),
      );
    }
  }

  private toSessionView(session: SessionRow, currentSessionId?: string) {
    const device = session.userAgent ? describeUserAgent(session.userAgent) : 'Unknown device';
    return {
      id: session.id,
      device,
      ipAddress: session.ipAddress,
      lastActive: session.lastActive,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      isCurrent: currentSessionId ? session.id === currentSessionId : undefined,
    };
  }
}

function describeUserAgent(userAgent: string): string {
  const { browser, os, device } = UAParser(userAgent);
  const browserLabel = browser.name ? `${browser.name}${browser.version ? ` ${browser.version.split('.')[0]}` : ''}` : 'Unknown browser';
  const osLabel = os.name ? `${os.name}${os.version ? ` ${os.version}` : ''}` : 'Unknown OS';
  const deviceLabel = device.model ? ` (${device.model})` : '';
  return `${browserLabel} on ${osLabel}${deviceLabel}`;
}
