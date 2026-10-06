import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';

export interface ScimRequestContext {
  tenantId: string;
  tokenId: string;
}

/**
 * SCIM provisioning uses its own single-purpose bearer token (ScimToken),
 * not a user's JWT — an IdP's provisioning connector is a machine client
 * with no user session, and scoping it to "SCIM only, one tenant" is
 * tighter than handing out a general API key.
 */
@Injectable()
export class ScimAuthGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const authHeader: string | undefined = req.headers['authorization'];
    const token = authHeader?.replace(/^Bearer\s+/i, '');

    if (!token) {
      throw new UnauthorizedException('Missing SCIM bearer token');
    }

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const record = await this.prisma.scimToken.findUnique({ where: { tokenHash } });

    if (!record || record.revokedAt) {
      throw new UnauthorizedException('Invalid or revoked SCIM token');
    }

    // Best-effort, non-blocking usage tracking.
    this.prisma.scimToken.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } }).catch(() => undefined);

    const ctx: ScimRequestContext = { tenantId: record.tenantId, tokenId: record.id };
    req.scim = ctx;
    return true;
  }
}
