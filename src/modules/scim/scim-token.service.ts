import { Injectable, NotFoundException } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class ScimTokenService {
  constructor(private readonly prisma: PrismaService) {}

  async create(tenantId: string, name: string) {
    const rawToken = `scim_${randomBytes(32).toString('hex')}`;
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');

    const record = await this.prisma.scimToken.create({
      data: { tenantId, name, tokenHash },
    });

    return {
      id: record.id,
      name: record.name,
      token: rawToken, // shown once, at creation — same convention as API keys
      createdAt: record.createdAt,
    };
  }

  async list(tenantId: string) {
    return this.prisma.scimToken.findMany({
      where: { tenantId, revokedAt: null },
      select: { id: true, name: true, lastUsedAt: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async revoke(tenantId: string, id: string) {
    const token = await this.prisma.scimToken.findFirst({ where: { id, tenantId } });
    if (!token) throw new NotFoundException('SCIM token not found');
    await this.prisma.scimToken.update({ where: { id }, data: { revokedAt: new Date() } });
    return { success: true };
  }
}
