import { Injectable, NotFoundException } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class ApiKeysService {
  constructor(private readonly prisma: PrismaService) {}

  async create(tenantId: string, userId: string, name: string, scopes: string[]) {
    const rawKey = `sk_live_${randomBytes(32).toString('hex')}`;
    const keyHash = createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.slice(0, 12);

    const record = await this.prisma.apiKey.create({
      data: {
        tenantId,
        userId,
        name,
        keyHash,
        keyPrefix,
        scopes,
      },
    });

    // Return raw key ONLY once
    return {
      id: record.id,
      name: record.name,
      keyPrefix: record.keyPrefix,
      scopes: record.scopes,
      key: rawKey,
      createdAt: record.createdAt,
    };
  }

  async list(tenantId: string) {
    return this.prisma.apiKey.findMany({
      where: { tenantId, revokedAt: null },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async revoke(tenantId: string, id: string) {
    const key = await this.prisma.apiKey.findFirst({ where: { id, tenantId } });
    if (!key) throw new NotFoundException('API key not found');

    await this.prisma.apiKey.update({
      where: { id },
      data: { revokedAt: new Date() },
    });

    return { success: true };
  }
}
