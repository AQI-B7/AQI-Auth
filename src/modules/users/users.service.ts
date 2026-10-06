import { Injectable, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly events: EventEmitter2,
  ) {}

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        imageUrl: true,
        emailVerified: true,
        status: true,
        tenantId: true,
        lastLoginAt: true,
        createdAt: true,
        bannedAt: true,
        roles: {
          include: { role: { select: { id: true, name: true, permissions: true } } },
        },
      },
    });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async listByTenant(tenantId: string) {
    return this.prisma.user.findMany({
      where: { tenantId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        status: true,
        emailVerified: true,
        lastLoginAt: true,
        bannedAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async updateProfile(userId: string, data: { firstName?: string; lastName?: string; imageUrl?: string }) {
    return this.prisma.user.update({
      where: { id: userId },
      data,
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        imageUrl: true,
        emailVerified: true,
      },
    });
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });
    if (!user.passwordHash) {
      throw new BadRequestException('Password login not enabled for this account');
    }

    const valid = await argon2.verify(user.passwordHash, currentPassword);
    if (!valid) throw new BadRequestException('Current password is incorrect');

    const passwordHash = await argon2.hash(newPassword, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    // Revoke other sessions
    await this.prisma.session.updateMany({
      where: { userId },
      data: { revokedAt: new Date() },
    });
    await this.prisma.refreshToken.updateMany({
      where: { userId },
      data: { revokedAt: new Date() },
    });

    return { success: true, message: 'Password changed. Please log in again.' };
  }

  async banUser(tenantId: string, targetUserId: string, reason?: string) {
    const user = await this.prisma.user.findFirst({ where: { id: targetUserId, tenantId } });
    if (!user) throw new NotFoundException('User not found');

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: targetUserId },
        data: { status: 'BANNED', bannedAt: new Date(), banReason: reason },
      }),
      this.prisma.session.updateMany({
        where: { userId: targetUserId },
        data: { revokedAt: new Date() },
      }),
      this.prisma.refreshToken.updateMany({
        where: { userId: targetUserId },
        data: { revokedAt: new Date() },
      }),
    ]);

    this.events.emit('user.banned', { tenantId, userId: targetUserId, reason });

    return { success: true };
  }

  async unbanUser(tenantId: string, targetUserId: string) {
    const user = await this.prisma.user.findFirst({ where: { id: targetUserId, tenantId } });
    if (!user) throw new NotFoundException('User not found');

    await this.prisma.user.update({
      where: { id: targetUserId },
      data: { status: 'ACTIVE', bannedAt: null, banReason: null },
    });

    return { success: true };
  }
}
