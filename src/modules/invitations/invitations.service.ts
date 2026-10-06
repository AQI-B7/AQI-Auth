import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import * as argon2 from 'argon2';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { PrismaService } from '../../prisma/prisma.service';
import { EmailService } from '../email/email.service';

@Injectable()
export class InvitationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly events: EventEmitter2,
    private readonly emailService: EmailService,
  ) {}

  async create(tenantId: string, invitedById: string, email: string, roleId?: string) {
    const existing = await this.prisma.user.findFirst({
      where: { tenantId, email: email.toLowerCase() },
    });
    if (existing) throw new ConflictException('User already exists in this tenant');

    const pending = await this.prisma.invitation.findFirst({
      where: { tenantId, email: email.toLowerCase(), status: 'PENDING' },
    });
    if (pending) throw new ConflictException('Invitation already pending for this email');

    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');

    const invitation = await this.prisma.invitation.create({
      data: {
        tenantId,
        email: email.toLowerCase(),
        roleId,
        tokenHash,
        invitedById,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
    });

    const acceptLink = `${this.config.get<string>('frontendUrl')}/invitations/accept?token=${rawToken}`;
    await this.emailService.sendInvitation(invitation.email, acceptLink, invitation.expiresAt.toDateString());

    this.events.emit('invitation.created', {
      tenantId,
      invitationId: invitation.id,
      email: invitation.email,
    });

    return {
      id: invitation.id,
      email: invitation.email,
      expiresAt: invitation.expiresAt,
      // Only surfaced outside production; otherwise it must come by email.
      ...(this.config.get<string>('nodeEnv') === 'production' ? {} : { token: rawToken }),
    };
  }

  async list(tenantId: string) {
    return this.prisma.invitation.findMany({
      where: { tenantId },
      select: {
        id: true,
        email: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async revoke(tenantId: string, id: string) {
    const inv = await this.prisma.invitation.findFirst({ where: { id, tenantId } });
    if (!inv) throw new NotFoundException('Invitation not found');

    await this.prisma.invitation.update({
      where: { id },
      data: { status: 'REVOKED' },
    });

    return { success: true };
  }

  async accept(token: string, password: string, firstName: string, lastName?: string) {
    const tokenHash = createHash('sha256').update(token).digest('hex');

    const inv = await this.prisma.invitation.findUnique({
      where: { tokenHash },
      include: { tenant: true },
    });

    if (!inv || inv.status !== 'PENDING' || inv.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired invitation');
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    const result = await this.prisma.$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: {
          tenantId: inv.tenantId,
          email: inv.email,
          passwordHash,
          firstName,
          lastName,
          emailVerified: true,
          status: 'ACTIVE',
        },
      });

      if (inv.roleId) {
        await tx.userRole.create({
          data: { userId: user.id, roleId: inv.roleId },
        });
      } else {
        const memberRole = await tx.role.findFirst({
          where: { tenantId: inv.tenantId, name: 'member' },
        });
        if (memberRole) {
          await tx.userRole.create({
            data: { userId: user.id, roleId: memberRole.id },
          });
        }
      }

      await tx.invitation.update({
        where: { id: inv.id },
        data: { status: 'ACCEPTED', acceptedAt: new Date() },
      });

      return user;
    });

    this.events.emit('invitation.accepted', {
      tenantId: result.tenantId,
      invitationId: inv.id,
      userId: result.id,
      email: result.email,
    });

    return {
      user: {
        id: result.id,
        email: result.email,
        firstName: result.firstName,
        tenantId: result.tenantId,
      },
      message: 'Invitation accepted. You can now log in.',
    };
  }
}
