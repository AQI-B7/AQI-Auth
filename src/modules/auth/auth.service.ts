import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';
import { EmailService } from '../email/email.service';
import { LockoutService } from './lockout.service';
import { LockedException } from '../../common/exceptions/locked.exception';
import { MetricsService } from '../metrics/metrics.service';
import { TokenCipher } from '../../common/utils/token-cipher.util';
import { DomainsService } from '../domains/domains.service';
import { RiskService, RiskAssessment } from '../risk/risk.service';
import { OAuthProfile } from './strategies/oauth-profile.interface';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  MagicLinkRequestDto,
} from './dto/auth.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly tokenCipher: TokenCipher;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly redis: RedisService,
    private readonly emailService: EmailService,
    private readonly events: EventEmitter2,
    private readonly lockout: LockoutService,
    private readonly metrics: MetricsService,
    private readonly domains: DomainsService,
    private readonly risk: RiskService,
  ) {
    const encryptionSecret =
      this.config.get<string>('oauth.tokenEncryptionKey') ||
      this.config.get<string>('jwt.accessSecret') ||
      'insecure-dev-only-fallback-key';
    this.tokenCipher = new TokenCipher(encryptionSecret);
  }

  /** Only leak raw tokens in API responses outside production — mirrors
   *  the existing dev-testing convention in this file, but gated so it
   *  can never happen accidentally in prod. */
  private get isProd(): boolean {
    return this.config.get<string>('nodeEnv') === 'production';
  }

  // ─────────────────────────────────────────────
  // Register
  // ─────────────────────────────────────────────
  async register(dto: RegisterDto, ip?: string, userAgent?: string) {
    const riskAssessment = await this.risk.assessSignup(dto.email, ip, userAgent);
    if (riskAssessment?.action === 'block' && this.risk.mode === 'enforce') {
      throw new UnauthorizedException('Unable to complete registration from this request');
    }

    if (dto.joinExistingByDomain) {
      const match = await this.domains.lookupAutoJoin(dto.email);
      if (match) {
        return this.registerViaDomainAutoJoin(dto, match, ip, userAgent, riskAssessment);
      }
      // No verified auto-join domain for this email — fall through to
      // the normal new-tenant signup below rather than erroring, since
      // the caller asked to auto-join *if possible*, not *or fail*.
    }

    const slug =
      dto.tenantSlug ||
      dto.tenantName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 50);

    const existingTenant = await this.prisma.tenant.findUnique({ where: { slug } });
    if (existingTenant) {
      throw new ConflictException('Tenant slug already exists');
    }

    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    const result = await this.prisma.$transaction(async (tx: any) => {
      const tenant = await tx.tenant.create({
        data: {
          name: dto.tenantName,
          slug,
          status: 'ACTIVE',
          plan: 'free',
        },
      });

      // Default admin role for the tenant
      const adminRole = await tx.role.create({
        data: {
          tenantId: tenant.id,
          name: 'admin',
          description: 'Full administrative access',
          permissions: ['*'],
          isSystem: true,
        },
      });

      // Default member role
      await tx.role.create({
        data: {
          tenantId: tenant.id,
          name: 'member',
          description: 'Standard member access',
          permissions: ['profile:read', 'profile:write'],
          isSystem: true,
        },
      });

      const user = await tx.user.create({
        data: {
          tenantId: tenant.id,
          email: dto.email.toLowerCase(),
          passwordHash,
          firstName: dto.firstName,
          lastName: dto.lastName,
          emailVerified: false,
          status: 'ACTIVE',
        },
      });

      await tx.userRole.create({
        data: { userId: user.id, roleId: adminRole.id },
      });

      // Email verification token
      const verifyToken = randomBytes(32).toString('hex');
      const verifyHash = this.hashToken(verifyToken);
      await tx.emailVerificationToken.create({
        data: {
          userId: user.id,
          tokenHash: verifyHash,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      });

      await tx.authEvent.create({
        data: {
          userId: user.id,
          tenantId: tenant.id,
          type: 'register.success',
          ipAddress: ip,
          userAgent,
          metadata: riskAssessment ? { risk: riskAssessment } : undefined,
        },
      });

      return { tenant, user, verifyToken, permissions: ['*'] };
    });

    await this.risk.recordSignup(ip);

    const tokens = await this.issueTokens(
      result.user.id,
      result.tenant.id,
      result.user.email,
      result.permissions,
      ip,
      userAgent,
    );

    this.events.emit('user.registered', {
      userId: result.user.id,
      tenantId: result.tenant.id,
      email: result.user.email,
    });

    return {
      user: {
        id: result.user.id,
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
        emailVerified: result.user.emailVerified,
        tenantId: result.tenant.id,
      },
      tenant: {
        id: result.tenant.id,
        name: result.tenant.name,
        slug: result.tenant.slug,
      },
      ...tokens,
      // Only surfaced outside production; in prod this must be emailed.
      ...(this.isProd ? {} : { emailVerificationToken: result.verifyToken }),
      ...(riskAssessment?.action === 'challenge' && this.risk.mode === 'enforce'
        ? { requiresAdditionalVerification: true }
        : {}),
    };
  }

  /**
   * The domain-auto-join branch of register(): joins an existing tenant
   * (found via a verified TenantDomain) instead of creating a new one.
   * No password-less shortcut — the user still sets a password exactly
   * as normal signup would, they just land in someone else's tenant
   * with the domain's configured default role instead of getting their
   * own admin-owned tenant.
   */
  private async registerViaDomainAutoJoin(
    dto: RegisterDto,
    match: { tenantId: string; tenantName: string; defaultRoleId: string | null },
    ip?: string,
    userAgent?: string,
    riskAssessment?: RiskAssessment | null,
  ) {
    const existingUser = await this.prisma.user.findFirst({
      where: { tenantId: match.tenantId, email: dto.email.toLowerCase() },
    });
    if (existingUser) {
      throw new ConflictException('An account with this email already exists in this organization');
    }

    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    let roleId = match.defaultRoleId;
    if (!roleId) {
      const memberRole = await this.prisma.role.findFirst({
        where: { tenantId: match.tenantId, name: 'member' },
      });
      roleId = memberRole?.id ?? null;
    }

    const result = await this.prisma.$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: {
          tenantId: match.tenantId,
          email: dto.email.toLowerCase(),
          passwordHash,
          firstName: dto.firstName,
          lastName: dto.lastName,
          emailVerified: false,
          status: 'ACTIVE',
        },
      });

      if (roleId) {
        await tx.userRole.create({ data: { userId: user.id, roleId } });
      }

      const verifyToken = randomBytes(32).toString('hex');
      await tx.emailVerificationToken.create({
        data: {
          userId: user.id,
          tokenHash: this.hashToken(verifyToken),
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      });

      await tx.authEvent.create({
        data: {
          userId: user.id,
          tenantId: match.tenantId,
          type: 'register.success',
          ipAddress: ip,
          userAgent,
          metadata: { method: 'domain_auto_join', ...(riskAssessment ? { risk: riskAssessment } : {}) },
        },
      });

      return { user, verifyToken };
    });

    await this.risk.recordSignup(ip);

    const permissions = roleId
      ? this.collectPermissions([{ role: { permissions: (await this.prisma.role.findUnique({ where: { id: roleId } }))?.permissions ?? [] } }])
      : [];

    const tokens = await this.issueTokens(result.user.id, match.tenantId, result.user.email, permissions, ip, userAgent);

    this.events.emit('user.registered', {
      userId: result.user.id,
      tenantId: match.tenantId,
      email: result.user.email,
      method: 'domain_auto_join',
    });

    return {
      user: {
        id: result.user.id,
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
        emailVerified: false,
        tenantId: match.tenantId,
      },
      tenant: { id: match.tenantId, name: match.tenantName, slug: undefined },
      joinedExistingOrganization: true,
      ...tokens,
      ...(this.isProd ? {} : { emailVerificationToken: result.verifyToken }),
      ...(riskAssessment?.action === 'challenge' && this.risk.mode === 'enforce'
        ? { requiresAdditionalVerification: true }
        : {}),
    };
  }

  // ─────────────────────────────────────────────
  // Login
  // ─────────────────────────────────────────────
  async login(dto: LoginDto, ip?: string, userAgent?: string) {
    const lockoutKey = dto.email.toLowerCase();
    const status = await this.lockout.check('login', lockoutKey);
    if (status.locked) {
      this.metrics.loginAttemptsTotal.inc({ result: 'locked' });
      throw new LockedException(
        `Too many failed login attempts. Try again in ${status.retryAfterSeconds}s.`,
        status.retryAfterSeconds!,
      );
    }

    let user = await this.prisma.user.findFirst({
      where: {
        email: dto.email.toLowerCase(),
        ...(dto.tenantSlug
          ? { tenant: { slug: dto.tenantSlug } }
          : {}),
      },
      include: {
        tenant: true,
        roles: { include: { role: true } },
        twoFactor: true,
      },
    });

    // Timing-safe: always hash even if user not found
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy';
    const hashToCheck = user?.passwordHash || dummyHash;
    const passwordValid = await argon2.verify(hashToCheck, dto.password).catch(() => false);

    if (!user || !passwordValid || user.status !== 'ACTIVE') {
      const failStatus = await this.lockout.recordFailure('login', lockoutKey);
      await this.prisma.authEvent.create({
        data: {
          userId: user?.id,
          tenantId: user?.tenantId,
          type: 'login.failed',
          ipAddress: ip,
          userAgent,
          metadata: { email: dto.email },
        },
      });
      if (failStatus.locked) {
        this.metrics.accountLockoutsTotal.inc({ scope: 'login' });
        this.metrics.loginAttemptsTotal.inc({ result: 'locked' });
        throw new LockedException(
          `Too many failed login attempts. Try again in ${failStatus.retryAfterSeconds}s.`,
          failStatus.retryAfterSeconds!,
        );
      }
      this.metrics.loginAttemptsTotal.inc({ result: 'invalid_credentials' });
      throw new UnauthorizedException('Invalid email or password');
    }

    if (user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Tenant is suspended or cancelled');
    }

    // 2FA check
    if (user.twoFactor?.verified) {
      if (!dto.totpCode) {
        return { requires2FA: true, message: 'TOTP code required' };
      }
      const valid = authenticator.verify({
        token: dto.totpCode,
        secret: user.twoFactor.secret,
      });
      if (!valid) {
        // Try backup codes
        const backupValid = await this.verifyBackupCode(user.id, dto.totpCode);
        if (!backupValid) {
          const failStatus = await this.lockout.recordFailure('login', lockoutKey);
          if (failStatus.locked) {
            this.metrics.accountLockoutsTotal.inc({ scope: 'login' });
            this.metrics.loginAttemptsTotal.inc({ result: 'locked' });
            throw new LockedException(
              `Too many failed login attempts. Try again in ${failStatus.retryAfterSeconds}s.`,
              failStatus.retryAfterSeconds!,
            );
          }
          this.metrics.loginAttemptsTotal.inc({ result: 'invalid_2fa' });
          throw new UnauthorizedException('Invalid 2FA code');
        }
      }
    }

    await this.lockout.recordSuccess('login', lockoutKey);

    const permissions = this.collectPermissions(user.roles);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: 'login.success',
        ipAddress: ip,
        userAgent,
      },
    });

    const tokens = await this.issueTokens(
      user.id,
      user.tenantId,
      user.email,
      permissions,
      ip,
      userAgent,
    );

    this.events.emit('user.login', {
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      method: 'password',
    });
    this.metrics.loginAttemptsTotal.inc({ result: 'success' });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: user.emailVerified,
        tenantId: user.tenantId,
        permissions,
      },
      tenant: {
        id: user.tenant.id,
        name: user.tenant.name,
        slug: user.tenant.slug,
      },
      ...tokens,
    };
  }

  // ─────────────────────────────────────────────
  // Refresh
  // ─────────────────────────────────────────────
  async refresh(dto: RefreshTokenDto, ip?: string, userAgent?: string) {
    const tokenHash = this.hashToken(dto.refreshToken);

    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: {
            tenant: true,
            roles: { include: { role: true } },
          },
        },
        session: true,
      },
    });

    if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
      // Reuse detection: if token was already replaced, revoke the whole family
      if (stored?.replacedBy) {
        await this.prisma.refreshToken.updateMany({
          where: { sessionId: stored.sessionId },
          data: { revokedAt: new Date() },
        });
        await this.prisma.session.update({
          where: { id: stored.sessionId },
          data: { revokedAt: new Date() },
        });
      }
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    if (stored.user.status !== 'ACTIVE' || stored.user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account or tenant is not active');
    }

    // Rotate: revoke old, issue new
    const newRawToken = randomBytes(48).toString('hex');
    const newHash = this.hashToken(newRawToken);

    await this.prisma.$transaction([
      this.prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revokedAt: new Date(), replacedBy: newHash },
      }),
      this.prisma.refreshToken.create({
        data: {
          tokenHash: newHash,
          userId: stored.userId,
          sessionId: stored.sessionId,
          expiresAt: new Date(Date.now() + this.refreshTtlMs()),
        },
      }),
    ]);

    const permissions = this.collectPermissions(stored.user.roles);
    const { token: accessToken } = await this.signAccessToken({
      userId: stored.user.id,
      tenantId: stored.user.tenantId,
      email: stored.user.email,
      permissions,
      sessionId: stored.sessionId,
    });

    return {
      accessToken,
      refreshToken: newRawToken,
      expiresIn: this.accessTtlSeconds(),
      tokenType: 'Bearer',
    };
  }

  // ─────────────────────────────────────────────
  // Logout
  // ─────────────────────────────────────────────
  async logout(userId: string, jti?: string, sessionId?: string) {
    if (jti) {
      await this.redis.blacklistToken(jti, this.accessTtlSeconds());
    }

    if (sessionId) {
      await this.prisma.$transaction([
        this.prisma.session.update({
          where: { id: sessionId },
          data: { revokedAt: new Date() },
        }),
        this.prisma.refreshToken.updateMany({
          where: { sessionId },
          data: { revokedAt: new Date() },
        }),
      ]);
    }

    await this.prisma.authEvent.create({
      data: {
        userId,
        type: 'logout',
      },
    });

    return { success: true };
  }

  // ─────────────────────────────────────────────
  // Password Reset
  // ─────────────────────────────────────────────
  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email.toLowerCase(),
        ...(dto.tenantSlug ? { tenant: { slug: dto.tenantSlug } } : {}),
      },
    });

    // Always return success to avoid email enumeration
    if (!user) {
      return { success: true, message: 'If the email exists, a reset link has been sent' };
    }

    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawToken);

    await this.prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: 'password.reset_requested',
      },
    });

    const resetLink = `${this.config.get<string>('frontendUrl')}/reset-password?token=${rawToken}`;
    await this.emailService.sendPasswordReset(user.email, resetLink);

    return {
      success: true,
      message: 'If the email exists, a reset link has been sent',
      // Only surfaced outside production, to keep local testing painless
      // without an SMTP server configured.
      ...(this.isProd ? {} : { resetToken: rawToken }),
    };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const tokenHash = this.hashToken(dto.token);

    const record = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const passwordHash = await argon2.hash(dto.newPassword, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { passwordHash },
      }),
      this.prisma.passwordResetToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      // Revoke all sessions
      this.prisma.session.updateMany({
        where: { userId: record.userId },
        data: { revokedAt: new Date() },
      }),
      this.prisma.refreshToken.updateMany({
        where: { userId: record.userId },
        data: { revokedAt: new Date() },
      }),
    ]);

    await this.prisma.authEvent.create({
      data: {
        userId: record.userId,
        tenantId: record.user.tenantId,
        type: 'password.reset_completed',
      },
    });

    return { success: true, message: 'Password has been reset' };
  }

  // ─────────────────────────────────────────────
  // Email Verification
  // ─────────────────────────────────────────────
  async verifyEmail(token: string) {
    const tokenHash = this.hashToken(token);

    const record = await this.prisma.emailVerificationToken.findUnique({
      where: { tokenHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { emailVerified: true },
      }),
      this.prisma.emailVerificationToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
    ]);

    return { success: true, message: 'Email verified' };
  }

  // ─────────────────────────────────────────────
  // Magic Link (passwordless login)
  // ─────────────────────────────────────────────
  async requestMagicLink(dto: MagicLinkRequestDto) {
    const rateKey = `magic-link:${dto.email.toLowerCase()}`;
    const attempts = await this.redis.incrementRateLimit(rateKey, 300); // 5 min window
    if (attempts > 5) {
      throw new UnauthorizedException('Too many requests. Try again later.');
    }

    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email.toLowerCase(),
        ...(dto.tenantSlug ? { tenant: { slug: dto.tenantSlug } } : {}),
      },
      include: { tenant: true },
    });

    const generic = {
      success: true,
      message: 'If an account exists for that email, a sign-in link has been sent',
    };

    // Anti-enumeration: always behave identically whether or not the
    // account exists, and never reveal an inactive tenant/user either.
    if (!user || user.status !== 'ACTIVE' || user.tenant.status !== 'ACTIVE') {
      return generic;
    }

    const rawToken = randomBytes(32).toString('hex');
    const ttlMinutes = this.config.get<number>('magicLink.ttlMinutes') || 15;

    await this.prisma.magicLinkToken.create({
      data: {
        tokenHash: this.hashToken(rawToken),
        email: user.email,
        tenantId: user.tenantId,
        userId: user.id,
        expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
      },
    });

    const link = `${this.config.get<string>('frontendUrl')}/auth/magic-link/callback?token=${rawToken}`;
    const { delivered } = await this.emailService.sendMagicLink(user.email, link, ttlMinutes);

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: 'magic_link.requested',
      },
    });
    this.metrics.magicLinkTotal.inc({ action: 'requested', result: 'sent' });

    return {
      ...generic,
      // Only surfaced when there's nowhere else the link could have gone
      // (no SMTP configured) and never in production.
      ...(!delivered && !this.isProd ? { magicLinkToken: rawToken } : {}),
    };
  }

  async verifyMagicLink(token: string, ip?: string, userAgent?: string) {
    const lockoutId = ip || 'unknown';
    const status = await this.lockout.check('magic_link_verify', lockoutId);
    if (status.locked) {
      throw new LockedException(
        `Too many invalid sign-in link attempts. Try again in ${status.retryAfterSeconds}s.`,
        status.retryAfterSeconds!,
      );
    }

    const tokenHash = this.hashToken(token);

    const record = await this.prisma.magicLinkToken.findUnique({
      where: { tokenHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date() || !record.userId) {
      const failStatus = await this.lockout.recordFailure('magic_link_verify', lockoutId);
      this.metrics.magicLinkTotal.inc({ action: 'verified', result: 'invalid' });
      if (failStatus.locked) {
        this.metrics.accountLockoutsTotal.inc({ scope: 'magic_link' });
        throw new LockedException(
          `Too many invalid sign-in link attempts. Try again in ${failStatus.retryAfterSeconds}s.`,
          failStatus.retryAfterSeconds!,
        );
      }
      throw new BadRequestException('Invalid or expired sign-in link');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: record.userId },
      include: { tenant: true, roles: { include: { role: true } } },
    });

    if (!user || user.status !== 'ACTIVE' || user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account is not active');
    }

    await this.prisma.$transaction([
      this.prisma.magicLinkToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      this.prisma.user.update({
        where: { id: user.id },
        data: { emailVerified: true, lastLoginAt: new Date() },
      }),
    ]);

    const permissions = this.collectPermissions(user.roles);
    const tokens = await this.issueTokens(
      user.id,
      user.tenantId,
      user.email,
      permissions,
      ip,
      userAgent,
    );

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: 'login.success',
        ipAddress: ip,
        userAgent,
        metadata: { method: 'magic_link' },
      },
    });

    this.events.emit('user.login', {
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      method: 'magic_link',
    });
    await this.lockout.recordSuccess('magic_link_verify', lockoutId);
    this.metrics.magicLinkTotal.inc({ action: 'verified', result: 'success' });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: true,
        tenantId: user.tenantId,
        permissions,
      },
      tenant: { id: user.tenant.id, name: user.tenant.name, slug: user.tenant.slug },
      ...tokens,
    };
  }

  // ─────────────────────────────────────────────
  // OAuth (Google / GitHub)
  // ─────────────────────────────────────────────
  /**
   * Links or creates an account from a verified OAuth provider profile.
   *
   * Resolution order:
   *  1. Existing OAuthAccount for (provider, providerAccountId) → sign in.
   *  2. `tenantSlug` given + a user with this email exists in that tenant
   *     → link the new provider to that existing account.
   *  3. Otherwise → provision a brand-new tenant + admin user (this is
   *     how first-time "Sign in with Google" signup works), since OAuth
   *     provider emails are already verified.
   */
  async handleOAuthLogin(profile: OAuthProfile, tenantSlug?: string, ip?: string, userAgent?: string) {
    const encAccessToken = profile.accessToken ? this.tokenCipher.encrypt(profile.accessToken) : null;
    const encRefreshToken = profile.refreshToken ? this.tokenCipher.encrypt(profile.refreshToken) : null;

    const existingLink = await this.prisma.oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: {
          provider: profile.provider,
          providerAccountId: profile.providerAccountId,
        },
      },
      include: {
        user: { include: { tenant: true, roles: { include: { role: true } } } },
      },
    });

    let user: {
      id: string;
      tenantId: string;
      email: string;
      firstName: string | null;
      lastName: string | null;
      status: string;
      tenant: { id: string; name: string; slug: string; status: string };
      roles: { role: { permissions: string[] } }[];
    };
    let isNewUser = false;

    if (existingLink) {
      await this.prisma.oAuthAccount.update({
        where: { id: existingLink.id },
        data: {
          accessToken: encAccessToken,
          refreshToken: encRefreshToken ?? undefined,
          scope: profile.provider,
        },
      });
      user = existingLink.user;
    } else {
      const linkTarget = await this.prisma.user.findFirst({
        where: {
          email: profile.email,
          ...(tenantSlug ? { tenant: { slug: tenantSlug } } : {}),
        },
        include: { tenant: true, roles: { include: { role: true } } },
      });

      if (linkTarget) {
        await this.prisma.oAuthAccount.create({
          data: {
            userId: linkTarget.id,
            provider: profile.provider,
            providerAccountId: profile.providerAccountId,
            accessToken: encAccessToken,
            refreshToken: encRefreshToken,
          },
        });
        if (!linkTarget.emailVerified) {
          await this.prisma.user.update({
            where: { id: linkTarget.id },
            data: { emailVerified: true },
          });
        }
        user = linkTarget;
      } else {
        // First-time sign-up via OAuth: provision a personal tenant.
        isNewUser = true;
        const slugBase = profile.email
          .split('@')[0]
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .slice(0, 40);
        const slug = `${slugBase}-${randomBytes(3).toString('hex')}`;

        const created = await this.prisma.$transaction(async (tx: any) => {
          const tenant = await tx.tenant.create({
            data: { name: profile.email.split('@')[0], slug, status: 'ACTIVE', plan: 'free' },
          });
          const adminRole = await tx.role.create({
            data: {
              tenantId: tenant.id,
              name: 'admin',
              description: 'Full administrative access',
              permissions: ['*'],
              isSystem: true,
            },
          });
          const newUser = await tx.user.create({
            data: {
              tenantId: tenant.id,
              email: profile.email,
              firstName: profile.firstName,
              lastName: profile.lastName,
              imageUrl: profile.imageUrl,
              emailVerified: profile.emailVerified,
              status: 'ACTIVE',
            },
          });
          await tx.userRole.create({ data: { userId: newUser.id, roleId: adminRole.id } });
          await tx.oAuthAccount.create({
            data: {
              userId: newUser.id,
              provider: profile.provider,
              providerAccountId: profile.providerAccountId,
              accessToken: encAccessToken,
              refreshToken: encRefreshToken,
            },
          });
          return { tenant, user: newUser };
        });

        user = { ...created.user, tenant: created.tenant, roles: [] };
      }
    }

    if (user.status !== 'ACTIVE' || user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account or tenant is not active');
    }

    const permissions = isNewUser ? ['*'] : this.collectPermissions(user.roles);

    await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });

    const tokens = await this.issueTokens(user.id, user.tenantId, user.email, permissions, ip, userAgent);

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: isNewUser ? 'register.success' : 'login.success',
        ipAddress: ip,
        userAgent,
        metadata: { method: `oauth:${profile.provider}` },
      },
    });

    this.events.emit(isNewUser ? 'user.registered' : 'user.login', {
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      method: `oauth:${profile.provider}`,
    });
    this.metrics.oauthLoginTotal.inc({
      provider: profile.provider,
      result: isNewUser ? 'new_user' : 'success',
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: true,
        tenantId: user.tenantId,
        permissions,
      },
      tenant: { id: user.tenant.id, name: user.tenant.name, slug: user.tenant.slug },
      isNewUser,
      ...tokens,
    };
  }

  // ─────────────────────────────────────────────
  // Two-Factor Authentication
  // ─────────────────────────────────────────────
  async setup2FA(userId: string) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.email, 'StandaloneAuth', secret);
    const qrCode = await QRCode.toDataURL(otpauth);

    await this.prisma.twoFactorSecret.upsert({
      where: { userId },
      create: { userId, secret, verified: false },
      update: { secret, verified: false },
    });

    return { secret, qrCode, otpauth };
  }

  async enable2FA(userId: string, totpCode: string) {
    const record = await this.prisma.twoFactorSecret.findUnique({ where: { userId } });
    if (!record) {
      throw new BadRequestException('2FA not set up. Call setup first.');
    }

    const valid = authenticator.verify({ token: totpCode, secret: record.secret });
    if (!valid) {
      throw new BadRequestException('Invalid TOTP code');
    }

    // Generate backup codes
    const backupCodes: string[] = [];
    const hashedCodes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const code = randomBytes(4).toString('hex');
      backupCodes.push(code);
      hashedCodes.push(this.hashToken(code));
    }

    await this.prisma.$transaction([
      this.prisma.twoFactorSecret.update({
        where: { userId },
        data: { verified: true },
      }),
      this.prisma.twoFactorBackupCode.deleteMany({ where: { userId } }),
      this.prisma.twoFactorBackupCode.createMany({
        data: hashedCodes.map((codeHash) => ({ userId, codeHash })),
      }),
    ]);

    return { success: true, backupCodes };
  }

  async disable2FA(userId: string, totpCode: string) {
    const record = await this.prisma.twoFactorSecret.findUnique({ where: { userId } });
    if (!record?.verified) {
      throw new BadRequestException('2FA is not enabled');
    }

    const valid = authenticator.verify({ token: totpCode, secret: record.secret });
    if (!valid) {
      throw new BadRequestException('Invalid TOTP code');
    }

    await this.prisma.$transaction([
      this.prisma.twoFactorSecret.delete({ where: { userId } }),
      this.prisma.twoFactorBackupCode.deleteMany({ where: { userId } }),
    ]);

    return { success: true };
  }

  // ─────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────
  // Not `private`: WebAuthnService (passkeys) and future auth-strategy
  // services need to issue the same token pair after their own
  // credential verification succeeds, without duplicating this logic.
  async issueTokens(
    userId: string,
    tenantId: string,
    email: string,
    permissions: string[],
    ip?: string,
    userAgent?: string,
  ) {
    const session = await this.prisma.session.create({
      data: {
        userId,
        tenantId,
        ipAddress: ip,
        userAgent,
        expiresAt: new Date(Date.now() + this.refreshTtlMs()),
      },
    });

    const { token: accessToken } = await this.signAccessToken({
      userId,
      tenantId,
      email,
      permissions,
      sessionId: session.id,
    });

    const rawRefresh = randomBytes(48).toString('hex');
    await this.prisma.refreshToken.create({
      data: {
        tokenHash: this.hashToken(rawRefresh),
        userId,
        sessionId: session.id,
        expiresAt: new Date(Date.now() + this.refreshTtlMs()),
      },
    });

    return {
      accessToken,
      refreshToken: rawRefresh,
      expiresIn: this.accessTtlSeconds(),
      tokenType: 'Bearer',
    };
  }

  async signAccessToken(payload: {
    userId: string;
    tenantId: string;
    email: string;
    permissions: string[];
    sessionId: string;
    impersonatedBy?: string;
    expiresInOverride?: string;
    jtiOverride?: string;
  }): Promise<{ token: string; jti: string }> {
    const jti = payload.jtiOverride || uuidv4();
    const token = await this.jwt.signAsync(
      {
        sub: payload.userId,
        tenantId: payload.tenantId,
        email: payload.email,
        permissions: payload.permissions,
        sessionId: payload.sessionId,
        jti,
        ...(payload.impersonatedBy ? { impersonatedBy: payload.impersonatedBy } : {}),
      },
      {
        secret: this.config.get<string>('jwt.accessSecret'),
        expiresIn: (payload.expiresInOverride || this.config.get<string>('jwt.accessExpiresIn') || '15m') as any,
      },
    );
    return { token, jti };
  }

  collectPermissions(
    userRoles: { role: { permissions: string[] } }[],
  ): string[] {
    const set = new Set<string>();
    for (const ur of userRoles) {
      for (const p of ur.role.permissions) {
        set.add(p);
      }
    }
    return Array.from(set);
  }

  private async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const hash = this.hashToken(code);
    const record = await this.prisma.twoFactorBackupCode.findFirst({
      where: { userId, codeHash: hash, usedAt: null },
    });
    if (!record) return false;

    await this.prisma.twoFactorBackupCode.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });
    return true;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private accessTtlSeconds(): number {
    const exp = this.config.get<string>('jwt.accessExpiresIn') || '15m';
    if (exp.endsWith('m')) return parseInt(exp, 10) * 60;
    if (exp.endsWith('h')) return parseInt(exp, 10) * 3600;
    return 900;
  }

  private refreshTtlMs(): number {
    const exp = this.config.get<string>('jwt.refreshExpiresIn') || '30d';
    if (exp.endsWith('d')) return parseInt(exp, 10) * 24 * 60 * 60 * 1000;
    if (exp.endsWith('h')) return parseInt(exp, 10) * 60 * 60 * 1000;
    return 30 * 24 * 60 * 60 * 1000;
  }
}
