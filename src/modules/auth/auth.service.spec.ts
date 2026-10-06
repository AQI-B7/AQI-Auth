import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuthService } from './auth.service';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';
import { EmailService } from '../email/email.service';
import { LockoutService } from './lockout.service';
import { MetricsService } from '../metrics/metrics.service';
import { DomainsService } from '../domains/domains.service';
import { RiskService } from '../risk/risk.service';
import { ConflictException, UnauthorizedException } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let prisma: jest.Mocked<PrismaService>;
  let redis: jest.Mocked<RedisService>;

  const mockPrisma: Record<string, any> = {
    tenant: { findUnique: jest.fn(), create: jest.fn() },
    user: { findFirst: jest.fn(), create: jest.fn(), update: jest.fn(), findUniqueOrThrow: jest.fn() },
    role: { create: jest.fn() },
    userRole: { create: jest.fn() },
    session: { create: jest.fn(), update: jest.fn(), updateMany: jest.fn() },
    refreshToken: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    emailVerificationToken: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
    passwordResetToken: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
    twoFactorSecret: { findUnique: jest.fn(), upsert: jest.fn(), update: jest.fn(), delete: jest.fn() },
    twoFactorBackupCode: { createMany: jest.fn(), deleteMany: jest.fn(), findFirst: jest.fn(), update: jest.fn() },
    authEvent: { create: jest.fn() },
    $transaction: jest.fn((fn: any) => (typeof fn === 'function' ? fn(mockPrisma) : Promise.all(fn))),
  };

  const mockRedis = {
    incrementRateLimit: jest.fn().mockResolvedValue(1),
    blacklistToken: jest.fn(),
    isBlacklisted: jest.fn().mockResolvedValue(false),
  };

  const mockJwt = {
    signAsync: jest.fn().mockResolvedValue('mock.access.token'),
  };

  const mockConfig = {
    get: jest.fn((key: string) => {
      const map: Record<string, any> = {
        'jwt.accessSecret': 'test-access-secret-min-32-characters-long',
        'jwt.refreshSecret': 'test-refresh-secret-min-32-characters-long',
        'jwt.accessExpiresIn': '15m',
        'jwt.refreshExpiresIn': '30d',
        nodeEnv: 'test',
        frontendUrl: 'http://localhost:3000',
        'magicLink.ttlMinutes': 15,
      };
      return map[key];
    }),
  };

  const mockEmailService = {
    enabled: false,
    send: jest.fn().mockResolvedValue({ delivered: false }),
    sendMagicLink: jest.fn().mockResolvedValue({ delivered: false }),
    sendPasswordReset: jest.fn().mockResolvedValue({ delivered: false }),
    sendInvitation: jest.fn().mockResolvedValue({ delivered: false }),
  };

  const mockEvents = {
    emit: jest.fn(),
  };

  const mockLockout = {
    check: jest.fn().mockResolvedValue({ locked: false, attemptsRemaining: 5 }),
    recordFailure: jest.fn().mockResolvedValue({ locked: false, attemptsRemaining: 4 }),
    recordSuccess: jest.fn().mockResolvedValue(undefined),
  };

  const mockMetrics = {
    loginAttemptsTotal: { inc: jest.fn() },
    magicLinkTotal: { inc: jest.fn() },
    oauthLoginTotal: { inc: jest.fn() },
    accountLockoutsTotal: { inc: jest.fn() },
  };

  const mockDomains = {
    lookupAutoJoin: jest.fn().mockResolvedValue(null),
  };

  const mockRisk = {
    mode: 'log',
    assessSignup: jest.fn().mockResolvedValue(null),
    recordSignup: jest.fn().mockResolvedValue(undefined),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: RedisService, useValue: mockRedis },
        { provide: JwtService, useValue: mockJwt },
        { provide: ConfigService, useValue: mockConfig },
        { provide: EmailService, useValue: mockEmailService },
        { provide: EventEmitter2, useValue: mockEvents },
        { provide: LockoutService, useValue: mockLockout },
        { provide: MetricsService, useValue: mockMetrics },
        { provide: DomainsService, useValue: mockDomains },
        { provide: RiskService, useValue: mockRisk },
      ],
    }).compile();

    service = module.get(AuthService);
    prisma = module.get(PrismaService);
    redis = module.get(RedisService);

    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new tenant and admin user', async () => {
      mockPrisma.tenant.findUnique.mockResolvedValue(null);
      mockPrisma.tenant.create.mockResolvedValue({
        id: 'tenant_1',
        name: 'Acme',
        slug: 'acme',
      });
      mockPrisma.role.create
        .mockResolvedValueOnce({ id: 'role_admin', permissions: ['*'] })
        .mockResolvedValueOnce({ id: 'role_member', permissions: [] });
      mockPrisma.user.create.mockResolvedValue({
        id: 'user_1',
        email: 'admin@acme.com',
        firstName: 'Admin',
        lastName: null,
        emailVerified: false,
        tenantId: 'tenant_1',
      });
      mockPrisma.session.create.mockResolvedValue({ id: 'sess_1' });

      const result = await service.register({
        email: 'admin@acme.com',
        password: 'SecurePass1',
        firstName: 'Admin',
        tenantName: 'Acme',
      });

      expect(result.user.email).toBe('admin@acme.com');
      expect(result.tenant.slug).toBe('acme');
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should reject duplicate tenant slug', async () => {
      mockPrisma.tenant.findUnique.mockResolvedValue({ id: 'existing' });

      await expect(
        service.register({
          email: 'admin@acme.com',
          password: 'SecurePass1',
          firstName: 'Admin',
          tenantName: 'Acme',
          tenantSlug: 'acme',
        }),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('login', () => {
    it('should reject invalid credentials', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);

      await expect(
        service.login({ email: 'nobody@test.com', password: 'wrong' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('should blacklist token and revoke session', async () => {
      const result = await service.logout('user_1', 'jti_123', 'sess_1');
      expect(result.success).toBe(true);
      expect(redis.blacklistToken).toHaveBeenCalledWith('jti_123', expect.any(Number));
    });
  });
});
