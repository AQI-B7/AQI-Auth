import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SAML, Profile, ValidateInResponseTo } from '@node-saml/node-saml';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';
import { RedisSamlCacheProvider } from './redis-saml-cache-provider';
import { AuthService } from '../auth/auth.service';
import { CreateSsoConnectionDto, UpdateSsoConnectionDto } from './dto/sso.dto';

/**
 * SAML 2.0 SP-initiated SSO, one connection per tenant per IdP. Actual
 * assertion parsing/signature validation is delegated entirely to
 * @node-saml/node-saml — this service's job is: build the right SAML
 * client for a given tenant's connection, generate the redirect-to-IdP
 * URL, and turn a validated assertion into a user session (existing user
 * login or JIT-provisioned new user), the same way handleOAuthLogin does
 * for OAuth.
 */
@Injectable()
export class SsoService {
  private readonly logger = new Logger(SsoService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly authService: AuthService,
    private readonly redis: RedisService,
  ) {}

  // ── Connection CRUD (tenant-admin only) ─────────────────────

  async create(tenantId: string, dto: CreateSsoConnectionDto) {
    if (dto.defaultRoleId) {
      await this.assertRoleBelongsToTenant(tenantId, dto.defaultRoleId);
    }
    return this.prisma.ssoConnection.create({
      data: {
        tenantId,
        name: dto.name,
        entryPoint: dto.entryPoint,
        issuer: dto.issuer,
        cert: normalizeCert(dto.cert),
        wantAssertionsSigned: dto.wantAssertionsSigned ?? true,
        jitProvisioning: dto.jitProvisioning ?? true,
        defaultRoleId: dto.defaultRoleId,
      },
    });
  }

  async list(tenantId: string) {
    return this.prisma.ssoConnection.findMany({ where: { tenantId }, orderBy: { createdAt: 'desc' } });
  }

  async findOne(tenantId: string, id: string) {
    const conn = await this.prisma.ssoConnection.findFirst({ where: { id, tenantId } });
    if (!conn) throw new NotFoundException('SSO connection not found');
    return conn;
  }

  async update(tenantId: string, id: string, dto: UpdateSsoConnectionDto) {
    await this.findOne(tenantId, id);
    if (dto.defaultRoleId) {
      await this.assertRoleBelongsToTenant(tenantId, dto.defaultRoleId);
    }
    return this.prisma.ssoConnection.update({
      where: { id },
      data: { ...dto, cert: dto.cert ? normalizeCert(dto.cert) : undefined },
    });
  }

  async remove(tenantId: string, id: string) {
    await this.findOne(tenantId, id);
    await this.prisma.ssoConnection.delete({ where: { id } });
    return { success: true };
  }

  private async assertRoleBelongsToTenant(tenantId: string, roleId: string) {
    const role = await this.prisma.role.findFirst({ where: { id: roleId, tenantId } });
    if (!role) throw new BadRequestException('defaultRoleId does not belong to this tenant');
  }

  // ── Service Provider metadata (hand this to the IdP admin) ──

  async serviceProviderMetadata(tenantId: string, connectionId: string): Promise<string> {
    const connection = await this.findOne(tenantId, connectionId);
    const saml = this.buildSamlClient(connection, await this.tenantSlug(tenantId));
    return saml.generateServiceProviderMetadata(null, null);
  }

  // ── SP-initiated login ──

  async getLoginUrl(tenantSlug: string, connectionId: string, relayState: string): Promise<string> {
    const connection = await this.findActiveByTenantSlugAndId(tenantSlug, connectionId);
    const saml = this.buildSamlClient(connection, tenantSlug);
    return saml.getAuthorizeUrlAsync(relayState, undefined, {});
  }

  // ── ACS callback ──

  async handleCallback(
    tenantSlug: string,
    connectionId: string,
    samlResponse: string,
    ip?: string,
    userAgent?: string,
  ) {
    const connection = await this.findActiveByTenantSlugAndId(tenantSlug, connectionId);
    const saml = this.buildSamlClient(connection, tenantSlug);

    let profile: Profile | null;
    try {
      const result = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });
      profile = result.profile;
    } catch (err) {
      await this.logSsoFailure(connection.tenantId, (err as Error).message, ip, userAgent);
      throw new UnauthorizedException(`SAML assertion validation failed: ${(err as Error).message}`);
    }

    if (!profile) {
      throw new UnauthorizedException('SAML response did not contain a usable assertion');
    }

    // Defense in depth beyond node-saml's own signature/audience checks:
    // the asserting party must be exactly the IdP this connection trusts.
    if (profile.issuer !== connection.issuer) {
      await this.logSsoFailure(
        connection.tenantId,
        `Issuer mismatch: expected ${connection.issuer}, got ${profile.issuer}`,
        ip,
        userAgent,
      );
      throw new UnauthorizedException('SAML assertion issuer does not match the configured identity provider');
    }

    const email = extractEmail(profile);
    if (!email) {
      throw new BadRequestException('SAML assertion did not include an email attribute');
    }

    const { firstName, lastName } = extractName(profile);

    let user = await this.prisma.user.findFirst({
      where: { email: email.toLowerCase(), tenantId: connection.tenantId },
      include: { tenant: true, roles: { include: { role: true } } },
    });

    let isNewUser = false;

    if (!user) {
      if (!connection.jitProvisioning) {
        throw new UnauthorizedException(
          'No account found for this email, and just-in-time provisioning is disabled for this SSO connection',
        );
      }
      user = await this.jitProvisionUser(connection, email, firstName, lastName);
      isNewUser = true;
    } else if (!user.emailVerified) {
      user = await this.prisma.user.update({
        where: { id: user.id },
        data: { emailVerified: true },
        include: { tenant: true, roles: { include: { role: true } } },
      });
    }

    if (user.status !== 'ACTIVE' || user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account or tenant is not active');
    }

    const permissions = this.authService.collectPermissions(user.roles);
    await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    const tokens = await this.authService.issueTokens(user.id, user.tenantId, user.email, permissions, ip, userAgent);

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: isNewUser ? 'register.success' : 'login.success',
        ipAddress: ip,
        userAgent,
        metadata: { method: 'saml', connectionId: connection.id },
      },
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

  // ── Internals ──

  private async jitProvisionUser(
    connection: { id: string; tenantId: string; defaultRoleId: string | null },
    email: string,
    firstName?: string,
    lastName?: string,
  ) {
    let roleId = connection.defaultRoleId;
    if (!roleId) {
      const memberRole = await this.prisma.role.findFirst({
        where: { tenantId: connection.tenantId, name: 'member' },
      });
      roleId = memberRole?.id ?? null;
    }

    return this.prisma.$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: {
          tenantId: connection.tenantId,
          email: email.toLowerCase(),
          firstName,
          lastName,
          emailVerified: true, // the IdP already authenticated this email
          status: 'ACTIVE',
        },
      });
      if (roleId) {
        await tx.userRole.create({ data: { userId: user.id, roleId } });
      }
      return tx.user.findUniqueOrThrow({
        where: { id: user.id },
        include: { tenant: true, roles: { include: { role: true } } },
      });
    });
  }

  private buildSamlClient(
    connection: { id: string; entryPoint: string; issuer: string; cert: string; wantAssertionsSigned: boolean },
    tenantSlug: string,
  ): SAML {
    const spEntityId = this.config.get<string>('sso.spEntityId')!;
    return new SAML({
      issuer: spEntityId,
      callbackUrl: this.acsUrl(tenantSlug, connection.id),
      entryPoint: connection.entryPoint,
      idpCert: connection.cert,
      wantAssertionsSigned: connection.wantAssertionsSigned,
      audience: spEntityId,
      // Redis-backed, not the library's default in-memory Map: an
      // AuthnRequest's InResponseTo ID must be recognized on whichever
      // instance handles the ACS callback, not just the one that issued
      // it — this service already depends on Redis, so every instance
      // shares this state instead of failing SSO intermittently behind
      // a load balancer.
      cacheProvider: new RedisSamlCacheProvider(this.redis),
      validateInResponseTo: ValidateInResponseTo.always,
    });
  }

  private acsUrl(tenantSlug: string, connectionId: string): string {
    return `${this.config.get<string>('sso.appUrl')}/v1/sso/callback/${tenantSlug}/${connectionId}`;
  }

  private async tenantSlug(tenantId: string): Promise<string> {
    const tenant = await this.prisma.tenant.findUniqueOrThrow({ where: { id: tenantId } });
    return tenant.slug;
  }

  private async findActiveByTenantSlugAndId(tenantSlug: string, connectionId: string) {
    const connection = await this.prisma.ssoConnection.findFirst({
      where: { id: connectionId, tenant: { slug: tenantSlug } },
    });
    if (!connection || !connection.active) {
      throw new NotFoundException('SSO connection not found or inactive');
    }
    return connection;
  }

  private async logSsoFailure(tenantId: string, message: string, ip?: string, userAgent?: string) {
    await this.prisma.authEvent
      .create({
        data: { tenantId, type: 'sso.failed', ipAddress: ip, userAgent, metadata: { error: message } },
      })
      .catch(() => undefined);
  }
}

/** Accepts a cert with or without PEM headers/whitespace, as admins
 *  frequently paste it either way from their IdP's metadata page. */
function normalizeCert(cert: string): string {
  return cert
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\r?\n|\r/g, '')
    .trim();
}

function extractEmail(profile: Profile): string | undefined {
  const candidates = [
    profile.email,
    profile.mail,
    profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
    profile['http://schemas.xmlsoap.org/claims/EmailAddress'],
    profile.nameIDFormat?.includes('emailAddress') ? profile.nameID : undefined,
  ];
  const found = candidates.find((c) => typeof c === 'string' && c.includes('@'));
  return found as string | undefined;
}

function extractName(profile: Profile): { firstName?: string; lastName?: string } {
  const firstName =
    (profile.firstName as string) ||
    (profile.givenName as string) ||
    (profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'] as string);
  const lastName =
    (profile.lastName as string) ||
    (profile.surname as string) ||
    (profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'] as string);
  return { firstName, lastName };
}
