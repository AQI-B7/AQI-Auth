import { BadRequestException, ConflictException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { promises as dns } from 'dns';
import { randomBytes } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { AddTenantDomainDto, UpdateTenantDomainDto } from './dto/domains.dto';

const TXT_RECORD_PREFIX = 'authservice-domain-verification=';

/**
 * Domain ownership verification (DNS TXT record challenge, the same
 * mechanism Google Workspace/Slack/Notion use) plus the lookup that
 * powers JIT "org domain auto-join": once a tenant has proven it owns
 * acme.com, new signups with an @acme.com email can join that tenant
 * automatically instead of creating their own.
 */
@Injectable()
export class DomainsService {
  private readonly logger = new Logger(DomainsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async add(tenantId: string, dto: AddTenantDomainDto) {
    const domain = dto.domain.toLowerCase();

    const existing = await this.prisma.tenantDomain.findUnique({ where: { domain } });
    if (existing) {
      throw new ConflictException(
        existing.tenantId === tenantId
          ? 'This domain has already been added to your tenant'
          : 'This domain is already claimed by another tenant',
      );
    }

    if (dto.defaultRoleId) {
      const role = await this.prisma.role.findFirst({ where: { id: dto.defaultRoleId, tenantId } });
      if (!role) throw new BadRequestException('defaultRoleId does not belong to this tenant');
    }

    return this.prisma.tenantDomain.create({
      data: {
        tenantId,
        domain,
        verificationToken: randomBytes(16).toString('hex'),
        autoJoin: dto.autoJoin ?? true,
        defaultRoleId: dto.defaultRoleId,
      },
    });
  }

  async list(tenantId: string) {
    return this.prisma.tenantDomain.findMany({ where: { tenantId }, orderBy: { createdAt: 'desc' } });
  }

  async update(tenantId: string, id: string, dto: UpdateTenantDomainDto) {
    const domain = await this.findOwned(tenantId, id);
    if (dto.defaultRoleId) {
      const role = await this.prisma.role.findFirst({ where: { id: dto.defaultRoleId, tenantId } });
      if (!role) throw new BadRequestException('defaultRoleId does not belong to this tenant');
    }
    return this.prisma.tenantDomain.update({ where: { id: domain.id }, data: dto });
  }

  async remove(tenantId: string, id: string) {
    const domain = await this.findOwned(tenantId, id);
    await this.prisma.tenantDomain.delete({ where: { id: domain.id } });
    return { success: true };
  }

  /**
   * Performs a real DNS TXT lookup against the domain's DNS records and
   * checks for a record matching `authservice-domain-verification=<token>`.
   * No shortcuts: if the record isn't there, verification fails — same
   * as it would against a real DNS resolver in any environment with
   * outbound DNS access.
   */
  async verify(tenantId: string, id: string) {
    const domain = await this.findOwned(tenantId, id);
    if (domain.verified) {
      return domain;
    }

    let records: string[][];
    try {
      records = await dns.resolveTxt(domain.domain);
    } catch (err) {
      throw new BadRequestException(
        `Could not resolve DNS TXT records for ${domain.domain}: ${(err as Error).message}. ` +
          `Add a TXT record with value "${TXT_RECORD_PREFIX}${domain.verificationToken}" and try again — ` +
          `DNS propagation can take up to 24-48 hours.`,
      );
    }

    const expected = `${TXT_RECORD_PREFIX}${domain.verificationToken}`;
    const found = records.some((chunks) => chunks.join('').trim() === expected);

    if (!found) {
      throw new BadRequestException(
        `TXT record not found for ${domain.domain}. Expected a record with value "${expected}". ` +
          `DNS propagation can take up to 24-48 hours after adding it.`,
      );
    }

    this.logger.log(`Domain ${domain.domain} verified for tenant ${tenantId}`);
    return this.prisma.tenantDomain.update({
      where: { id: domain.id },
      data: { verified: true, verifiedAt: new Date() },
    });
  }

  /**
   * Used by the signup flow: given an email address, is there a
   * verified, auto-join-enabled tenant for its domain? Returns minimal,
   * non-sensitive info (tenant name only) suitable for showing a user
   * "you'll be joining <name>" before they confirm.
   */
  async lookupAutoJoin(email: string): Promise<{ tenantId: string; tenantName: string; defaultRoleId: string | null } | null> {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return null;

    const match = await this.prisma.tenantDomain.findFirst({
      where: { domain, verified: true, autoJoin: true },
      include: { tenant: true },
    });
    if (!match || match.tenant.status !== 'ACTIVE') return null;

    return { tenantId: match.tenantId, tenantName: match.tenant.name, defaultRoleId: match.defaultRoleId };
  }

  private async findOwned(tenantId: string, id: string) {
    const domain = await this.prisma.tenantDomain.findFirst({ where: { id, tenantId } });
    if (!domain) throw new NotFoundException('Domain not found');
    return domain;
  }
}
