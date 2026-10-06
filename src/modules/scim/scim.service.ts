import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { ScimUserPayload, ScimPatchPayload } from './dto/scim.dto';

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

/**
 * SCIM 2.0 (RFC 7643 resource model, RFC 7644 protocol) for the User
 * resource — the operation every IdP's provisioning connector actually
 * exercises in practice (create on hire, PATCH active:false on
 * deprovision, occasional attribute sync). Groups/Roles provisioning is
 * intentionally not implemented: RBAC roles here are tenant-defined and
 * don't map cleanly onto SCIM's Group resource without inventing
 * semantics no IdP will agree on, so this service is upfront about only
 * covering Users.
 */
@Injectable()
export class ScimService {
  constructor(private readonly prisma: PrismaService) {}

  async listUsers(tenantId: string, filter?: string, startIndex = 1, count = 20) {
    const where: Record<string, unknown> = { tenantId };
    const parsedFilter = parseFilter(filter);
    if (parsedFilter) {
      where[parsedFilter.field] = parsedFilter.value;
    }

    const safeStart = Math.max(1, startIndex);
    const safeCount = Math.min(Math.max(1, count), 100);

    const [total, users] = await Promise.all([
      this.prisma.user.count({ where }),
      this.prisma.user.findMany({
        where,
        skip: safeStart - 1,
        take: safeCount,
        orderBy: { createdAt: 'asc' },
      }),
    ]);

    return {
      schemas: [LIST_SCHEMA],
      totalResults: total,
      startIndex: safeStart,
      itemsPerPage: users.length,
      Resources: users.map(toScimUser),
    };
  }

  async getUser(tenantId: string, id: string) {
    const user = await this.prisma.user.findFirst({ where: { id, tenantId } });
    if (!user) throw new ScimNotFoundException(id);
    return toScimUser(user);
  }

  async createUser(tenantId: string, payload: ScimUserPayload) {
    const email = extractPrimaryEmail(payload);
    if (!email) {
      throw new BadRequestException('SCIM User payload must include userName or an emails[] entry');
    }

    const existing = await this.prisma.user.findFirst({ where: { tenantId, email: email.toLowerCase() } });
    if (existing) {
      throw new ConflictException(`A user with email ${email} already exists in this tenant`);
    }

    const memberRole = await this.prisma.role.findFirst({ where: { tenantId, name: 'member' } });

    const user = await this.prisma.$transaction(async (tx: any) => {
      const created = await tx.user.create({
        data: {
          tenantId,
          email: email.toLowerCase(),
          firstName: payload.name?.givenName,
          lastName: payload.name?.familyName,
          status: payload.active === false ? 'DISABLED' : 'ACTIVE',
          emailVerified: true, // provisioned by a trusted IdP
        },
      });
      if (memberRole) {
        await tx.userRole.create({ data: { userId: created.id, roleId: memberRole.id } });
      }
      return created;
    });

    return toScimUser(user);
  }

  /** SCIM PUT — full replace of the mutable attributes we support. */
  async replaceUser(tenantId: string, id: string, payload: ScimUserPayload) {
    const existing = await this.prisma.user.findFirst({ where: { id, tenantId } });
    if (!existing) throw new ScimNotFoundException(id);

    const email = extractPrimaryEmail(payload) ?? existing.email;

    const user = await this.prisma.user.update({
      where: { id },
      data: {
        email: email.toLowerCase(),
        firstName: payload.name?.givenName ?? existing.firstName,
        lastName: payload.name?.familyName ?? existing.lastName,
        status: payload.active === false ? 'DISABLED' : 'ACTIVE',
      },
    });

    return toScimUser(user);
  }

  /** SCIM PATCH — the deprovisioning path (`active: false`) is the one
   *  every IdP actually relies on; we support that plus the other
   *  common top-level attribute replacements. */
  async patchUser(tenantId: string, id: string, payload: ScimPatchPayload) {
    const existing = await this.prisma.user.findFirst({ where: { id, tenantId } });
    if (!existing) throw new ScimNotFoundException(id);

    const data: Record<string, unknown> = {};

    for (const operation of payload.Operations || []) {
      const op = operation.op?.toLowerCase();
      if (op !== 'replace' && op !== 'add') continue; // 'remove' has no meaningful target on this resource

      const path = operation.path?.toLowerCase();
      const value = operation.value;

      if (path === 'active' || (!path && isRecord(value) && 'active' in value)) {
        const active = path === 'active' ? value : (value as Record<string, unknown>).active;
        data.status = active === false ? 'DISABLED' : 'ACTIVE';
      } else if (path === 'name.givenname') {
        data.firstName = value;
      } else if (path === 'name.familyname') {
        data.lastName = value;
      } else if (path === 'username' || path === 'emails' || path === 'emails[type eq "work"].value') {
        const email = typeof value === 'string' ? value : extractPrimaryEmail({ emails: value as any });
        if (email) data.email = email.toLowerCase();
      } else if (!path && isRecord(value)) {
        if ('active' in value) data.status = value.active === false ? 'DISABLED' : 'ACTIVE';
        if ('userName' in value && typeof value.userName === 'string') data.email = (value.userName as string).toLowerCase();
      }
    }

    if (Object.keys(data).length === 0) {
      // Nothing we understood — RFC 7644 §3.5.2 says the server MAY
      // ignore unsupported attributes rather than error, so we return
      // the resource unchanged instead of a 400.
      return toScimUser(existing);
    }

    const user = await this.prisma.user.update({ where: { id }, data });
    return toScimUser(user);
  }

  async deleteUser(tenantId: string, id: string) {
    const existing = await this.prisma.user.findFirst({ where: { id, tenantId } });
    if (!existing) throw new ScimNotFoundException(id);
    // SCIM DELETE conventionally deactivates rather than hard-deletes in
    // most real deployments (preserves audit history/ownership of
    // resources created by the user).
    await this.prisma.user.update({ where: { id }, data: { status: 'DISABLED' } });
  }
}

/** RFC 7644 §3.12 error response shape. */
export class ScimNotFoundException extends NotFoundException {
  constructor(id: string) {
    super({
      schemas: [ERROR_SCHEMA],
      detail: `User ${id} not found`,
      status: '404',
    });
  }
}

function toScimUser(user: {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    schemas: [USER_SCHEMA],
    id: user.id,
    userName: user.email,
    name: { givenName: user.firstName ?? undefined, familyName: user.lastName ?? undefined },
    emails: [{ value: user.email, primary: true }],
    active: user.status === 'ACTIVE',
    meta: {
      resourceType: 'User',
      created: user.createdAt.toISOString(),
      lastModified: user.updatedAt.toISOString(),
    },
  };
}

function extractPrimaryEmail(payload: ScimUserPayload): string | undefined {
  const fromEmails = payload.emails?.find((e) => e.primary)?.value || payload.emails?.[0]?.value;
  const fromUserName = payload.userName?.includes('@') ? payload.userName : undefined;
  return fromEmails || fromUserName;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

/**
 * Minimal SCIM filter support: `userName eq "value"` and
 * `emails.value eq "value"`, which covers the two filters real IdPs
 * actually send (checking whether a user already exists before create).
 * Full SCIM filter grammar (and/or, pr, co, sw, nested groups) is a
 * small parser/grammar project on its own; this covers the practical
 * subset without pretending to be a complete implementation.
 */
function parseFilter(filter?: string): { field: 'email'; value: string } | null {
  if (!filter) return null;
  const match = filter.match(/^(userName|emails(?:\.value)?)\s+eq\s+"([^"]+)"$/i);
  if (!match) return null;
  return { field: 'email', value: match[2].toLowerCase() };
}
