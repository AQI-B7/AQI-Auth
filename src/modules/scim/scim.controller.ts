import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ScimService } from './scim.service';
import { ScimTokenService } from './scim-token.service';
import { ScimAuthGuard, ScimRequestContext } from './scim-auth.guard';
import { ScimContext } from './scim-context.decorator';
import { ScimUserPayload, ScimPatchPayload, CreateScimTokenDto } from './dto/scim.dto';
import { Public } from '../../common/decorators/public.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

const SCIM_CONTENT_TYPE = 'application/scim+json';

/**
 * SCIM 2.0 provisioning endpoints (RFC 7644), authenticated by a
 * per-tenant ScimToken bearer token — NOT the regular user JWT, since
 * the caller here is an IdP's provisioning connector, not a logged-in
 * user. `@Public()` opts these routes out of the global JwtAuthGuard;
 * `ScimAuthGuard` is this controller's own auth instead.
 *
 * Mounted at /v1/scim/v2/* (the global 'v1' prefix still applies) —
 * most IdPs let you configure an arbitrary base URL for the SCIM
 * connector, so this doesn't need to be the bare RFC-conventional path.
 */
@Controller('scim/v2')
@Public()
@UseGuards(ScimAuthGuard)
export class ScimController {
  constructor(private readonly scim: ScimService) {}

  @Get('Users')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  listUsers(
    @ScimContext() ctx: ScimRequestContext,
    @Query('filter') filter?: string,
    @Query('startIndex') startIndex?: string,
    @Query('count') count?: string,
  ) {
    return this.scim.listUsers(
      ctx.tenantId,
      filter,
      startIndex ? parseInt(startIndex, 10) : undefined,
      count ? parseInt(count, 10) : undefined,
    );
  }

  @Get('Users/:id')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  getUser(@ScimContext() ctx: ScimRequestContext, @Param('id') id: string) {
    return this.scim.getUser(ctx.tenantId, id);
  }

  @Post('Users')
  @HttpCode(HttpStatus.CREATED)
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  createUser(@ScimContext() ctx: ScimRequestContext, @Body() body: ScimUserPayload) {
    return this.scim.createUser(ctx.tenantId, body);
  }

  @Put('Users/:id')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  replaceUser(@ScimContext() ctx: ScimRequestContext, @Param('id') id: string, @Body() body: ScimUserPayload) {
    return this.scim.replaceUser(ctx.tenantId, id, body);
  }

  @Patch('Users/:id')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  patchUser(@ScimContext() ctx: ScimRequestContext, @Param('id') id: string, @Body() body: ScimPatchPayload) {
    return this.scim.patchUser(ctx.tenantId, id, body);
  }

  @Delete('Users/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteUser(@ScimContext() ctx: ScimRequestContext, @Param('id') id: string) {
    await this.scim.deleteUser(ctx.tenantId, id);
  }

  // ── Metadata endpoints many IdP connectors probe before provisioning ──

  @Get('ServiceProviderConfig')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  serviceProviderConfig() {
    return {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          type: 'oauthbearertoken',
          name: 'OAuth Bearer Token',
          description: 'Per-tenant SCIM provisioning token',
        },
      ],
    };
  }

  @Get('ResourceTypes')
  @Header('Content-Type', SCIM_CONTENT_TYPE)
  resourceTypes() {
    return {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: 1,
      Resources: [
        {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
          id: 'User',
          name: 'User',
          endpoint: '/Users',
          schema: 'urn:ietf:params:scim:schemas:core:2.0:User',
        },
      ],
    };
  }
}

/**
 * Token management for the SCIM connector itself — this IS behind the
 * normal JWT + RBAC guard, since it's a tenant-admin action, not
 * something the IdP connector calls.
 */
@Controller('scim/tokens')
@UseGuards(JwtAuthGuard)
export class ScimTokenController {
  constructor(private readonly tokens: ScimTokenService) {}

  @Post()
  @RequirePermissions('scim:write', '*')
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateScimTokenDto) {
    return this.tokens.create(user.tenantId, dto.name);
  }

  @Get()
  @RequirePermissions('scim:read', '*')
  list(@CurrentUser() user: AuthUser) {
    return this.tokens.list(user.tenantId);
  }

  @Delete(':id')
  @RequirePermissions('scim:write', '*')
  revoke(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.tokens.revoke(user.tenantId, id);
  }
}
