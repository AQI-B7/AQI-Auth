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
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { SsoService } from './sso.service';
import { CreateSsoConnectionDto, UpdateSsoConnectionDto, SamlCallbackDto } from './dto/sso.dto';
import { Public } from '../../common/decorators/public.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('sso')
export class SsoController {
  constructor(
    private readonly sso: SsoService,
    private readonly config: ConfigService,
  ) {}

  // ── Admin: connection management (tenant-scoped) ──

  @Post('connections')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:write', '*')
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateSsoConnectionDto) {
    return this.sso.create(user.tenantId, dto);
  }

  @Get('connections')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:read', '*')
  list(@CurrentUser() user: AuthUser) {
    return this.sso.list(user.tenantId);
  }

  @Get('connections/:id')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:read', '*')
  findOne(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.sso.findOne(user.tenantId, id);
  }

  @Patch('connections/:id')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:write', '*')
  update(@CurrentUser() user: AuthUser, @Param('id') id: string, @Body() dto: UpdateSsoConnectionDto) {
    return this.sso.update(user.tenantId, id, dto);
  }

  @Delete('connections/:id')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:write', '*')
  remove(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.sso.remove(user.tenantId, id);
  }

  @Get('connections/:id/metadata')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('sso:read', '*')
  @Header('Content-Type', 'application/xml')
  async metadata(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.sso.serviceProviderMetadata(user.tenantId, id);
  }

  // ── SP-initiated login (public — this IS the login flow) ──

  @Public()
  @Get('login/:tenantSlug/:connectionId')
  async login(
    @Param('tenantSlug') tenantSlug: string,
    @Param('connectionId') connectionId: string,
    @Res() res: Response,
  ) {
    // RelayState round-trips through the IdP unmodified; we use it purely
    // to correlate the callback back to this same connection/tenant in
    // case a future multi-IdP deployment wants to log it, not as a
    // security boundary (that's what path params + issuer verification
    // in the callback are for).
    const relayState = randomUUID();
    const url = await this.sso.getLoginUrl(tenantSlug, connectionId, relayState);
    return res.redirect(302, url);
  }

  // ── Assertion Consumer Service — the IdP POSTs here after the user
  // authenticates on their side. Public by necessity (the browser
  // arrives here with no prior session of ours). ──

  @Public()
  @Post('callback/:tenantSlug/:connectionId')
  @HttpCode(HttpStatus.OK)
  async callback(
    @Param('tenantSlug') tenantSlug: string,
    @Param('connectionId') connectionId: string,
    @Body() dto: SamlCallbackDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const frontendUrl = this.config.get<string>('frontendUrl');
    try {
      const result = await this.sso.handleCallback(
        tenantSlug,
        connectionId,
        dto.SAMLResponse,
        req.ip,
        req.headers['user-agent'],
      );
      const params = new URLSearchParams({
        access_token: result.accessToken,
        refresh_token: result.refreshToken,
        token_type: result.tokenType,
        expires_in: String(result.expiresIn),
        is_new_user: String(result.isNewUser),
      });
      return res.redirect(302, `${frontendUrl}/oauth/callback#${params.toString()}`);
    } catch (err) {
      const params = new URLSearchParams({ error: 'sso_failed' });
      return res.redirect(302, `${frontendUrl}/oauth/callback#${params.toString()}`);
    }
  }
}
