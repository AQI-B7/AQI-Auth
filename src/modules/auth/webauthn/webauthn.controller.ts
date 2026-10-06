import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Req } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { Request } from 'express';
import { WebAuthnService } from './webauthn.service';
import { Public } from '../../../common/decorators/public.decorator';
import { CurrentUser, AuthUser } from '../../../common/decorators/current-user.decorator';
import {
  WebAuthnRegisterOptionsDto,
  WebAuthnRegisterVerifyDto,
  WebAuthnAuthOptionsDto,
  WebAuthnAuthVerifyDto,
} from './dto/webauthn.dto';

@Controller('auth/webauthn')
export class WebAuthnController {
  constructor(private readonly webauthn: WebAuthnService) {}

  // ── Registration — requires an existing authenticated session; a
  // passkey is an additional credential added to an account, not (in
  // this service) a way to create a brand-new account from scratch. ──

  @Post('register/options')
  @HttpCode(HttpStatus.OK)
  async registerOptions(@CurrentUser() user: AuthUser, @Body() dto: WebAuthnRegisterOptionsDto) {
    return this.webauthn.generateRegistrationOptionsFor(user.userId, dto.credentialName);
  }

  @Post('register/verify')
  @HttpCode(HttpStatus.OK)
  async registerVerify(@CurrentUser() user: AuthUser, @Body() dto: WebAuthnRegisterVerifyDto) {
    return this.webauthn.verifyRegistration(user.userId, dto.response as any, dto.credentialName);
  }

  @Get('credentials')
  async listCredentials(@CurrentUser() user: AuthUser) {
    return this.webauthn.listCredentials(user.userId);
  }

  @Delete('credentials/:id')
  async removeCredential(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.webauthn.removeCredential(user.userId, id);
  }

  // ── Authentication — public, since signing in is by definition
  // pre-authentication. Supports both a username-first flow (pass
  // `email`) and a fully usernameless/discoverable-credential flow
  // (omit `email` entirely, letting the platform authenticator's own
  // account picker do the work). ──

  @Public()
  @Post('login/options')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async loginOptions(@Body() dto: WebAuthnAuthOptionsDto) {
    return this.webauthn.generateAuthenticationOptionsFor(dto.email, dto.tenantSlug);
  }

  @Public()
  @Post('login/verify')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async loginVerify(@Body() dto: WebAuthnAuthVerifyDto, @Req() req: Request) {
    return this.webauthn.verifyAuthentication(dto.response as any, req.ip, req.headers['user-agent']);
  }
}
