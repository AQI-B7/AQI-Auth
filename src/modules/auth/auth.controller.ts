import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  VerifyEmailDto,
  Enable2FADto,
  MagicLinkRequestDto,
  MagicLinkVerifyDto,
} from './dto/auth.dto';
import { Public } from '../../common/decorators/public.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { Throttle } from '@nestjs/throttler';
import { GoogleOAuthGuard, GithubOAuthGuard } from './guards/oauth.guards';
import { OAuthProfile } from './strategies/oauth-profile.interface';
import { MetricsService } from '../metrics/metrics.service';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly metrics: MetricsService,
  ) {}

  // ─────────────────────────────────────────────
  // CSRF (only relevant to browser/cookie-based clients — see
  // CsrfMiddleware; pure Bearer-token API clients can ignore this)
  // ─────────────────────────────────────────────
  @Public()
  @Get('csrf-token')
  csrfToken(@Req() req: Request) {
    return { csrfToken: req.cookies?.['csrf_token'] ?? null };
  }

  // ─────────────────────────────────────────────
  // Magic Link (passwordless)
  // ─────────────────────────────────────────────
  @Public()
  @Post('magic-link/request')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  async requestMagicLink(@Body() dto: MagicLinkRequestDto) {
    return this.authService.requestMagicLink(dto);
  }

  @Public()
  @Post('magic-link/verify')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async verifyMagicLink(@Body() dto: MagicLinkVerifyDto, @Req() req: Request) {
    return this.authService.verifyMagicLink(dto.token, req.ip, req.headers['user-agent']);
  }

  // ─────────────────────────────────────────────
  // OAuth (Google / GitHub) — each optional, gated on config
  // ─────────────────────────────────────────────
  @Public()
  @Get('oauth/providers')
  oauthProviders() {
    return {
      google: this.config.get<boolean>('oauth.google.enabled') ?? false,
      github: this.config.get<boolean>('oauth.github.enabled') ?? false,
    };
  }

  @Public()
  @Get('oauth/google')
  @UseGuards(GoogleOAuthGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async googleAuth() {
    // Guard performs the redirect to Google's consent screen; this handler
    // body never runs, but NestJS requires one for route registration.
    if (!this.config.get<boolean>('oauth.google.enabled')) {
      throw new NotFoundException('Google OAuth is not configured on this server');
    }
  }

  @Public()
  @Get('oauth/google/callback')
  @UseGuards(GoogleOAuthGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async googleCallback(
    @Req() req: Request & { user: OAuthProfile },
    @Query('state') state: string | undefined,
    @Res() res: Response,
  ) {
    return this.finishOAuthLogin(req.user, state, req, res);
  }

  @Public()
  @Get('oauth/github')
  @UseGuards(GithubOAuthGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async githubAuth() {
    if (!this.config.get<boolean>('oauth.github.enabled')) {
      throw new NotFoundException('GitHub OAuth is not configured on this server');
    }
  }

  @Public()
  @Get('oauth/github/callback')
  @UseGuards(GithubOAuthGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async githubCallback(
    @Req() req: Request & { user: OAuthProfile },
    @Query('state') state: string | undefined,
    @Res() res: Response,
  ) {
    return this.finishOAuthLogin(req.user, state, req, res);
  }

  private async finishOAuthLogin(
    profile: OAuthProfile,
    state: string | undefined,
    req: Request,
    res: Response,
  ) {
    let tenantSlug: string | undefined;
    if (state) {
      try {
        tenantSlug = JSON.parse(Buffer.from(state, 'base64url').toString('utf8')).tenantSlug;
      } catch {
        // Malformed/foreign state — ignore rather than fail the login.
      }
    }

    const frontendUrl = this.config.get<string>('frontendUrl');
    try {
      const result = await this.authService.handleOAuthLogin(
        profile,
        tenantSlug,
        req.ip,
        req.headers['user-agent'],
      );
      // Tokens are returned in the URL fragment (never sent to the server
      // in a Referer header, never logged by intermediate proxies).
      const params = new URLSearchParams({
        access_token: result.accessToken,
        refresh_token: result.refreshToken,
        token_type: result.tokenType,
        expires_in: String(result.expiresIn),
        is_new_user: String(result.isNewUser),
      });
      return res.redirect(302, `${frontendUrl}/oauth/callback#${params.toString()}`);
    } catch (err) {
      this.logger.warn(`OAuth login failed: ${(err as Error).message}`);
      this.metrics.oauthLoginTotal.inc({ provider: profile.provider, result: 'failed' });
      const params = new URLSearchParams({ error: 'oauth_failed' });
      return res.redirect(302, `${frontendUrl}/oauth/callback#${params.toString()}`);
    }
  }

  @Public()
  @Post('register')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  async register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(dto, req.ip, req.headers['user-agent']);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.authService.login(dto, req.ip, req.headers['user-agent']);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshTokenDto, @Req() req: Request) {
    return this.authService.refresh(dto, req.ip, req.headers['user-agent']);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser() user: AuthUser) {
    return this.authService.logout(user.userId, user.jti, user.sessionId);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto.token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/setup')
  async setup2FA(@CurrentUser() user: AuthUser) {
    return this.authService.setup2FA(user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/enable')
  async enable2FA(@CurrentUser() user: AuthUser, @Body() dto: Enable2FADto) {
    return this.authService.enable2FA(user.userId, dto.totpCode);
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/disable')
  async disable2FA(@CurrentUser() user: AuthUser, @Body() dto: Enable2FADto) {
    return this.authService.disable2FA(user.userId, dto.totpCode);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@CurrentUser() user: AuthUser) {
    return { user };
  }
}
