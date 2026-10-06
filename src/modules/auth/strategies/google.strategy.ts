import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, VerifyCallback, Profile } from 'passport-google-oauth20';
import { OAuthProfile } from './oauth-profile.interface';

/**
 * Only ever constructed when GOOGLE_CLIENT_ID/SECRET are set — see
 * AuthModule, which conditionally includes this provider. Passport
 * requires real-looking options even so, since the constructor validates
 * them eagerly.
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(config: ConfigService) {
    super({
      clientID: config.get<string>('oauth.google.clientId')!,
      clientSecret: config.get<string>('oauth.google.clientSecret')!,
      callbackURL: config.get<string>('oauth.google.callbackUrl')!,
      scope: ['profile', 'email'],
      // NOTE: we deliberately do NOT set `state: true` here. That flag
      // enables Passport's built-in session-backed state verification,
      // which this service can't use (stateless, JWT-only, no session
      // middleware). We instead pass our own opaque state string
      // per-request via GoogleOAuthGuard.getAuthenticateOptions() and
      // just echo it back unverified in the callback (it only ever
      // carries a non-sensitive tenantSlug hint, never used for auth).
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<void> {
    const email = profile.emails?.[0]?.value;
    if (!email) {
      return done(new Error('Google account has no verified email'), undefined);
    }

    const oauthProfile: OAuthProfile = {
      provider: 'google',
      providerAccountId: profile.id,
      email: email.toLowerCase(),
      emailVerified: profile.emails?.[0]?.verified !== false,
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      imageUrl: profile.photos?.[0]?.value,
      accessToken,
      refreshToken,
      raw: profile._json,
    };

    done(null, oauthProfile);
  }
}
