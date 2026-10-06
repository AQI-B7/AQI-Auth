import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
// passport-github2 ships no types; @types/passport-github2 provides them.
import { Strategy, Profile } from 'passport-github2';
import { OAuthProfile } from './oauth-profile.interface';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(config: ConfigService) {
    super({
      clientID: config.get<string>('oauth.github.clientId')!,
      clientSecret: config.get<string>('oauth.github.clientSecret')!,
      callbackURL: config.get<string>('oauth.github.callbackUrl')!,
      scope: ['user:email'],
      // See google.strategy.ts — no built-in `state` verification; we
      // pass our own opaque state through GithubOAuthGuard instead.
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (err: Error | null, user?: OAuthProfile) => void,
  ): Promise<void> {
    // GitHub's primary profile.emails entry is not guaranteed to be the
    // verified/primary address, but the GitHub API only returns emails
    // matching the granted `user:email` scope here; prefer the first one.
    const email = profile.emails?.[0]?.value;
    if (!email) {
      return done(
        new Error(
          'GitHub account has no public/verified email. Enable "user:email" scope or add a verified email to your GitHub account.',
        ),
      );
    }

    const oauthProfile: OAuthProfile = {
      provider: 'github',
      providerAccountId: profile.id,
      email: email.toLowerCase(),
      emailVerified: true,
      firstName: profile.displayName || profile.username,
      lastName: undefined,
      imageUrl: profile.photos?.[0]?.value,
      accessToken,
      refreshToken,
      raw: (profile as unknown as { _json?: unknown })._json,
    };

    done(null, oauthProfile);
  }
}
