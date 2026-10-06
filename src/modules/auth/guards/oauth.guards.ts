import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Both guards forward `tenantSlug` (if the client passed one on the
 * initiating request) through Passport's `state` parameter so the
 * callback can link the OAuth identity to the right tenant without
 * relying on cookies/sessions — this service is stateless/JWT-only.
 */
function withState(strategy: string) {
  @Injectable()
  class OAuthGuard extends AuthGuard(strategy) {
    getAuthenticateOptions(context: ExecutionContext) {
      const req = context.switchToHttp().getRequest();
      const tenantSlug = req.query?.tenantSlug;
      if (tenantSlug) {
        return { state: Buffer.from(JSON.stringify({ tenantSlug })).toString('base64url') };
      }
      return {};
    }
  }
  return OAuthGuard;
}

export class GoogleOAuthGuard extends withState('google') {}
export class GithubOAuthGuard extends withState('github') {}
