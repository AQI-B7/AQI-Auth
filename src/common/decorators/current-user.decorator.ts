import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export interface AuthUser {
  userId: string;
  tenantId: string;
  email: string;
  permissions: string[];
  sessionId?: string;
  jti?: string;
  /** Present only on a short-lived impersonation token — the admin
   *  user id who is acting as this user. Every service that logs
   *  security-sensitive actions should include this when present. */
  impersonatedBy?: string;
}

export const CurrentUser = createParamDecorator(
  (data: keyof AuthUser | undefined, ctx: ExecutionContext): AuthUser | unknown => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as AuthUser;
    return data ? user?.[data] : user;
  },
);
