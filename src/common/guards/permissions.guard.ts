import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { AuthUser } from '../decorators/current-user.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!required || required.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as AuthUser;

    if (!user?.permissions) {
      throw new ForbiddenException('No permissions found');
    }

    // Call sites list alternatives, e.g. RequirePermissions('webhooks:write', '*'),
    // meaning "any one of these" — a full wildcard grant OR any specific
    // permission in the list. (Previously this used `.every()`, which
    // required the caller to hold every listed permission simultaneously,
    // including the literal '*' — meaning even admin/wildcard roles were
    // rejected by any permission-gated route. Fixed to proper OR/wildcard
    // semantics.)
    const hasAccess =
      user.permissions.includes('*') || required.some((p) => user.permissions.includes(p));
    if (!hasAccess) {
      throw new ForbiddenException(`Missing required permissions: ${required.join(', ')}`);
    }

    return true;
  }
}
