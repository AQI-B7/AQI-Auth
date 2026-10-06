import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const activated = await (super.canActivate(context) as Promise<boolean>);
    if (!activated) return false;

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (user?.jti) {
      const blacklisted = await this.redis.isBlacklisted(user.jti);
      if (blacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    if (user?.sessionId) {
      const sessionRevoked = await this.redis.isSessionRevoked(user.sessionId);
      if (sessionRevoked) {
        throw new UnauthorizedException('Session has been revoked');
      }
    }

    return true;
  }

  handleRequest<TUser>(err: Error | null, user: TUser): TUser {
    if (err || !user) {
      throw err || new UnauthorizedException('Invalid or expired token');
    }
    return user;
  }
}
