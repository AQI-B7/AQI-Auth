import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { ScimRequestContext } from './scim-auth.guard';

export const ScimContext = createParamDecorator((_: unknown, ctx: ExecutionContext): ScimRequestContext => {
  const request = ctx.switchToHttp().getRequest();
  return request.scim;
});
