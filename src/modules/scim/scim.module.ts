import { Module } from '@nestjs/common';
import { ScimService } from './scim.service';
import { ScimTokenService } from './scim-token.service';
import { ScimAuthGuard } from './scim-auth.guard';
import { ScimController, ScimTokenController } from './scim.controller';

@Module({
  controllers: [ScimController, ScimTokenController],
  providers: [ScimService, ScimTokenService, ScimAuthGuard],
  exports: [ScimService, ScimTokenService],
})
export class ScimModule {}
