import { Module } from '@nestjs/common';
import { ImpersonationService } from './impersonation.service';
import { ImpersonationController } from './impersonation.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule], // for AuthService.signAccessToken/collectPermissions
  controllers: [ImpersonationController],
  providers: [ImpersonationService],
  exports: [ImpersonationService],
})
export class ImpersonationModule {}
