import { Module } from '@nestjs/common';
import { SsoService } from './sso.service';
import { SsoController } from './sso.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule], // for AuthService.issueTokens/collectPermissions
  controllers: [SsoController],
  providers: [SsoService],
  exports: [SsoService],
})
export class SsoModule {}
