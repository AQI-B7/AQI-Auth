import { Module } from '@nestjs/common';
import { WebAuthnService } from './webauthn.service';
import { WebAuthnController } from './webauthn.controller';
import { AuthModule } from '../auth.module';

@Module({
  imports: [AuthModule], // for AuthService.issueTokens/collectPermissions
  controllers: [WebAuthnController],
  providers: [WebAuthnService],
  exports: [WebAuthnService],
})
export class WebAuthnModule {}
