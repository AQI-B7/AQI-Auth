import { Body, Controller, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { ImpersonationService } from './impersonation.service';
import { StartImpersonationDto } from './dto/impersonation.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('impersonation')
@UseGuards(JwtAuthGuard)
export class ImpersonationController {
  constructor(private readonly impersonation: ImpersonationService) {}

  @Post('start')
  @RequirePermissions('impersonate:*')
  start(@CurrentUser() user: AuthUser, @Body() dto: StartImpersonationDto, @Req() req: Request) {
    return this.impersonation.start(user, dto.targetUserId, dto.reason, req.ip, req.headers['user-agent']);
  }

  @Post(':sessionId/end')
  @RequirePermissions('impersonate:*')
  end(@CurrentUser() user: AuthUser, @Param('sessionId') sessionId: string) {
    return this.impersonation.end(user, sessionId);
  }

  @Get('active')
  @RequirePermissions('impersonate:*')
  active(@CurrentUser() user: AuthUser) {
    return this.impersonation.listActive(user.tenantId);
  }

  @Get('history')
  @RequirePermissions('impersonate:*')
  history(@CurrentUser() user: AuthUser) {
    return this.impersonation.listHistory(user.tenantId);
  }
}
