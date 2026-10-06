import { Controller, Get, Delete, Param, UseGuards } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  @Get()
  async list(@CurrentUser() user: AuthUser) {
    return this.sessionsService.listSessions(user.userId, user.sessionId);
  }

  @Delete(':id')
  async revoke(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.sessionsService.revokeSession(user.userId, id);
  }

  @Delete()
  async revokeAll(@CurrentUser() user: AuthUser) {
    return this.sessionsService.revokeAllSessions(user.userId, user.sessionId);
  }

  // ── Admin: manage another tenant member's sessions ──

  @Get('admin/users/:userId')
  @RequirePermissions('sessions:read', '*')
  adminList(@CurrentUser() user: AuthUser, @Param('userId') userId: string) {
    return this.sessionsService.adminListSessions(user.tenantId, userId);
  }

  @Delete('admin/:sessionId')
  @RequirePermissions('sessions:write', '*')
  adminRevoke(@CurrentUser() user: AuthUser, @Param('sessionId') sessionId: string) {
    return this.sessionsService.adminRevokeSession(user.tenantId, sessionId);
  }
}
