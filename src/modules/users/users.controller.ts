import { Controller, Get, Patch, Post, Body, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';
import { UpdateProfileDto, ChangePasswordDto } from '../auth/dto/auth.dto';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  async getMe(@CurrentUser() user: AuthUser) {
    return this.usersService.findById(user.userId);
  }

  @Patch('me')
  async updateMe(@CurrentUser() user: AuthUser, @Body() dto: UpdateProfileDto) {
    return this.usersService.updateProfile(user.userId, dto);
  }

  @Post('me/change-password')
  async changePassword(@CurrentUser() user: AuthUser, @Body() dto: ChangePasswordDto) {
    return this.usersService.changePassword(user.userId, dto.currentPassword, dto.newPassword);
  }

  @Get()
  @RequirePermissions('users:read', '*')
  async listUsers(@CurrentUser() user: AuthUser) {
    return this.usersService.listByTenant(user.tenantId);
  }

  @Post(':id/ban')
  @RequirePermissions('users:manage', '*')
  async banUser(
    @CurrentUser() user: AuthUser,
    @Param('id') id: string,
    @Body('reason') reason?: string,
  ) {
    return this.usersService.banUser(user.tenantId, id, reason);
  }

  @Post(':id/unban')
  @RequirePermissions('users:manage', '*')
  async unbanUser(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.usersService.unbanUser(user.tenantId, id);
  }
}
