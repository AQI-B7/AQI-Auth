import { Controller, Get, Post, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { InvitationsService } from './invitations.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';
import { CreateInvitationDto, AcceptInvitationDto } from '../auth/dto/auth.dto';

@Controller('invitations')
export class InvitationsController {
  constructor(private readonly invitationsService: InvitationsService) {}

  @UseGuards(JwtAuthGuard)
  @Post()
  @RequirePermissions('users:invite', '*')
  async create(@CurrentUser() user: AuthUser, @Body() dto: CreateInvitationDto) {
    return this.invitationsService.create(user.tenantId, user.userId, dto.email, dto.roleId);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  @RequirePermissions('users:read', '*')
  async list(@CurrentUser() user: AuthUser) {
    return this.invitationsService.list(user.tenantId);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @RequirePermissions('users:invite', '*')
  async revoke(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.invitationsService.revoke(user.tenantId, id);
  }

  @Public()
  @Post('accept')
  async accept(@Body() dto: AcceptInvitationDto) {
    return this.invitationsService.accept(dto.token, dto.password, dto.firstName, dto.lastName);
  }
}
