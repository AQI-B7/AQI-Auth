import { Controller, Get, Post, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { ApiKeysService } from './api-keys.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';
import { CreateApiKeyDto } from '../auth/dto/auth.dto';

@Controller('api-keys')
@UseGuards(JwtAuthGuard)
export class ApiKeysController {
  constructor(private readonly apiKeysService: ApiKeysService) {}

  @Post()
  @RequirePermissions('api_keys:write', '*')
  async create(@CurrentUser() user: AuthUser, @Body() dto: CreateApiKeyDto) {
    return this.apiKeysService.create(user.tenantId, user.userId, dto.name, dto.scopes);
  }

  @Get()
  @RequirePermissions('api_keys:read', '*')
  async list(@CurrentUser() user: AuthUser) {
    return this.apiKeysService.list(user.tenantId);
  }

  @Delete(':id')
  @RequirePermissions('api_keys:write', '*')
  async revoke(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.apiKeysService.revoke(user.tenantId, id);
  }
}
