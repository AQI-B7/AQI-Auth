import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { TenantsService } from './tenants.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';

@Controller('tenants')
@UseGuards(JwtAuthGuard)
export class TenantsController {
  constructor(private readonly tenantsService: TenantsService) {}

  @Get('me')
  async getMyTenant(@CurrentUser() user: AuthUser) {
    return this.tenantsService.findById(user.tenantId);
  }

  @Get(':id')
  async getTenant(@Param('id') id: string, @CurrentUser() user: AuthUser) {
    // Users can only see their own tenant
    if (id !== user.tenantId) {
      return this.tenantsService.findById(user.tenantId);
    }
    return this.tenantsService.findById(id);
  }
}
