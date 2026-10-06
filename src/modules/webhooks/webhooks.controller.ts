import { Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards } from '@nestjs/common';
import { WebhooksService } from './webhooks.service';
import { CreateWebhookEndpointDto, UpdateWebhookEndpointDto, WEBHOOK_EVENT_TYPES } from './dto/webhook.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('webhooks')
@UseGuards(JwtAuthGuard)
export class WebhooksController {
  constructor(private readonly webhooksService: WebhooksService) {}

  @Get('event-types')
  eventTypes() {
    return { eventTypes: WEBHOOK_EVENT_TYPES };
  }

  @Post('endpoints')
  @RequirePermissions('webhooks:write', '*')
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateWebhookEndpointDto) {
    return this.webhooksService.create(user.tenantId, dto);
  }

  @Get('endpoints')
  @RequirePermissions('webhooks:read', '*')
  list(@CurrentUser() user: AuthUser) {
    return this.webhooksService.list(user.tenantId);
  }

  @Get('endpoints/:id')
  @RequirePermissions('webhooks:read', '*')
  findOne(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.webhooksService.findOne(user.tenantId, id);
  }

  @Patch('endpoints/:id')
  @RequirePermissions('webhooks:write', '*')
  update(@CurrentUser() user: AuthUser, @Param('id') id: string, @Body() dto: UpdateWebhookEndpointDto) {
    return this.webhooksService.update(user.tenantId, id, dto);
  }

  @Post('endpoints/:id/rotate-secret')
  @RequirePermissions('webhooks:write', '*')
  rotateSecret(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.webhooksService.rotateSecret(user.tenantId, id);
  }

  @Delete('endpoints/:id')
  @RequirePermissions('webhooks:write', '*')
  remove(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.webhooksService.remove(user.tenantId, id);
  }

  @Post('endpoints/:id/test')
  @RequirePermissions('webhooks:write', '*')
  sendTest(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.webhooksService.sendTestEvent(user.tenantId, id);
  }

  @Get('endpoints/:id/deliveries')
  @RequirePermissions('webhooks:read', '*')
  deliveries(
    @CurrentUser() user: AuthUser,
    @Param('id') id: string,
    @Query('limit') limit?: string,
  ) {
    return this.webhooksService.listDeliveries(user.tenantId, id, limit ? parseInt(limit, 10) : undefined);
  }

  @Post('endpoints/:id/deliveries/:deliveryId/resend')
  @RequirePermissions('webhooks:write', '*')
  resend(
    @CurrentUser() user: AuthUser,
    @Param('id') id: string,
    @Param('deliveryId') deliveryId: string,
  ) {
    return this.webhooksService.resendDelivery(user.tenantId, id, deliveryId);
  }
}
