import { Module } from '@nestjs/common';
import { WebhooksService } from './webhooks.service';
import { WebhooksController } from './webhooks.controller';
import { WebhookDeliveryProcessor } from './webhook-delivery.processor';
import { WebhookEventsListener } from './webhook-events.listener';
import { WebhookAlertsService } from './webhook-alerts.service';
import { webhookQueueProvider } from './webhook-queue.provider';
import { EmailModule } from '../email/email.module';

@Module({
  imports: [EmailModule],
  controllers: [WebhooksController],
  providers: [
    WebhooksService,
    WebhookDeliveryProcessor,
    WebhookEventsListener,
    WebhookAlertsService,
    webhookQueueProvider,
  ],
  exports: [WebhooksService],
})
export class WebhooksModule {}
