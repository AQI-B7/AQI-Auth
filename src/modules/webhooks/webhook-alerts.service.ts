import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { EmailService } from '../email/email.service';
import { PrismaService } from '../../prisma/prisma.service';

export interface DeadLetterAlertInput {
  deliveryId: string;
  endpointId: string;
  endpointUrl: string;
  tenantId: string;
  eventType: string;
  attempts: number;
  errorMessage?: string | null;
  responseStatus?: number | null;
}

/**
 * Fires a best-effort notification whenever a webhook delivery exhausts
 * all its retry attempts. Two channels, both optional and independent:
 *
 *  - Ops webhook (Slack-compatible "incoming webhook" POST) — for the
 *    team running this auth service to notice a downstream integration
 *    is broken.
 *  - Email to the tenant — so the tenant that *owns* the failing
 *    endpoint finds out without having to poll the deliveries API.
 *
 * A failure to send either notification is logged and swallowed — an
 * alerting failure must never affect the delivery pipeline itself.
 */
@Injectable()
export class WebhookAlertsService {
  private readonly logger = new Logger(WebhookAlertsService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly emailService: EmailService,
    private readonly prisma: PrismaService,
  ) {}

  async notifyDeadLetter(input: DeadLetterAlertInput): Promise<void> {
    if (!this.config.get<boolean>('alerts.enabled')) return;

    await Promise.all([this.notifyOpsWebhook(input), this.notifyTenantOwner(input)]);
  }

  private async notifyOpsWebhook(input: DeadLetterAlertInput): Promise<void> {
    const url = this.config.get<string>('alerts.opsWebhookUrl');
    if (!url) return;

    try {
      await axios.post(
        url,
        {
          text:
            `:rotating_light: Webhook delivery dead-lettered\n` +
            `*Tenant:* ${input.tenantId}\n` +
            `*Endpoint:* ${input.endpointUrl}\n` +
            `*Event:* ${input.eventType}\n` +
            `*Attempts:* ${input.attempts}\n` +
            `*Last error:* ${input.errorMessage || `HTTP ${input.responseStatus ?? 'n/a'}`}\n` +
            `*Delivery ID:* ${input.deliveryId}`,
        },
        { timeout: 5000 },
      );
    } catch (err) {
      this.logger.warn(`Failed to post ops alert for delivery ${input.deliveryId}: ${(err as Error).message}`);
    }
  }

  private async notifyTenantOwner(input: DeadLetterAlertInput): Promise<void> {
    try {
      // "Owner" = any user with an admin-level role in the tenant.
      // Keeping this lookup simple/best-effort: if it fails we still
      // don't want to block the delivery pipeline.
      const admins = await this.prisma.user.findMany({
        where: {
          tenantId: input.tenantId,
          status: 'ACTIVE',
          roles: { some: { role: { permissions: { has: '*' } } } },
        },
        select: { email: true },
        take: 5,
      });

      await Promise.all(
        admins.map((admin: { email: string }) =>
          this.emailService.sendWebhookDeadLetterAlert(admin.email, {
            endpointUrl: input.endpointUrl,
            eventType: input.eventType,
            attempts: input.attempts,
            errorMessage: input.errorMessage || (input.responseStatus ? `HTTP ${input.responseStatus}` : undefined),
            deliveryId: input.deliveryId,
          }),
        ),
      );
    } catch (err) {
      this.logger.warn(
        `Failed to notify tenant admins for delivery ${input.deliveryId}: ${(err as Error).message}`,
      );
    }
  }
}
