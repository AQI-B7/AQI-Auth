import { Inject, Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { Queue } from 'bullmq';
import { PrismaService } from '../../prisma/prisma.service';
import { WEBHOOK_QUEUE, WEBHOOK_QUEUE_NAME } from './webhook-queue.provider';
import { CreateWebhookEndpointDto, UpdateWebhookEndpointDto } from './dto/webhook.dto';

export interface WebhookJobData {
  deliveryId: string;
}

@Injectable()
export class WebhooksService {
  private readonly logger = new Logger(WebhooksService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    @Optional() @Inject(WEBHOOK_QUEUE) private readonly queue: Queue<WebhookJobData> | null,
  ) {}

  get isEnabled(): boolean {
    return Boolean(this.queue);
  }

  // ── Endpoint CRUD ────────────────────────────────────────
  async create(tenantId: string, dto: CreateWebhookEndpointDto) {
    const secret = `whsec_${randomBytes(24).toString('hex')}`;
    const endpoint = await this.prisma.webhookEndpoint.create({
      data: {
        tenantId,
        url: dto.url,
        events: dto.events,
        description: dto.description,
        secret,
      },
    });
    // Secret is only ever shown once, at creation, same convention as API keys.
    return endpoint;
  }

  async list(tenantId: string) {
    const endpoints = await this.prisma.webhookEndpoint.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
    return endpoints.map((e: { secret: string; [k: string]: unknown }) => ({
      ...e,
      secret: maskSecret(e.secret),
    }));
  }

  async findOne(tenantId: string, id: string) {
    const endpoint = await this.prisma.webhookEndpoint.findFirst({ where: { id, tenantId } });
    if (!endpoint) throw new NotFoundException('Webhook endpoint not found');
    return endpoint;
  }

  async update(tenantId: string, id: string, dto: UpdateWebhookEndpointDto) {
    await this.findOne(tenantId, id);
    return this.prisma.webhookEndpoint.update({ where: { id }, data: dto });
  }

  async rotateSecret(tenantId: string, id: string) {
    await this.findOne(tenantId, id);
    const secret = `whsec_${randomBytes(24).toString('hex')}`;
    const endpoint = await this.prisma.webhookEndpoint.update({ where: { id }, data: { secret } });
    return endpoint; // full secret shown once, immediately after rotation
  }

  async remove(tenantId: string, id: string) {
    await this.findOne(tenantId, id);
    await this.prisma.webhookEndpoint.delete({ where: { id } });
    return { success: true };
  }

  async listDeliveries(tenantId: string, endpointId: string, limit = 50) {
    await this.findOne(tenantId, endpointId);
    return this.prisma.webhookDelivery.findMany({
      where: { endpointId },
      orderBy: { createdAt: 'desc' },
      take: Math.min(limit, 200),
    });
  }

  async sendTestEvent(tenantId: string, endpointId: string) {
    const endpoint = await this.findOne(tenantId, endpointId);
    return this.enqueueDelivery(endpoint.id, 'webhook.test', {
      message: 'This is a test event from your Standalone Auth Service webhook settings.',
      sentAt: new Date().toISOString(),
    });
  }

  async resendDelivery(tenantId: string, endpointId: string, deliveryId: string) {
    await this.findOne(tenantId, endpointId);
    const original = await this.prisma.webhookDelivery.findFirst({
      where: { id: deliveryId, endpointId },
    });
    if (!original) throw new NotFoundException('Delivery not found');

    return this.enqueueDelivery(
      endpointId,
      original.eventType,
      original.payload as Record<string, unknown>,
    );
  }

  // ── Fan-out ──────────────────────────────────────────────
  /** Called by WebhookEventsListener whenever a domain event fires. */
  async dispatchEvent(tenantId: string, eventType: string, payload: Record<string, unknown>) {
    if (!this.isEnabled) return;

    const endpoints = await this.prisma.webhookEndpoint.findMany({
      where: { tenantId, active: true },
    });
    const subscribed = endpoints.filter(
      (e: { events: string[] }) => e.events.includes(eventType) || e.events.includes('*'),
    );

    await Promise.all(
      subscribed.map((endpoint: { id: string }) =>
        this.enqueueDelivery(endpoint.id, eventType, payload),
      ),
    );
  }

  private async enqueueDelivery(
    endpointId: string,
    eventType: string,
    payload: Record<string, unknown>,
  ) {
    const maxAttempts = this.config.get<number>('webhooks.maxAttempts') || 8;

    const delivery = await this.prisma.webhookDelivery.create({
      data: {
        endpointId,
        eventType,
        eventId: `evt_${randomBytes(12).toString('hex')}`,
        payload,
        maxAttempts,
        status: 'PENDING',
      },
    });

    if (!this.queue) {
      this.logger.warn(
        `Webhook queue disabled; delivery ${delivery.id} created but will not be sent`,
      );
      return delivery;
    }

    await this.queue.add(
      WEBHOOK_QUEUE_NAME,
      { deliveryId: delivery.id },
      {
        attempts: maxAttempts,
        backoff: { type: 'exponential', delay: 5_000 },
      },
    );

    return delivery;
  }
}

function maskSecret(secret: string): string {
  return `${secret.slice(0, 10)}${'*'.repeat(Math.max(secret.length - 14, 4))}${secret.slice(-4)}`;
}
