import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job, Worker } from 'bullmq';
import axios from 'axios';
import { PrismaService } from '../../prisma/prisma.service';
import { createBullConnection, WEBHOOK_QUEUE_NAME } from './webhook-queue.provider';
import { signWebhookPayload } from './webhook-signature.util';
import { WebhookJobData } from './webhooks.service';
import { WebhookAlertsService } from './webhook-alerts.service';
import { MetricsService } from '../metrics/metrics.service';

/**
 * Standalone BullMQ worker for outgoing webhook delivery.
 *
 * Retry policy: BullMQ handles exponential backoff/rescheduling natively
 * (job.opts.attempts / backoff, set at enqueue time in WebhooksService).
 * This processor's job is: sign, POST, persist the outcome, and decide
 * whether the *failure itself* is retryable (network/5xx/timeout → yes;
 * a malformed endpoint → no point retrying, though we still let BullMQ's
 * budget run out rather than guessing wrong and dropping a delivery).
 */
@Injectable()
export class WebhookDeliveryProcessor implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(WebhookDeliveryProcessor.name);
  private worker: Worker<WebhookJobData> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly alerts: WebhookAlertsService,
    private readonly metrics: MetricsService,
  ) {}

  onModuleInit() {
    if (!this.config.get<boolean>('webhooks.enabled')) {
      this.logger.warn('Webhooks disabled — delivery worker not started');
      return;
    }
    const connection = createBullConnection(this.config.get<string>('redisUrl')!);
    this.worker = new Worker<WebhookJobData>(
      WEBHOOK_QUEUE_NAME,
      (job) => this.process(job),
      { connection, concurrency: 10 },
    );
    this.worker.on('failed', (job, err) => {
      this.logger.warn(`Webhook delivery ${job?.data.deliveryId} attempt failed: ${err.message}`);
    });
    this.logger.log('Webhook delivery worker started');
  }

  async onModuleDestroy() {
    await this.worker?.close();
  }

  async process(job: Job<WebhookJobData>): Promise<void> {
    const delivery = await this.prisma.webhookDelivery.findUnique({
      where: { id: job.data.deliveryId },
      include: { endpoint: true },
    });
    if (!delivery) {
      this.logger.warn(`Delivery ${job.data.deliveryId} no longer exists — skipping`);
      return;
    }

    if (!delivery.endpoint.active) {
      await this.prisma.webhookDelivery.update({
        where: { id: delivery.id },
        data: { status: 'FAILED', errorMessage: 'Endpoint disabled' },
      });
      return; // not retried — nothing will change until re-enabled
    }

    const attemptNumber = job.attemptsMade + 1;
    const isLastAttempt = attemptNumber >= (job.opts.attempts ?? 1);

    await this.prisma.webhookDelivery.update({
      where: { id: delivery.id },
      data: { status: 'DELIVERING', attempts: attemptNumber },
    });

    const rawBody = JSON.stringify({
      id: delivery.eventId,
      type: delivery.eventType,
      createdAt: delivery.createdAt.toISOString(),
      data: delivery.payload,
    });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signWebhookPayload(delivery.endpoint.secret, timestamp, rawBody);
    const timeoutMs = this.config.get<number>('webhooks.timeoutMs') || 10_000;

    try {
      const response = await axios.post(delivery.endpoint.url, rawBody, {
        timeout: timeoutMs,
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Id': delivery.id,
          'X-Webhook-Event': delivery.eventType,
          'X-Webhook-Signature': signature,
          'User-Agent': 'standalone-auth-webhooks/1.0',
        },
        validateStatus: () => true, // we classify status ourselves below
      });

      if (response.status >= 200 && response.status < 300) {
        await this.prisma.webhookDelivery.update({
          where: { id: delivery.id },
          data: {
            status: 'SUCCEEDED',
            responseStatus: response.status,
            responseBody: truncate(safeStringify(response.data)),
            deliveredAt: new Date(),
          },
        });
        this.metrics.webhookDeliveryTotal.inc({ status: 'succeeded' });
        return;
      }

      throw new NonSuccessResponseError(response.status, truncate(safeStringify(response.data)));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const responseStatus = err instanceof NonSuccessResponseError ? err.status : undefined;
      const responseBody = err instanceof NonSuccessResponseError ? err.body : undefined;

      await this.prisma.webhookDelivery.update({
        where: { id: delivery.id },
        data: {
          status: isLastAttempt ? 'DEAD_LETTERED' : 'PENDING',
          responseStatus,
          responseBody,
          errorMessage: message,
          nextAttemptAt: isLastAttempt ? null : nextAttemptEstimate(attemptNumber),
        },
      });

      if (isLastAttempt) {
        this.logger.error(
          `Webhook delivery ${delivery.id} permanently failed after ${attemptNumber} attempts: ${message}`,
        );
        this.metrics.webhookDeliveryTotal.inc({ status: 'dead_lettered' });
        this.metrics.webhookDeadLetterTotal.inc({ tenant_id: delivery.endpoint.tenantId });
        await this.alerts.notifyDeadLetter({
          deliveryId: delivery.id,
          endpointId: delivery.endpoint.id,
          endpointUrl: delivery.endpoint.url,
          tenantId: delivery.endpoint.tenantId,
          eventType: delivery.eventType,
          attempts: attemptNumber,
          errorMessage: message,
          responseStatus,
        });
        return; // swallow — don't let BullMQ mark this "failed" forever; DB is the source of truth
      }

      this.metrics.webhookDeliveryTotal.inc({ status: 'failed' });
      throw err; // let BullMQ schedule the next retry with backoff
    }
  }
}

class NonSuccessResponseError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`Endpoint responded with HTTP ${status}`);
  }
}

function safeStringify(data: unknown): string {
  try {
    return typeof data === 'string' ? data : JSON.stringify(data);
  } catch {
    return '';
  }
}

function truncate(s: string, max = 2000): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function nextAttemptEstimate(attemptNumber: number): Date {
  const delaySeconds = Math.min(5 * 2 ** attemptNumber, 3600);
  return new Date(Date.now() + delaySeconds * 1000);
}
