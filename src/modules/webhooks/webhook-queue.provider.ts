import { Provider, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

export const WEBHOOK_QUEUE = 'WEBHOOK_DELIVERY_QUEUE';
export const WEBHOOK_QUEUE_NAME = 'webhook-delivery';

const logger = new Logger('WebhookQueue');

/** BullMQ requires its own connection with maxRetriesPerRequest: null. */
export function createBullConnection(redisUrl: string): IORedis {
  return new IORedis(redisUrl, { maxRetriesPerRequest: null, lazyConnect: true });
}

/**
 * The queue (and its Worker, in webhook-delivery.processor.ts) are only
 * constructed when webhooks are enabled — WEBHOOKS_ENABLED=false lets an
 * operator fully disable the feature (e.g. in a Redis-less test/CI
 * environment) without touching any other module.
 */
export const webhookQueueProvider: Provider = {
  provide: WEBHOOK_QUEUE,
  inject: [ConfigService],
  useFactory: (config: ConfigService) => {
    if (!config.get<boolean>('webhooks.enabled')) {
      logger.warn('Webhooks disabled via WEBHOOKS_ENABLED=false — delivery queue not started');
      return null;
    }
    const connection = createBullConnection(config.get<string>('redisUrl')!);
    return new Queue(WEBHOOK_QUEUE_NAME, {
      connection,
      defaultJobOptions: {
        removeOnComplete: { count: 1000, age: 24 * 3600 },
        removeOnFail: { count: 5000 },
      },
    });
  },
};
