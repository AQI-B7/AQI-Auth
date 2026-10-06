import { Injectable, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly client: Redis;
  private readonly logger = new Logger(RedisService.name);

  constructor(private readonly config: ConfigService) {
    const url = this.config.get<string>('redisUrl') || 'redis://localhost:6379';
    this.client = new Redis(url, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });

    this.client.on('connect', () => this.logger.log('Connected to Redis'));
    this.client.on('error', (err) => this.logger.error('Redis error', err.message));
  }

  async onModuleDestroy() {
    await this.client.quit();
  }

  getClient(): Redis {
    return this.client;
  }

  async connect(): Promise<void> {
    if (this.client.status !== 'ready') {
      await this.client.connect();
    }
  }

  // ── Blacklist helpers ──────────────────────────────────
  async blacklistToken(jti: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(`bl:${jti}`, ttlSeconds, '1');
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    const result = await this.client.get(`bl:${jti}`);
    return result === '1';
  }

  /**
   * Marks an entire session as revoked — distinct from (and stronger
   * than) blacklisting one token's jti. A refresh-token rotation can
   * mint several access tokens carrying the same `sessionId` claim over
   * a session's lifetime; blacklisting only the jti of the most recently
   * issued one would still leave earlier still-valid-by-expiry access
   * tokens usable. This makes session revocation immediate for every
   * access token ever issued under it, not just the latest one.
   */
  async revokeSession(sessionId: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(`session-revoked:${sessionId}`, ttlSeconds, '1');
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    const result = await this.client.get(`session-revoked:${sessionId}`);
    return result === '1';
  }

  // ── Rate limiting helpers ──────────────────────────────
  async incrementRateLimit(key: string, windowSeconds: number): Promise<number> {
    const multi = this.client.multi();
    multi.incr(key);
    multi.expire(key, windowSeconds);
    const results = await multi.exec();
    return (results?.[0]?.[1] as number) || 0;
  }

  // ── Generic ────────────────────────────────────────────
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.setex(key, ttlSeconds, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }
}
