import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../redis/redis.service';

export interface LockoutStatus {
  locked: boolean;
  retryAfterSeconds?: number;
  attemptsRemaining?: number;
}

/**
 * Progressive-delay account lockout, tracked in Redis (not the DB) so it
 * stays cheap under credential-stuffing load and never blocks on a write
 * to the primary database.
 *
 * Keyed by `${scope}:${identifier}` where identifier is normally
 * `email|ip` — locking on the pair (rather than email alone) stops one
 * abusive IP from locking out a legitimate user sitting behind a
 * different IP, while still stopping distributed attempts against a
 * single account from a botnet by *also* tracking email-only.
 *
 * Escalating thresholds:
 *   5 failures  → 60s lock
 *   10 failures → 15 min lock
 *   15 failures → 1 hour lock
 *   20+ failures→ 24 hour lock (forces a password reset / support contact)
 */
@Injectable()
export class LockoutService {
  private readonly maxAttempts: number;

  constructor(
    private readonly redis: RedisService,
    private readonly config: ConfigService,
  ) {
    this.maxAttempts = this.config.get<number>('security.lockoutMaxAttempts') || 5;
  }

  private static readonly THRESHOLDS: Array<{ attempts: number; lockSeconds: number }> = [
    { attempts: 20, lockSeconds: 24 * 3600 },
    { attempts: 15, lockSeconds: 3600 },
    { attempts: 10, lockSeconds: 15 * 60 },
    { attempts: 5, lockSeconds: 60 },
  ];

  private attemptsKey(scope: string, identifier: string) {
    return `lockout:attempts:${scope}:${identifier}`;
  }

  private lockKey(scope: string, identifier: string) {
    return `lockout:locked:${scope}:${identifier}`;
  }

  async check(scope: string, identifier: string): Promise<LockoutStatus> {
    const lockedUntilRaw = await this.redis.get(this.lockKey(scope, identifier));
    if (lockedUntilRaw) {
      const retryAfterSeconds = Math.max(
        0,
        Math.ceil((Number(lockedUntilRaw) - Date.now()) / 1000),
      );
      if (retryAfterSeconds > 0) {
        return { locked: true, retryAfterSeconds };
      }
    }
    const attemptsRaw = await this.redis.get(this.attemptsKey(scope, identifier));
    const attempts = attemptsRaw ? parseInt(attemptsRaw, 10) : 0;
    return { locked: false, attemptsRemaining: Math.max(0, this.maxAttempts - attempts) };
  }

  /** Call on every failed credential check. Returns the resulting status. */
  async recordFailure(scope: string, identifier: string): Promise<LockoutStatus> {
    const attempts = await this.redis.incrementRateLimit(
      this.attemptsKey(scope, identifier),
      24 * 3600, // attempt counter itself resets after 24h of no activity
    );

    const threshold = LockoutService.THRESHOLDS.find((t) => attempts >= t.attempts);
    if (threshold) {
      const lockedUntil = Date.now() + threshold.lockSeconds * 1000;
      await this.redis.set(this.lockKey(scope, identifier), String(lockedUntil), threshold.lockSeconds);
      return { locked: true, retryAfterSeconds: threshold.lockSeconds };
    }

    return { locked: false, attemptsRemaining: Math.max(0, this.maxAttempts - attempts) };
  }

  /** Call on every successful credential check to clear the counter. */
  async recordSuccess(scope: string, identifier: string): Promise<void> {
    await Promise.all([
      this.redis.del(this.attemptsKey(scope, identifier)),
      this.redis.del(this.lockKey(scope, identifier)),
    ]);
  }
}
