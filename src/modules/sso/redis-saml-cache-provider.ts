import type { CacheProvider, CacheItem } from '@node-saml/node-saml';
import { RedisService } from '../../redis/redis.service';

const KEY_PREFIX = 'saml:inresponseto:';

/**
 * node-saml's default CacheProvider is a plain in-memory Map — correct
 * for a single instance, but a SAML AuthnRequest's InResponseTo value
 * (the replay-protection mechanism: the ACS callback must reference an
 * ID this service itself issued) would only be recognized by whichever
 * instance happened to generate it. Behind a load balancer, that means
 * intermittent, load-dependent SSO login failures as requests get routed
 * to a different instance than the one that started the flow.
 *
 * This backs the same 3-method interface with Redis (already a hard
 * dependency of this service), so InResponseTo state is visible to every
 * instance regardless of which one handles the callback.
 */
export class RedisSamlCacheProvider implements CacheProvider {
  constructor(
    private readonly redis: RedisService,
    private readonly ttlSeconds: number = 300, // AuthnRequest validity window
  ) {}

  async saveAsync(key: string, value: string): Promise<CacheItem | null> {
    const createdAt = Date.now();
    await this.redis.set(KEY_PREFIX + key, JSON.stringify({ value, createdAt }), this.ttlSeconds);
    return { value, createdAt };
  }

  async getAsync(key: string): Promise<string | null> {
    const raw = await this.redis.get(KEY_PREFIX + key);
    if (!raw) return null;
    try {
      return (JSON.parse(raw) as CacheItem).value;
    } catch {
      return null;
    }
  }

  async removeAsync(key: string | null): Promise<string | null> {
    if (!key) return null;
    const value = await this.getAsync(key);
    await this.redis.del(KEY_PREFIX + key);
    return value;
  }
}
