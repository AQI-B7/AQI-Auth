import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { isbot } from 'isbot';
// CommonJS package with no bundled .d.ts — see comment below.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const disposableEmailDomains = require('disposable-email-domains') as string[];
const disposableSet = new Set(disposableEmailDomains);

import { RedisService } from '../../redis/redis.service';
import { MetricsService } from '../metrics/metrics.service';

export type RiskAction = 'allow' | 'challenge' | 'block';

export interface RiskAssessment {
  score: number; // 0-100
  action: RiskAction;
  signals: {
    disposableEmail: boolean;
    botUserAgent: boolean;
    highIpVelocity: boolean;
    abuseIpDbScore?: number; // 0-100 confidence, only present if configured
  };
}

/**
 * Real heuristic signals, each independently verifiable and each
 * contributing an honest, explainable amount to the score — not a
 * black-box ML classifier this service doesn't have training data or a
 * team to maintain. Every signal either:
 *   (a) checks something objectively true right now (is this email
 *       domain on a maintained disposable-email list; does this User-Agent
 *       match a known bot/scraper signature), or
 *   (b) measures something this service can itself observe (how many
 *       accounts have been created from this IP in the last hour), or
 *   (c) is an explicit, optional integration with a real third-party
 *       IP-reputation service (AbuseIPDB) that contributes nothing at
 *       all unless an API key is actually configured.
 *
 * There is no signal here that pretends to be more than it is.
 */
@Injectable()
export class RiskService {
  private readonly logger = new Logger(RiskService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly redis: RedisService,
    private readonly metrics: MetricsService,
  ) {}

  get mode(): 'off' | 'log' | 'enforce' {
    return (this.config.get<string>('risk.mode') as any) || 'log';
  }

  async assessSignup(email: string, ip?: string, userAgent?: string): Promise<RiskAssessment | null> {
    if (this.mode === 'off') return null;

    const domain = email.split('@')[1]?.toLowerCase();
    const disposableEmail = domain ? disposableSet.has(domain) : false;
    const botUserAgent = userAgent ? isbot(userAgent) : false;
    const highIpVelocity = ip ? await this.checkNewAccountVelocity(ip) : false;
    const abuseIpDbScore = ip ? await this.checkAbuseIpDb(ip) : undefined;

    let score = 0;
    if (disposableEmail) score += 40;
    if (botUserAgent) score += 30;
    if (highIpVelocity) score += 30;
    if (abuseIpDbScore !== undefined) score = Math.min(100, score + abuseIpDbScore * 0.5);

    const challengeThreshold = this.config.get<number>('risk.challengeThreshold') || 40;
    const blockThreshold = this.config.get<number>('risk.blockThreshold') || 70;

    const action: RiskAction = score >= blockThreshold ? 'block' : score >= challengeThreshold ? 'challenge' : 'allow';

    const assessment: RiskAssessment = {
      score: Math.round(score),
      action,
      signals: { disposableEmail, botUserAgent, highIpVelocity, abuseIpDbScore },
    };

    if (action !== 'allow') {
      this.logger.warn(
        `Signup risk ${action} (score=${assessment.score}) for ${email} from ${ip || 'unknown IP'}: ${JSON.stringify(assessment.signals)}`,
      );
    }
    this.metrics.riskAssessmentTotal.inc({ action });

    return assessment;
  }

  /** Records a successful registration's IP for future velocity checks.
   *  Call this AFTER the account is actually created, not before — a
   *  blocked/rejected attempt shouldn't count toward the window. */
  async recordSignup(ip?: string): Promise<void> {
    if (!ip) return;
    await this.redis.incrementRateLimit(`risk:signup-velocity:${ip}`, 3600);
  }

  private async checkNewAccountVelocity(ip: string): Promise<boolean> {
    const threshold = this.config.get<number>('risk.newAccountVelocityThreshold') || 5;
    const current = await this.redis.get(`risk:signup-velocity:${ip}`);
    return current ? parseInt(current, 10) >= threshold : false;
  }

  /**
   * Optional real integration: https://www.abuseipdb.com/ community IP
   * reputation database. Returns undefined (contributes nothing) unless
   * ABUSEIPDB_API_KEY is set — never a fabricated placeholder score.
   * Cached in Redis since AbuseIPDB's free tier has a strict daily quota
   * and the same abusive IPs hit us repeatedly.
   */
  private async checkAbuseIpDb(ip: string): Promise<number | undefined> {
    const apiKey = this.config.get<string>('risk.abuseIpDb.apiKey');
    if (!apiKey) return undefined;

    const cacheKey = `risk:abuseipdb:${ip}`;
    const cached = await this.redis.get(cacheKey);
    if (cached !== null) return parseInt(cached, 10);

    try {
      const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: { ipAddress: ip, maxAgeInDays: 30 },
        headers: { Key: apiKey, Accept: 'application/json' },
        timeout: 3000,
      });
      const confidenceScore: number = response.data?.data?.abuseConfidenceScore ?? 0;
      const ttl = this.config.get<number>('risk.abuseIpDb.cacheTtlSeconds') || 3600;
      await this.redis.set(cacheKey, String(confidenceScore), ttl);
      return confidenceScore;
    } catch (err) {
      this.logger.warn(`AbuseIPDB lookup failed for ${ip}: ${(err as Error).message}`);
      return undefined; // a failed lookup contributes nothing — never guessed
    }
  }
}
