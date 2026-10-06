import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/**
 * Central Prometheus registry + typed helper methods for the counters
 * this service cares about. Kept deliberately small and hand-rolled
 * (rather than pulling in a full NestJS Prometheus interceptor package)
 * so it has zero dependency on how logging/tracing is wired, and works
 * whether or not OTEL is enabled.
 */
@Injectable()
export class MetricsService {
  readonly registry = new Registry();

  readonly httpRequestDuration = new Histogram({
    name: 'http_request_duration_seconds',
    help: 'HTTP request duration in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5],
    registers: [this.registry],
  });

  readonly httpRequestsTotal = new Counter({
    name: 'http_requests_total',
    help: 'Total HTTP requests',
    labelNames: ['method', 'route', 'status_code'],
    registers: [this.registry],
  });

  readonly loginAttemptsTotal = new Counter({
    name: 'auth_login_attempts_total',
    help: 'Login attempts by outcome',
    labelNames: ['result'], // success | invalid_credentials | locked | requires_2fa
    registers: [this.registry],
  });

  readonly magicLinkTotal = new Counter({
    name: 'auth_magic_link_total',
    help: 'Magic link requests/verifications by outcome',
    labelNames: ['action', 'result'], // action: requested|verified
    registers: [this.registry],
  });

  readonly oauthLoginTotal = new Counter({
    name: 'auth_oauth_login_total',
    help: 'OAuth logins by provider and outcome',
    labelNames: ['provider', 'result'], // result: success|failed|new_user
    registers: [this.registry],
  });

  readonly webhookDeliveryTotal = new Counter({
    name: 'webhooks_delivery_total',
    help: 'Webhook delivery attempts by final status',
    labelNames: ['status'], // succeeded|failed|dead_lettered
    registers: [this.registry],
  });

  readonly webhookDeadLetterTotal = new Counter({
    name: 'webhooks_dead_letter_total',
    help: 'Webhook deliveries that exhausted all retry attempts',
    labelNames: ['tenant_id'],
    registers: [this.registry],
  });

  readonly accountLockoutsTotal = new Counter({
    name: 'auth_account_lockouts_total',
    help: 'Account lockouts triggered by repeated failed credential checks',
    labelNames: ['scope'], // login|magic_link
    registers: [this.registry],
  });

  readonly riskAssessmentTotal = new Counter({
    name: 'auth_risk_assessment_total',
    help: 'Signup risk assessments by resulting action',
    labelNames: ['action'], // allow|challenge|block
    registers: [this.registry],
  });

  constructor() {
    collectDefaultMetrics({ register: this.registry, prefix: 'authsvc_' });
  }

  async metricsText(): Promise<string> {
    return this.registry.metrics();
  }
}
