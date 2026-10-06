export default () => ({
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '4000', 10),
  appUrl: process.env.APP_URL || 'http://localhost:4000',

  databaseUrl: process.env.DATABASE_URL,

  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  },

  corsOrigins: process.env.CORS_ORIGINS || 'http://localhost:3000',

  cookieSecure: process.env.COOKIE_SECURE === 'true',

  email: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.EMAIL_FROM || 'Auth Service <noreply@example.com>',
    // Feature is "optional": enabled automatically once SMTP host is configured.
    enabled: Boolean(process.env.SMTP_HOST),
  },

  frontendUrl: process.env.FRONTEND_URL || process.env.APP_URL || 'http://localhost:4000',

  // ── OAuth (Google / GitHub) — each provider is entirely optional and
  // only activates when its client id + secret are both present. ──
  oauth: {
    google: {
      enabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl:
        process.env.GOOGLE_CALLBACK_URL ||
        `${process.env.APP_URL || 'http://localhost:4000'}/v1/auth/oauth/google/callback`,
    },
    github: {
      enabled: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackUrl:
        process.env.GITHUB_CALLBACK_URL ||
        `${process.env.APP_URL || 'http://localhost:4000'}/v1/auth/oauth/github/callback`,
    },
    // AES-256-GCM key (32 bytes, base64 or hex) used to encrypt OAuth
    // provider tokens at rest. Falls back to deriving from JWT secret in
    // non-production so the feature still works out of the box in dev.
    tokenEncryptionKey: process.env.OAUTH_TOKEN_ENCRYPTION_KEY,
  },

  // ── Outgoing webhooks — optional; the delivery worker only starts
  // processing jobs once REDIS_URL is reachable, which is already a hard
  // dependency of the service, so this is "enabled" whenever the tenant
  // creates at least one endpoint. WEBHOOKS_ENABLED lets ops kill-switch it. ──
  webhooks: {
    enabled: process.env.WEBHOOKS_ENABLED !== 'false',
    maxAttempts: parseInt(process.env.WEBHOOK_MAX_ATTEMPTS || '8', 10),
    timeoutMs: parseInt(process.env.WEBHOOK_TIMEOUT_MS || '10000', 10),
    signatureToleranceSeconds: parseInt(
      process.env.WEBHOOK_SIGNATURE_TOLERANCE_SECONDS || '300',
      10,
    ),
  },

  // ── Magic link (passwordless) — always available; enabling SMTP just
  // means the link is actually emailed instead of returned in the API
  // response for local testing. ──
  magicLink: {
    ttlMinutes: parseInt(process.env.MAGIC_LINK_TTL_MINUTES || '15', 10),
  },

  security: {
    // Progressive lockout kicks in past this many failed attempts;
    // see LockoutService for the full escalation ladder.
    lockoutMaxAttempts: parseInt(process.env.LOCKOUT_MAX_ATTEMPTS || '5', 10),
  },

  logging: {
    level: process.env.LOG_LEVEL || 'info',
  },

  metrics: {
    // Set METRICS_TOKEN to require `Authorization: Bearer <token>` on
    // GET /v1/metrics. Leave unset only when the scrape path is already
    // restricted at the network layer.
    token: process.env.METRICS_TOKEN,
  },

  // ── Branding / email templates ──
  branding: {
    productName: process.env.BRAND_NAME || 'Auth Service',
    logoUrl: process.env.BRAND_LOGO_URL,
    primaryColor: process.env.BRAND_PRIMARY_COLOR || '#4f46e5',
    supportEmail: process.env.BRAND_SUPPORT_EMAIL,
    defaultLocale: process.env.DEFAULT_LOCALE || 'en',
  },

  // ── Ops alerting for webhook dead-letters ──
  alerts: {
    // Any Slack-compatible "incoming webhook" URL (Slack, Discord w/
    // adapter, Mattermost, or a generic collector) that dead-lettered
    // webhook deliveries get POSTed to. Optional.
    opsWebhookUrl: process.env.OPS_ALERT_WEBHOOK_URL,
    enabled: process.env.WEBHOOK_ALERTS_ENABLED !== 'false',
  },

  // ── Secrets management (optional) ──
  secrets: {
    // 'env' (default) reads secrets from process.env / .env exactly as
    // before. 'vault' and 'aws' fetch and merge additional values into
    // process.env at boot, before ConfigModule reads anything.
    provider: process.env.SECRETS_PROVIDER || 'env',
    vault: {
      addr: process.env.VAULT_ADDR,
      token: process.env.VAULT_TOKEN,
      path: process.env.VAULT_SECRET_PATH, // e.g. 'secret/data/auth-service'
    },
    aws: {
      region: process.env.AWS_REGION || 'us-east-1',
      secretId: process.env.AWS_SECRET_ID, // e.g. 'auth-service/production'
    },
  },
  // ── Passkeys / WebAuthn ──
  webauthn: {
    rpName: process.env.WEBAUTHN_RP_NAME || process.env.BRAND_NAME || 'Auth Service',
    rpId: process.env.WEBAUTHN_RP_ID || 'localhost',
    // Comma-separated list of allowed origins (must match exactly,
    // including scheme/port) that a passkey ceremony can be completed
    // from — normally just your frontend's origin.
    origins: (process.env.WEBAUTHN_ORIGINS || 'http://localhost:3000').split(','),
    challengeTtlSeconds: parseInt(process.env.WEBAUTHN_CHALLENGE_TTL_SECONDS || '300', 10),
  },
  // ── SSO (SAML) ──
  sso: {
    // The entity ID this service presents to IdPs as itself (the
    // Service Provider). Each tenant's IdP admin configures their side
    // to trust this value.
    spEntityId: process.env.SSO_SP_ENTITY_ID || `${process.env.APP_URL || 'http://localhost:4000'}/v1/sso/metadata`,
    appUrl: process.env.APP_URL || 'http://localhost:4000',
  },

  // ── SCIM 2.0 provisioning (RFC 7644) ──
  scim: {
    enabled: process.env.SCIM_ENABLED !== 'false',
  },

  // ── User impersonation (support tooling) ──
  impersonation: {
    ttlMinutes: parseInt(process.env.IMPERSONATION_TTL_MINUTES || '15', 10),
  },

  // ── Bot / fraud risk signals ──
  // 'off'    — no assessment at all.
  // 'log'    — assess and record the signals/score on the AuthEvent, no
  //            effect on the request. Safe default: visible in your
  //            audit trail immediately without risking false-positive
  //            lockouts on day one.
  // 'enforce'— additionally reject registrations at/above blockThreshold
  //            and flag (`requiresAdditionalVerification: true` in the
  //            response) those at/above challengeThreshold, so a client
  //            can layer its own step-up (e.g. CAPTCHA) on top — this
  //            service does not implement CAPTCHA itself.
  risk: {
    mode: process.env.RISK_MODE || 'log',
    challengeThreshold: parseInt(process.env.RISK_CHALLENGE_THRESHOLD || '40', 10),
    blockThreshold: parseInt(process.env.RISK_BLOCK_THRESHOLD || '70', 10),
    // Registrations from the same IP within one hour before it's treated
    // as suspicious velocity (real signal, not a guess: bulk/bot signups
    // overwhelmingly cluster from one IP in a short window).
    newAccountVelocityThreshold: parseInt(process.env.RISK_NEW_ACCOUNT_VELOCITY_THRESHOLD || '5', 10),
    // Optional real IP-reputation lookup. Unset = that signal simply
    // contributes nothing, rather than being faked.
    abuseIpDb: {
      apiKey: process.env.ABUSEIPDB_API_KEY,
      cacheTtlSeconds: parseInt(process.env.ABUSEIPDB_CACHE_TTL_SECONDS || '3600', 10),
    },
  },
});
