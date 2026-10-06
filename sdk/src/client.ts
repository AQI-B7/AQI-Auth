import { AuthServiceApiError } from './errors';
import type {
  AuthResult,
  RequiresTwoFactor,
  RegisterInput,
  LoginInput,
  TokenPair,
  UserSummary,
  WebhookEndpoint,
  WebhookDelivery,
  SessionSummary,
  OAuthProviders,
  DomainLookupResult,
  ApiErrorShape,
} from './types';

export interface AuthServiceClientOptions {
  /** e.g. "https://auth.example.com/v1" — include the /v1 prefix. */
  baseUrl: string;
  /** Override fetch, e.g. for Node <18 (node-fetch) or test mocking. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Called whenever the client's tokens change (login, refresh, logout) — wire this to your
   *  own storage (localStorage, secure cookie, keychain, etc). The SDK itself never persists
   *  anything, so it works identically in a browser tab, a React Native app, or a server process. */
  onTokensChanged?: (tokens: TokenPair | null) => void;
  /** Seed the client with previously-stored tokens at construction time. */
  initialTokens?: TokenPair | null;
}

/**
 * Typed client for the Standalone Auth Service HTTP API. Covers
 * password/magic-link/OAuth-URL/passkey authentication, session
 * management, and webhook administration — the endpoints documented in
 * the service's README. It intentionally does NOT wrap every admin
 * endpoint (SSO connection management, SCIM, domain verification,
 * impersonation): those are typically called from a backend/admin
 * surface rather than an end-user-facing app, and are straightforward
 * to call directly with `client.request()` if you need them from here too.
 */
export class AuthServiceClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly onTokensChanged?: (tokens: TokenPair | null) => void;
  private tokens: TokenPair | null;
  private refreshInFlight: Promise<TokenPair> | null = null;

  constructor(options: AuthServiceClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error(
        'No fetch implementation available. Pass { fetchImpl } explicitly on a runtime without global fetch (e.g. Node < 18).',
      );
    }
    this.onTokensChanged = options.onTokensChanged;
    this.tokens = options.initialTokens ?? null;
  }

  // ── Token state ──

  getTokens(): TokenPair | null {
    return this.tokens;
  }

  setTokens(tokens: TokenPair | null): void {
    this.tokens = tokens;
    this.onTokensChanged?.(tokens);
  }

  isAuthenticated(): boolean {
    return this.tokens !== null;
  }

  // ── Auth ──

  async register(input: RegisterInput): Promise<AuthResult> {
    const result = await this.request<AuthResult>('POST', '/auth/register', { body: input, auth: false });
    this.setTokens(toTokenPair(result));
    return result;
  }

  async login(input: LoginInput): Promise<AuthResult | RequiresTwoFactor> {
    const result = await this.request<AuthResult | RequiresTwoFactor>('POST', '/auth/login', {
      body: input,
      auth: false,
    });
    if (!('requires2FA' in result)) {
      this.setTokens(toTokenPair(result));
    }
    return result;
  }

  /** Ends the current session server-side and clears local token state
   *  regardless of whether the request succeeds (a network failure
   *  shouldn't leave the SDK believing it's still logged in). */
  async logout(): Promise<void> {
    try {
      await this.request('POST', '/auth/logout', { auth: true });
    } finally {
      this.setTokens(null);
    }
  }

  async forgotPassword(email: string): Promise<{ success: boolean; message: string }> {
    return this.request('POST', '/auth/forgot-password', { body: { email }, auth: false });
  }

  async resetPassword(token: string, password: string): Promise<{ success: boolean }> {
    return this.request('POST', '/auth/reset-password', { body: { token, password }, auth: false });
  }

  async verifyEmail(token: string): Promise<{ success: boolean }> {
    return this.request('POST', '/auth/verify-email', { body: { token }, auth: false });
  }

  async me(): Promise<{ user: { userId: string; tenantId: string; email: string; permissions: string[] } }> {
    return this.request('GET', '/auth/me', { auth: true });
  }

  // ── Magic link (passwordless) ──

  magicLink = {
    request: (email: string, tenantSlug?: string): Promise<{ success: boolean; message: string; magicLinkToken?: string }> =>
      this.request('POST', '/auth/magic-link/request', { body: { email, tenantSlug }, auth: false }),

    verify: async (token: string): Promise<AuthResult> => {
      const result = await this.request<AuthResult>('POST', '/auth/magic-link/verify', {
        body: { token },
        auth: false,
      });
      this.setTokens(toTokenPair(result));
      return result;
    },
  };

  // ── OAuth (Google/GitHub) — this SDK builds the redirect URL; the
  // actual redirect and callback round-trip happens in the browser, not
  // through this client (the callback lands the browser on your
  // frontend with tokens in the URL fragment — call setTokens() with
  // those once you've parsed them out). ──

  oauth = {
    getProviders: (): Promise<OAuthProviders> => this.request('GET', '/auth/oauth/providers', { auth: false }),

    getLoginUrl: (provider: 'google' | 'github', tenantSlug?: string): string => {
      const qs = tenantSlug ? `?tenantSlug=${encodeURIComponent(tenantSlug)}` : '';
      return `${this.baseUrl}/auth/oauth/${provider}${qs}`;
    },
  };

  // ── Two-factor authentication ──

  twoFactor = {
    setup: (): Promise<{ secret: string; qrCode: string }> => this.request('POST', '/auth/2fa/setup', { auth: true }),
    enable: (totpCode: string): Promise<{ success: boolean; backupCodes: string[] }> =>
      this.request('POST', '/auth/2fa/enable', { body: { totpCode }, auth: true }),
    disable: (totpCode: string): Promise<{ success: boolean }> =>
      this.request('POST', '/auth/2fa/disable', { body: { totpCode }, auth: true }),
  };

  // ── Sessions ──

  sessions = {
    list: (): Promise<SessionSummary[]> => this.request('GET', '/sessions', { auth: true }),
    revoke: (sessionId: string): Promise<{ success: boolean }> =>
      this.request('DELETE', `/sessions/${sessionId}`, { auth: true }),
    revokeAll: (): Promise<{ success: boolean; revoked: number }> => this.request('DELETE', '/sessions', { auth: true }),
  };

  // ── Webhooks ──

  webhooks = {
    listEventTypes: (): Promise<{ eventTypes: string[] }> => this.request('GET', '/webhooks/event-types', { auth: true }),
    create: (input: { url: string; events: string[]; description?: string }): Promise<WebhookEndpoint> =>
      this.request('POST', '/webhooks/endpoints', { body: input, auth: true }),
    list: (): Promise<WebhookEndpoint[]> => this.request('GET', '/webhooks/endpoints', { auth: true }),
    get: (id: string): Promise<WebhookEndpoint> => this.request('GET', `/webhooks/endpoints/${id}`, { auth: true }),
    update: (
      id: string,
      input: Partial<{ url: string; events: string[]; active: boolean; description: string }>,
    ): Promise<WebhookEndpoint> => this.request('PATCH', `/webhooks/endpoints/${id}`, { body: input, auth: true }),
    rotateSecret: (id: string): Promise<WebhookEndpoint> =>
      this.request('POST', `/webhooks/endpoints/${id}/rotate-secret`, { auth: true }),
    remove: (id: string): Promise<{ success: boolean }> =>
      this.request('DELETE', `/webhooks/endpoints/${id}`, { auth: true }),
    sendTest: (id: string): Promise<{ id: string }> => this.request('POST', `/webhooks/endpoints/${id}/test`, { auth: true }),
    deliveries: (id: string, limit?: number): Promise<WebhookDelivery[]> =>
      this.request('GET', `/webhooks/endpoints/${id}/deliveries${limit ? `?limit=${limit}` : ''}`, { auth: true }),
    resend: (id: string, deliveryId: string): Promise<{ id: string }> =>
      this.request('POST', `/webhooks/endpoints/${id}/deliveries/${deliveryId}/resend`, { auth: true }),
  };

  // ── Domain auto-join lookup (for a signup UI to show "join <Org>?") ──

  domains = {
    lookup: (email: string): Promise<DomainLookupResult> =>
      this.request('GET', `/domains/lookup?email=${encodeURIComponent(email)}`, { auth: false }),
  };

  // ── Low-level escalation hatch: call any endpoint this wrapper
  // doesn't have a typed method for yet (SSO connections, SCIM tokens,
  // impersonation, domain verification, ...), with the same
  // auth/refresh/error handling as every typed method above. ──

  async request<T>(
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    options: { body?: unknown; auth?: boolean } = {},
  ): Promise<T> {
    return this.doRequest<T>(method, path, options, /* isRetry */ false);
  }

  private async doRequest<T>(
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    options: { body?: unknown; auth?: boolean },
    isRetry: boolean,
  ): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (options.auth !== false && this.tokens) {
      headers['Authorization'] = `Bearer ${this.tokens.accessToken}`;
    }

    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });

    if (response.status === 401 && options.auth !== false && this.tokens && !isRetry) {
      // Single-flight refresh: concurrent 401s from several in-flight
      // requests share one refresh call rather than each racing to
      // refresh (and potentially invalidating each other's new token
      // via refresh-token rotation).
      try {
        await this.refreshTokens();
      } catch {
        this.setTokens(null);
        throw await this.toApiError(response);
      }
      return this.doRequest<T>(method, path, options, true);
    }

    if (!response.ok) {
      throw await this.toApiError(response);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  }

  private async refreshTokens(): Promise<TokenPair> {
    if (this.refreshInFlight) return this.refreshInFlight;

    this.refreshInFlight = (async () => {
      if (!this.tokens) throw new Error('No refresh token available');
      const pair = await this.request<TokenPair>('POST', '/auth/refresh', {
        body: { refreshToken: this.tokens.refreshToken },
        auth: false,
      });
      this.setTokens(pair);
      return pair;
    })();

    try {
      return await this.refreshInFlight;
    } finally {
      this.refreshInFlight = null;
    }
  }

  private async toApiError(response: Response): Promise<AuthServiceApiError> {
    try {
      const body = (await response.json()) as ApiErrorShape;
      return new AuthServiceApiError(body);
    } catch {
      return new AuthServiceApiError({
        success: false,
        statusCode: response.status,
        code: 'UNKNOWN_ERROR',
        message: response.statusText || 'Request failed',
        path: response.url,
        timestamp: new Date().toISOString(),
      });
    }
  }
}

function toTokenPair(result: AuthResult): TokenPair {
  return {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    tokenType: result.tokenType,
    expiresIn: result.expiresIn,
  };
}
