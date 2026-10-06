# @standalone-auth/sdk

Typed TypeScript/JavaScript client for the Standalone Auth Service HTTP API. Isomorphic — works in Node (18+, or any runtime with `fetch`) and browsers. No framework dependency: pair it with React/Vue/vanilla JS/React Native yourself.

## Scope

Covers password/magic-link/OAuth-URL/2FA authentication, session management, and webhook administration — the surface an end-user-facing app actually needs. It does **not** wrap the admin-only endpoints (SSO connection management, SCIM tokens, domain verification, impersonation) — those are typically called from a backend or internal admin tool, not a public client bundle, and are one line away via the same typed `client.request()` escalation hatch every method above is built on.

## Install

```bash
npm install @standalone-auth/sdk
```

## Usage

```ts
import { AuthServiceClient } from '@standalone-auth/sdk';

const client = new AuthServiceClient({
  baseUrl: 'https://auth.yourapp.com/v1',
  // The SDK never touches storage itself — wire persistence yourself:
  initialTokens: JSON.parse(localStorage.getItem('auth_tokens') || 'null'),
  onTokensChanged: (tokens) => {
    if (tokens) localStorage.setItem('auth_tokens', JSON.stringify(tokens));
    else localStorage.removeItem('auth_tokens');
  },
});

const result = await client.login({ email: 'jane@acme.com', password: '...' });
if ('requires2FA' in result) {
  await client.login({ email: 'jane@acme.com', password: '...', totpCode: '123456' });
}

// Expired access tokens are refreshed automatically and transparently —
// every authenticated call below retries once after a silent refresh.
const sessions = await client.sessions.list();
await client.webhooks.create({ url: 'https://myapp.com/hooks', events: ['user.login'] });
```

### OAuth

```ts
// Redirect the browser here; the callback lands on your frontend with
// tokens in the URL fragment (#access_token=...&refresh_token=...).
window.location.href = client.oauth.getLoginUrl('google');

// On your /oauth/callback page:
const params = new URLSearchParams(window.location.hash.slice(1));
client.setTokens({
  accessToken: params.get('access_token')!,
  refreshToken: params.get('refresh_token')!,
  tokenType: 'Bearer',
  expiresIn: Number(params.get('expires_in')),
});
```

### Error handling

```ts
import { AuthServiceApiError } from '@standalone-auth/sdk';

try {
  await client.login({ email, password });
} catch (err) {
  if (err instanceof AuthServiceApiError) {
    if (err.statusCode === 423) {
      // account locked — err.retryAfterSeconds tells you how long
    }
  }
}
```

## Build

```bash
npm run build   # emits dist/ (CommonJS + type declarations)
```
