# AQI-Auth

<p align="center">
  <img src="https://img.shields.io/github/license/foxiboy07/AQI-Auth" alt="License" />
  <img src="https://img.shields.io/github/last-commit/foxiboy07/AQI-Auth" alt="Last Commit" />
  <img src="https://img.shields.io/github/stars/foxiboy07/AQI-Auth" alt="GitHub stars" />
  <img src="https://img.shields.io/github/forks/foxiboy07/AQI-Auth" alt="GitHub forks" />
  <img src="https://img.shields.io/badge/Node.js-22.x-339933?logo=node.js&logoColor=white" alt="Node.js 22" />
  <img src="https://img.shields.io/badge/NestJS-11-E0234E?logo=nestjs&logoColor=white" alt="NestJS 11" />
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white" alt="TypeScript 5" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL 16" />
  <img src="https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white" alt="Redis 7" />
</p>

A production-ready, standalone authentication and identity service designed as a direct alternative to Clerk-style auth platforms. AQI-Auth is built for multi-product ecosystems, internal platforms, SaaS applications, and enterprise-grade authorization workflows.

It provides secure authentication, session lifecycle management, tenant-aware access control, rate limiting, passwordless flows, SAML/SSO, passkeys, OAuth, webhooks, and a typed SDK for modern application integrations.

## Why AQI-Auth?

- Centralized authentication for multiple products
- Works across OMS, e-commerce, admin portals, and internal apps
- Built with modern security practices by default
- Ready for both startup MVPs and enterprise security requirements
- Easy to deploy with Docker and PostgreSQL + Redis
- Includes SDK support for frontend and backend integrations

## Core Features

| Feature | Status |
| --- | --- |
| Email + password auth | ✅ |
| JWT access + refresh token rotation | ✅ |
| Refresh token reuse detection | ✅ |
| Logout and token blacklist | ✅ |
| Password reset | ✅ |
| Change password | ✅ |
| Email verification | ✅ |
| Magic link / passwordless login | ✅ |
| Multi-tenant / organizations | ✅ |
| Organization invitations | ✅ |
| RBAC with role and permission claims | ✅ |
| TOTP + backup codes | ✅ |
| Session listing and revocation | ✅ |
| API key generation and management | ✅ |
| User ban / unban | ✅ |
| Profile management | ✅ |
| Rate limiting | ✅ |
| Audit logs | ✅ |
| Health checks | ✅ |
| OAuth - Google and GitHub | ✅ |
| Webhook delivery pipeline | ✅ |
| Passkeys / WebAuthn | ✅ |
| SAML / SSO support | ✅ |
| SCIM provisioning | ✅ |
| Domain auto-join / JIT user onboarding | ✅ |
| User impersonation controls | ✅ |
| Fraud and risk heuristics | ✅ |
| JS/TS SDK | ✅ |

## Architecture Overview

AQI-Auth is structured as a dedicated authentication service that other applications trust via signed JWTs and verified identity claims.

```text
Client App / Frontend
        |
        v
AQI-Auth API
  - Auth Controller
  - User & Session Management
  - Tenants / Roles / Permissions
  - Webhooks / OAuth / SSO / SCIM
        |
        +--> PostgreSQL (users, sessions, tenants, tokens, roles)
        +--> Redis (token/session state, queues, caching)
        +--> Email / SMTP / provider callbacks
```

The service emits claims such as `sub`, `tenantId`, `permissions`, and `sessionId`, allowing downstream apps to verify identity locally without storing user passwords or session state.

## Repository Structure

```text
AQI-Auth/
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── MIGRATIONS.md
├── README.md
├── nest-cli.json
├── package.json
├── package-lock.json
├── prisma/
│   └── schema.prisma
├── scripts/
├── sdk/
│   ├── README.md
│   └── src/
├── src/
│   ├── app.module.ts
│   ├── common/
│   ├── config/
│   ├── main.ts
│   ├── modules/
│   ├── prisma/
│   ├── redis/
│   ├── tracing.ts
│   └── ...
├── tsconfig.json
├── tsconfig.build.json
└── LICENSE
```

## Tech Stack

- NestJS 11
- TypeScript 5
- Prisma 6
- PostgreSQL 16
- Redis 7
- JWT
- Argon2 password hashing
- OTPLib for TOTP
- BullMQ for webhooks
- Helmet + class-validator + throttling
- Node.js 22

## Quick Start

### 1) Clone and install

```bash
git clone https://github.com/foxiboy07/AQI-Auth.git
cd AQI-Auth
npm install
```

### 2) Configure environment

```bash
cp .env.example .env
```

Update `.env` with secure values, especially:

- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `DATABASE_URL`
- `REDIS_URL`
- `FRONTEND_URL`
- OAuth client credentials if you plan to enable Google/GitHub login

### 3) Run infrastructure

```bash
docker compose up -d
```

This starts the required PostgreSQL and Redis services.

### 4) Create database schema

```bash
npx prisma migrate dev --name init
```

### 5) Start the service

```bash
npm run start:dev
```

API base URL:

```text
http://localhost:4000/v1
```

## Main API Surface

### Authentication

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`
- `POST /v1/auth/forgot-password`
- `POST /v1/auth/reset-password`
- `POST /v1/auth/verify-email`
- `POST /v1/auth/2fa/setup|enable|disable`
- `GET /v1/auth/me`

### Users

- `GET /v1/users/me`
- `PATCH /v1/users/me`
- `POST /v1/users/me/change-password`
- `GET /v1/users`
- `POST /v1/users/:id/ban`
- `POST /v1/users/:id/unban`

### Sessions

- `GET /v1/sessions`
- `DELETE /v1/sessions/:id`
- `DELETE /v1/sessions`

### Invitations

- `POST /v1/invitations`
- `GET /v1/invitations`
- `DELETE /v1/invitations/:id`
- `POST /v1/invitations/accept`

### API Keys

- `POST /v1/api-keys`
- `GET /v1/api-keys`
- `DELETE /v1/api-keys/:id`

### Tenants

- `GET /v1/tenants/me`

### Webhooks

- `GET /v1/webhooks/event-types`
- `POST /v1/webhooks/endpoints`
- `GET /v1/webhooks/endpoints`
- `GET /v1/webhooks/endpoints/:id`
- `PATCH /v1/webhooks/endpoints/:id`
- `POST /v1/webhooks/endpoints/:id/rotate-secret`
- `DELETE /v1/webhooks/endpoints/:id`
- `POST /v1/webhooks/endpoints/:id/test`
- `GET /v1/webhooks/endpoints/:id/deliveries`

### OAuth

- `GET /v1/auth/oauth/providers`
- `GET /v1/auth/oauth/google`
- `GET /v1/auth/oauth/github`
- `GET /v1/auth/oauth/google/callback`
- `GET /v1/auth/oauth/github/callback`

### Magic Link

- `POST /v1/auth/magic-link/request`
- `POST /v1/auth/magic-link/verify`

## Security Model

AQI-Auth is designed around a trust boundary where the auth service owns identity state, while downstream apps verify claims locally.

Key characteristics:

- Passwords are hashed with `argon2`
- JWTs are short-lived and rotated safely
- Refresh token reuse is detected and invalidates sessions when suspicious
- Sessions can be listed and revoked individually or collectively
- OAuth provider tokens are encrypted before persistence
- Webhook payloads are signed with HMAC-SHA256
- Protection is included for rate limiting, abuse signals, and suspicious user activity

## SDK

The repository includes a typed SDK for JavaScript and TypeScript integrations.

See:

- `sdk/`
- `sdk/README.md`

It supports authentication workflows, session operations, webhook client usage, magic links, OAuth URL generation, and domain lookups.

## Environment and Deployment

AQI-Auth is intended to run in a containerized environment with:

- PostgreSQL for persistence
- Redis for session/rate-limit/webhook queueing
- SMTP or dev-mode token responses during local development
- Secure secrets in production environments

Production notes:

- use strong secret values
- enable HTTPS behind a reverse proxy
- set `FRONTEND_URL` to your actual frontend origin
- run Prisma migrations using `prisma migrate deploy` in CI/CD
- disable webhooks with `WEBHOOKS_ENABLED=false` if they are not required in a specific environment

## Verification

This project includes a compiler and build verification flow.

```bash
npx tsc --noEmit
npm run build
```

The repository is structured for end-to-end integration with Postgres and Redis, along with enterprise identity features such as SSO, SCIM, WebAuthn, and domain-based onboarding.

## Contribution

Contributions are welcome. If you are improving security, API behavior, or developer experience, please open a pull request with a clear description and validation steps.

## License

This project is licensed under the MIT License.

---

<p align="center">
  <strong>AQI-Auth</strong><br />
  Secure identity infrastructure for modern product teams.
</p>
