import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ServeStaticModule } from '@nestjs/serve-static';
import { LoggerModule } from 'nestjs-pino';
import { randomUUID } from 'crypto';
import { join } from 'path';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { AuthModule } from './modules/auth/auth.module';
import { WebAuthnModule } from './modules/auth/webauthn/webauthn.module';
import { UsersModule } from './modules/users/users.module';
import { TenantsModule } from './modules/tenants/tenants.module';
import { RolesModule } from './modules/roles/roles.module';
import { SessionsModule } from './modules/sessions/sessions.module';
import { ApiKeysModule } from './modules/api-keys/api-keys.module';
import { InvitationsModule } from './modules/invitations/invitations.module';
import { WebhooksModule } from './modules/webhooks/webhooks.module';
import { SsoModule } from './modules/sso/sso.module';
import { ScimModule } from './modules/scim/scim.module';
import { DomainsModule } from './modules/domains/domains.module';
import { ImpersonationModule } from './modules/impersonation/impersonation.module';
import { RiskModule } from './modules/risk/risk.module';
import { HealthModule } from './modules/health/health.module';
import { MetricsModule } from './modules/metrics/metrics.module';
import { SecretsModule } from './modules/secrets/secrets.module';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';
import configuration from './config/configuration';

@Module({
  imports: [
    // Secrets are resolved into process.env before ConfigModule reads
    // it, so this import must come first — see SecretsModule for why
    // this is safe to do synchronously at module-graph build time.
    SecretsModule,
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      envFilePath: ['.env'],
    }),
    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        pinoHttp: {
          level: config.get<string>('logging.level') || 'info',
          genReqId: (req: any, res: any) => {
            const existing = req.headers['x-request-id'];
            const id = (Array.isArray(existing) ? existing[0] : existing) || randomUUID();
            res.setHeader('X-Request-Id', id);
            return id;
          },
          // Structured JSON in production (for log aggregators); pretty
          // human-readable output locally. Both go to stdout either way.
          transport:
            config.get<string>('nodeEnv') === 'production'
              ? undefined
              : { target: 'pino-pretty', options: { colorize: true, singleLine: true } },
          redact: {
            paths: [
              'req.headers.authorization',
              'req.headers.cookie',
              'req.body.password',
              'req.body.token',
              'req.body.refreshToken',
              'req.body.accessToken',
              'res.headers["set-cookie"]',
            ],
            censor: '[REDACTED]',
          },
          customLogLevel: (req: any, res: any, err: unknown) => {
            if (res.statusCode >= 500 || err) return 'error';
            if (res.statusCode >= 400) return 'warn';
            return 'info';
          },
          autoLogging: {
            ignore: (req: any) => req.url === '/v1/health' || req.url === '/v1/metrics',
          },
        },
      }),
    }),
    // Lightweight in-process pub/sub so feature modules (webhooks) can
    // react to domain events (user.login, invitation.created, ...)
    // without the emitting services depending on them directly.
    EventEmitterModule.forRoot(),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
      serveRoot: '/ui',
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60_000,
        limit: 30,
      },
    ]),
    MetricsModule,
    PrismaModule,
    RedisModule,
    AuthModule,
    WebAuthnModule,
    UsersModule,
    TenantsModule,
    RolesModule,
    SessionsModule,
    ApiKeysModule,
    InvitationsModule,
    WebhooksModule,
    SsoModule,
    ScimModule,
    DomainsModule,
    ImpersonationModule,
    RiskModule,
    HealthModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CsrfMiddleware).forRoutes('*');
  }
}
