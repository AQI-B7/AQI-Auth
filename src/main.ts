import './tracing'; // no-op unless OTEL_ENABLED=true; must load first for auto-instrumentation
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger as PinoLogger } from 'nestjs-pino';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { loadExternalSecrets } from './modules/secrets/secrets.module';

async function bootstrap() {
  // Must happen before NestFactory.create(): ConfigModule reads
  // process.env synchronously at module-graph construction time, so any
  // Vault/AWS-sourced values have to already be in process.env by then.
  await loadExternalSecrets();

  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(PinoLogger));

  const config = app.get(ConfigService);
  const port = config.get<number>('PORT', 4000);
  const corsOrigins = config.get<string>('CORS_ORIGINS', 'http://localhost:3000').split(',');

  app.use(helmet());
  app.use(cookieParser());

  app.enableCors({
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-Id', 'Retry-After'],
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  app.useGlobalFilters(new AllExceptionsFilter());

  app.setGlobalPrefix('v1', {
    exclude: ['ui', 'ui/(.*)'],
  });

  await app.listen(port);
  app.get(PinoLogger).log(`Auth Service running on http://localhost:${port}/v1`, 'Bootstrap');
}

bootstrap();
