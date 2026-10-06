/**
 * Optional OpenTelemetry bootstrap. Must be `require()`d before any other
 * module (including main.ts's own imports) so auto-instrumentation can
 * patch http/express/ioredis/pg before they're first loaded — that's why
 * this is invoked via `node -r ./dist/tracing` in package.json's
 * `start:prod:traced` script rather than imported inside main.ts.
 *
 * Entirely inert (no-op, zero overhead) unless OTEL_ENABLED=true.
 */
if (process.env.OTEL_ENABLED === 'true') {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { resourceFromAttributes } = require('@opentelemetry/resources');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } = require('@opentelemetry/semantic-conventions');

  const sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: process.env.OTEL_SERVICE_NAME || 'standalone-auth-service',
      [ATTR_SERVICE_VERSION]: process.env.npm_package_version || '1.0.0',
    }),
    traceExporter: new OTLPTraceExporter({
      url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
    }),
    instrumentations: [
      getNodeAutoInstrumentations({
        // Health checks and the metrics scrape endpoint create noise,
        // not useful traces.
        '@opentelemetry/instrumentation-http': {
          ignoreIncomingRequestHook: (req: { url?: string }) =>
            req.url === '/v1/health' || req.url === '/v1/metrics',
        },
      }),
    ],
  });

  sdk.start();

  process.on('SIGTERM', () => {
    sdk.shutdown().finally(() => process.exit(0));
  });

  // eslint-disable-next-line no-console
  console.log('[tracing] OpenTelemetry initialized');
}

export {};
