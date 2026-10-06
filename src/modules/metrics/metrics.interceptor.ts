import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { MetricsService } from './metrics.service';

@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly metrics: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== 'http') return next.handle();

    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();
    const start = process.hrtime.bigint();
    // Route template (e.g. "/v1/webhooks/endpoints/:id") keeps cardinality
    // bounded, unlike req.url which contains raw ids.
    const route = req.route?.path ? `${req.baseUrl || ''}${req.route.path}` : req.path;

    const record = () => {
      const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9;
      const labels = { method: req.method, route, status_code: String(res.statusCode) };
      this.metrics.httpRequestDuration.observe(labels, durationSeconds);
      this.metrics.httpRequestsTotal.inc(labels);
    };

    return next.handle().pipe(tap({ next: record, error: record }));
  }
}
