import { Controller, Get, Header, UnauthorizedException, Headers } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Public } from '../../common/decorators/public.decorator';
import { MetricsService } from './metrics.service';

@Controller('metrics')
export class MetricsController {
  constructor(
    private readonly metrics: MetricsService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Public route (no JWT required — a Prometheus scraper isn't a logged
   * in tenant user) but gated behind a static bearer token when
   * METRICS_TOKEN is set, since this endpoint reveals operational
   * volume/shape. Leave METRICS_TOKEN unset only behind a network
   * boundary the scraper already controls (e.g. a private VPC).
   */
  @Public()
  @Get()
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  async index(@Headers('authorization') authHeader?: string) {
    const token = this.config.get<string>('metrics.token');
    if (token) {
      const provided = authHeader?.replace(/^Bearer\s+/i, '');
      if (provided !== token) {
        throw new UnauthorizedException('Invalid metrics token');
      }
    }
    return this.metrics.metricsText();
  }
}
