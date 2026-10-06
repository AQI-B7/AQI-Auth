import { Controller, Get } from '@nestjs/common';
import { Public } from '../../common/decorators/public.decorator';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';

@Controller('health')
export class HealthController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  @Public()
  @Get()
  async check() {
    let db = 'ok';
    let redis = 'ok';

    try {
      await this.prisma.$queryRaw`SELECT 1`;
    } catch {
      db = 'error';
    }

    try {
      await this.redis.getClient().ping();
    } catch {
      redis = 'error';
    }

    const status = db === 'ok' && redis === 'ok' ? 'healthy' : 'degraded';

    return {
      status,
      timestamp: new Date().toISOString(),
      checks: { database: db, redis },
    };
  }
}
