import { Body, Controller, Delete, Get, Param, Patch, Post, Query, UseGuards } from '@nestjs/common';
import { DomainsService } from './domains.service';
import { AddTenantDomainDto, UpdateTenantDomainDto } from './dto/domains.dto';
import { Public } from '../../common/decorators/public.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../../common/decorators/current-user.decorator';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';
import { IsEmail } from 'class-validator';

class DomainLookupQueryDto {
  @IsEmail()
  email!: string;
}

@Controller('domains')
export class DomainsController {
  constructor(private readonly domains: DomainsService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('domains:write', '*')
  add(@CurrentUser() user: AuthUser, @Body() dto: AddTenantDomainDto) {
    return this.domains.add(user.tenantId, dto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('domains:read', '*')
  list(@CurrentUser() user: AuthUser) {
    return this.domains.list(user.tenantId);
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('domains:write', '*')
  update(@CurrentUser() user: AuthUser, @Param('id') id: string, @Body() dto: UpdateTenantDomainDto) {
    return this.domains.update(user.tenantId, id, dto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('domains:write', '*')
  remove(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.domains.remove(user.tenantId, id);
  }

  @Post(':id/verify')
  @UseGuards(JwtAuthGuard)
  @RequirePermissions('domains:write', '*')
  verify(@CurrentUser() user: AuthUser, @Param('id') id: string) {
    return this.domains.verify(user.tenantId, id);
  }

  /**
   * Public — called by a signup UI before the user submits the register
   * form, to decide whether to show "you'll be joining <Org>". Returns
   * only a tenant name (never an id list, member count, or anything else
   * that would let an attacker enumerate org membership by probing
   * emails).
   */
  @Public()
  @Get('lookup')
  async lookup(@Query() query: DomainLookupQueryDto) {
    const match = await this.domains.lookupAutoJoin(query.email);
    return match ? { autoJoin: true, tenantName: match.tenantName } : { autoJoin: false };
  }
}
