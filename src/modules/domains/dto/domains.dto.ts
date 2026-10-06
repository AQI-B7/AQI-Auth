import { IsBoolean, IsOptional, IsString, Matches } from 'class-validator';

const DOMAIN_PATTERN = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

export class AddTenantDomainDto {
  @IsString()
  @Matches(DOMAIN_PATTERN, { message: 'Must be a valid domain name, e.g. acme.com' })
  domain!: string;

  @IsOptional()
  @IsBoolean()
  autoJoin?: boolean;

  @IsOptional()
  @IsString()
  defaultRoleId?: string;
}

export class UpdateTenantDomainDto {
  @IsOptional()
  @IsBoolean()
  autoJoin?: boolean;

  @IsOptional()
  @IsString()
  defaultRoleId?: string;
}
