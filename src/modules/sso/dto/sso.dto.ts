import { IsBoolean, IsOptional, IsString, IsUrl, MaxLength, MinLength } from 'class-validator';

export class CreateSsoConnectionDto {
  @IsString()
  @MaxLength(100)
  name!: string;

  @IsUrl({ require_tld: false, protocols: ['https', 'http'] })
  entryPoint!: string; // IdP SSO redirect URL

  @IsString()
  @MinLength(1)
  issuer!: string; // IdP entity ID

  @IsString()
  @MinLength(50) // a real PEM cert is always much longer than this
  cert!: string; // IdP's X.509 signing certificate (PEM, with or without headers)

  @IsOptional()
  @IsBoolean()
  wantAssertionsSigned?: boolean;

  @IsOptional()
  @IsBoolean()
  jitProvisioning?: boolean;

  @IsOptional()
  @IsString()
  defaultRoleId?: string;
}

export class UpdateSsoConnectionDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsUrl({ require_tld: false, protocols: ['https', 'http'] })
  entryPoint?: string;

  @IsOptional()
  @IsString()
  issuer?: string;

  @IsOptional()
  @IsString()
  @MinLength(50)
  cert?: string;

  @IsOptional()
  @IsBoolean()
  wantAssertionsSigned?: boolean;

  @IsOptional()
  @IsBoolean()
  active?: boolean;

  @IsOptional()
  @IsBoolean()
  jitProvisioning?: boolean;

  @IsOptional()
  @IsString()
  defaultRoleId?: string;
}

export class SamlCallbackDto {
  @IsString()
  SAMLResponse!: string;

  @IsOptional()
  @IsString()
  RelayState?: string;
}
