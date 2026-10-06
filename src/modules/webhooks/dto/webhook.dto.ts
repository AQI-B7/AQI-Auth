import { IsArray, IsBoolean, IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export const WEBHOOK_EVENT_TYPES = [
  'user.registered',
  'user.login',
  'user.banned',
  'session.revoked',
  'invitation.created',
  'invitation.accepted',
] as const;

export class CreateWebhookEndpointDto {
  @IsUrl({ require_tld: false, protocols: ['https', 'http'] })
  url!: string;

  @IsArray()
  @IsString({ each: true })
  events!: string[];

  @IsOptional()
  @IsString()
  @MaxLength(200)
  description?: string;
}

export class UpdateWebhookEndpointDto {
  @IsOptional()
  @IsUrl({ require_tld: false, protocols: ['https', 'http'] })
  url?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  events?: string[];

  @IsOptional()
  @IsBoolean()
  active?: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  description?: string;
}
