import { IsString, MinLength, MaxLength } from 'class-validator';

export class StartImpersonationDto {
  @IsString()
  targetUserId!: string;

  // Required, not optional — every impersonation session must be
  // justified in the audit trail. A short placeholder like "debug" is
  // still forced through, but at least it's on the record.
  @IsString()
  @MinLength(10)
  @MaxLength(500)
  reason!: string;
}
