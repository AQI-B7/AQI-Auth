import { IsEmail, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

export class WebAuthnRegisterOptionsDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  credentialName?: string;
}

export class WebAuthnRegisterVerifyDto {
  // The RegistrationResponseJSON produced by the browser's
  // navigator.credentials.create() call, relayed as-is from the client.
  // Its exact shape is defined by the WebAuthn spec / @simplewebauthn/browser
  // and validated structurally by verifyRegistrationResponse() itself —
  // re-declaring every nested field here would just duplicate that
  // validation with a second, looser copy.
  @IsObject()
  response!: Record<string, unknown>;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  credentialName?: string;
}

export class WebAuthnAuthOptionsDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  tenantSlug?: string;
}

export class WebAuthnAuthVerifyDto {
  @IsObject()
  response!: Record<string, unknown>;
}
