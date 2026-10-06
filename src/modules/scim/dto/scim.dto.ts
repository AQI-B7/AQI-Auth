import { IsString } from 'class-validator';

export class CreateScimTokenDto {
  @IsString()
  name!: string;
}

/**
 * SCIM User/PatchOp request bodies are defined by RFC 7643/7644, not by
 * this service, and are intentionally NOT declared as class-validator
 * DTOs: this service's global ValidationPipe runs with
 * whitelist/forbidNonWhitelisted enabled, which would strip or reject
 * any SCIM attribute we didn't explicitly re-declare (schemas, emails,
 * name.*, etc.) — breaking real IdPs that send a fuller payload than we
 * bothered to model. Using plain TS interfaces (erased at runtime, so
 * Nest's ValidationPipe sees a bare `Object` metatype and skips
 * validation entirely) accepts whatever shape the IdP sends, and
 * ScimService picks out only the fields it understands, defensively.
 */
export interface ScimUserPayload {
  schemas?: string[];
  userName?: string;
  active?: boolean;
  name?: { givenName?: string; familyName?: string };
  emails?: { value: string; primary?: boolean }[];
  externalId?: string;
  [key: string]: unknown;
}

export interface ScimPatchOperation {
  op: 'add' | 'remove' | 'replace' | string;
  path?: string;
  value?: unknown;
}

export interface ScimPatchPayload {
  schemas?: string[];
  Operations: ScimPatchOperation[];
}
