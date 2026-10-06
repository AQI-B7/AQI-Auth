export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

export interface UserSummary {
  id: string;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  emailVerified: boolean;
  tenantId: string;
  permissions?: string[];
}

export interface TenantSummary {
  id: string;
  name: string;
  slug?: string;
}

export interface AuthResult extends TokenPair {
  user: UserSummary;
  tenant: TenantSummary;
  isNewUser?: boolean;
  joinedExistingOrganization?: boolean;
  requiresAdditionalVerification?: boolean;
  emailVerificationToken?: string; // dev-mode only, never present in production
}

export interface RequiresTwoFactor {
  requires2FA: true;
  message: string;
}

export interface RegisterInput {
  email: string;
  password: string;
  firstName: string;
  lastName?: string;
  tenantName: string;
  tenantSlug?: string;
  joinExistingByDomain?: boolean;
}

export interface LoginInput {
  email: string;
  password: string;
  tenantSlug?: string;
  totpCode?: string;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  description?: string | null;
  active: boolean;
  secret: string; // full value only on create/rotate; masked elsewhere
  createdAt: string;
  updatedAt: string;
}

export interface WebhookDelivery {
  id: string;
  eventType: string;
  eventId: string;
  status: 'PENDING' | 'DELIVERING' | 'SUCCEEDED' | 'FAILED' | 'DEAD_LETTERED';
  attempts: number;
  maxAttempts: number;
  responseStatus?: number | null;
  errorMessage?: string | null;
  createdAt: string;
}

export interface SessionSummary {
  id: string;
  device: string;
  ipAddress: string | null;
  lastActive: string;
  createdAt: string;
  expiresAt: string;
  isCurrent?: boolean;
}

export interface OAuthProviders {
  google: boolean;
  github: boolean;
}

export interface DomainLookupResult {
  autoJoin: boolean;
  tenantName?: string;
}

export interface ApiErrorShape {
  success: false;
  statusCode: number;
  code: string;
  message: string | string[];
  path: string;
  requestId?: string;
  timestamp: string;
  retryAfterSeconds?: number;
}
