export interface OAuthProfile {
  provider: 'google' | 'github';
  providerAccountId: string;
  email: string;
  emailVerified: boolean;
  firstName?: string;
  lastName?: string;
  imageUrl?: string;
  accessToken?: string;
  refreshToken?: string;
  raw?: unknown;
}
