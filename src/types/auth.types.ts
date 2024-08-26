export interface AuthTokenResponse {
  idToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthMfaChallengeResponse {
  challengeName: string;
  session: string;
  challengeParameters: Record<string, string>;
}

export interface AuthUserData {
  id: string;
  email: string;
}

export interface OAuthTokenCredentials {
  id_token: string;
  refresh_token: string;
  expires_in?: number;
  expiry_date?: number;
}

export interface User {
  id: string;
  sub: string;
  username: string;
  lastOnline: Date;
  anonymous: boolean;
  expires: Date;
  confirmed: Date;
  createdAt: Date;
  verified: Date;
  authComplete: Date;
  avatar: number;
  mfaEnabled: boolean;
  pricingPlan: number;
}

export interface AuthUser {
  id: string;
  clientId: string;
  orgId: string;
  username: string;
  createdAt: string;
  updatedAt: string;
}
