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

export interface AuthData {
  secretKey: string;
  orgId: string;
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

export interface ReqquestAuthParams {
  keyName: string;
  keyId: string;
  appPid: string;
}

export enum AuthVerificationCodeType {
  REGISTER = 'register',
  PASSWORD_RESET = 'passwordReset'
}

export enum AuthProvider {
  EMAIL = 'email',
  GITHUB = 'github',
  GOOGLE = 'google'
}

export interface GithubAuthCredentials {
  client_id: string;
  client_secret: string;
  code: string;
}

export interface GithubUserData {
  providerId: string;
  username: string;
  email: string;
}
