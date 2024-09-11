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

export interface AuthUserIdentity {
  id: string;
  provider: AuthProvider;
  providerId: string | null;
  verifiedAt: Date;
}

export interface AuthUserIdentityCredentials {
  uid: string;
  identityId: string;
  provider: AuthProvider;
  providerId: string | null;
  email: string;
  password: string;
  salt: string;
  keyVersion: number;
  verifiedAt: Date;
}

export interface AuthUserMfaFactor {
  id: string;
  type: AuthMfaFactorType;
  verifiedAt: Date;
}

export interface AuthUser {
  id: string;
  orgId: string;
  appId: string;
  email: string;
  username: string;
  authMfaEnabled: boolean;
  factors: AuthUserMfaFactor[];
  clientId: string;
  createdAt: string;
  updatedAt: string;
  identities: AuthUserIdentity[];
  blockedAt: string | null;
}

export interface AuthSession {
  token?: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: number;
  destroyAt?: number;
  authStorageType?: AuthStorageType;
}

export interface AuthUserSession {
  session: AuthSession | null;
  user: AuthUser;
  tmpToken?: string;
}

export interface RequestAuthParams {
  keyName: string;
  keyId: string;
  appPid: string;
}

export enum AuthVerificationCodeType {
  REGISTER = 'register',
  PASSWORD_RESET = 'passwordReset'
}

export enum AuthStorageType {
  PERSIST = 'persist',
  SESSION = 'session'
}

export enum AuthProvider {
  EMAIL = 'email',
  GITHUB = 'github',
  GOOGLE = 'google'
}

export enum AuthMfaFactorType {
  TOTP = 'totp'
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

export interface AuthenticationActionLog {
  uid: string | null;
  identityId: string | null;
  appId: string | null;
  keyId: string | null;
  errorMessage: string | null;
}

export enum AuthenticationActionResult {
  SUCCESS = 'SUCCESS',
  FAIL = 'FAIL'
}

export enum AuthenticationAction {
  AUTHENTICATE = 'authenticate',
  GET_SESSION = 'getSession',
  PASSWORD_RESET = 'passwordReset',
  PASSWORD_RESET_CONFIRM = 'passwordResetConfirm'
}
