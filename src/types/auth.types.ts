export interface AuthSignupResponse {
  uid: string;
  identityId: string;
  clientId: string;
}

export interface AuthUserData {
  id: string;
  email: string;
}

export interface AuthData {
  secretKey: string;
  orgId: string;
}

export interface AuthUserIdentity {
  id: string;
  provider: AuthProvider;
  providerId: string | null;
  verifiedAt: string;
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
  verifiedAt: string;
  identities: AuthUserIdentity[];
  blockedAt: string | null;
  firstName: string | null;
  lastName: string | null;
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
  publicKey: string;
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
  GOOGLE = 'google',
  ANONYMOUS = 'anonymous'
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
  PASSWORD_RESET_CONFIRM = 'passwordResetConfirm',
  VERIFY = 'verify',
  SEND_VERIFICATION_CODE = 'sendVerificationCode',
  REGISTER = 'register'
}
