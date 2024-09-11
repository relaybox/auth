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
  keyId: string | null;
}

export enum AuthenticationActionResult {
  SUCCESS = 'SUCCESS',
  FAIL = 'FAIL'
}

export enum AuthenticationAction {
  LOGIN = 'login',
  REGISTER = 'register',
  RESET_PASSWORD = 'reset_password',
  VERIFY = 'verify',
  FORGOT_PASSWORD = 'forgot_password',
  CONFIRM_PASSWORD = 'confirm_password',
  UPDATE_PASSWORD = 'update_password',
  UPDATE_PROFILE = 'update_profile',
  DELETE_ACCOUNT = 'delete_account',
  AUTHENTICATE = 'authenticate',
  REFRESH = 'refresh',
  MFA_ENROLL = 'mfa_enroll',
  MFA_CHALLENGE = 'mfa_challenge',
  MFA_VERIFY = 'mfa_verify',
  BLOCK = 'block',
  UNBLOCK = 'unblock',
  STATUS_UPDATE = 'status_update',
  USER_STATUS_UPDATE = 'user_status_update',
  USER_SUBSCRIBE = 'user_subscribe',
  USER_UNSUBSCRIBE = 'user_unsubscribe',
  USER_UNSUBSCRIBE_ALL = 'user_unsubscribe_all',
  CLIENT_AUTH = 'client_auth',
  CLIENT_AUTH_STATUS_UPDATE = 'client_auth_status_update',
  CLIENT_AUTH_SUBSCRIBE = 'client_auth_subscribe',
  CLIENT_AUTH_UNSUBSCRIBE = 'client_auth_unsubscribe',
  CLIENT_AUTH_UNSUBSCRIBE_ALL = 'client_auth_unsubscribe_all',
  IDP_AUTH = 'idp_auth',
  IDP_AUTH_STATUS_UPDATE = 'idp_auth_status_update',
  IDP_AUTH_SUBSCRIBE = 'idp_auth_subscribe',
  IDP_AUTH_UNSUBSCRIBE = 'idp_auth_unsubscribe',
  IDP_AUTH_UNSUBSCRIBE_ALL = 'idp_auth_unsubscribe_all'
}
