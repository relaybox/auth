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
