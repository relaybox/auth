export interface PublicAuthUserData {
  id: string;
  clientId: string;
  createdAt: string;
  updatedAt: string;
  username: string;
  orgId: string;
  appId: string;
  isOnline: boolean;
  lastOnline: string;
  blockedAt: string | null;
}

export interface ReducedWebhookSessionData {
  appPid: string;
  keyId: string;
  clientId: string;
  connectionId: string | null;
  socketId: string | null;
  timestamp: string;
  user: PublicAuthUserData;
  exp: number | null;
}

export interface WebhookPayload {
  id: string;
  event: string;
  data: any;
  session: ReducedWebhookSessionData;
  filterAttributes?: Record<string, unknown>;
}

export enum WebhookEvent {
  AUTH_SIGNUP = 'auth:signup',
  AUTH_SIGNIN = 'auth:signin'
}
