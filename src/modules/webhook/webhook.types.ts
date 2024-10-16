import { AuthUser } from '@/types/auth.types';

export interface ReducedWebhookSessionData {
  appPid: string;
  keyId: string;
  clientId: string;
  connectionId: string | null;
  socketId: string | null;
  timestamp: string;
  user: AuthUser | null;
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
