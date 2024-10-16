import { Job } from 'bullmq';
import { WebhookEvent, WebhookPayload } from './webhook.types';
import { Logger } from 'winston';
import { v4 as uuid } from 'uuid';
import { defaultJobConfig, WebhookJobName, webhookQueue } from './webhook.queue';
import { AuthUser, AuthUserSession } from '@/types/auth.types';

export async function enqueueWebhookEvent(
  logger: Logger,
  event: WebhookEvent,
  appPid: string,
  keyId: string,
  authSession: AuthUserSession
): Promise<Job> {
  const id = uuid();

  const { session, user } = authSession;

  logger.debug(`Enqueuing webhook event ${id}, "${event}"`, { id, event, uid: user.id });

  const { identities, factors, authMfaEnabled, email, verifiedAt, ...userData } = user;

  const webhookData = {
    identities,
    factors,
    authMfaEnabled,
    email,
    verifiedAt
  };

  const webhookUserData = {
    ...userData,
    isOnline: true,
    lastOnline: new Date().toISOString()
  };

  const reducedWehbookSessionData = {
    appPid,
    keyId,
    clientId: user.clientId,
    connectionId: null,
    socketId: null,
    timestamp: new Date().toISOString(),
    exp: session?.expiresAt || null,
    user: webhookUserData
  };

  const jobData: WebhookPayload = {
    id,
    event,
    data: webhookData,
    session: reducedWehbookSessionData
  };

  return webhookQueue.add(WebhookJobName.WEBHOOK_PROCESS, jobData, defaultJobConfig);
}
