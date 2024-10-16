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
  authUser: AuthUser,
  sessionExpiresAt: number | null = null
): Promise<Job> {
  const id = uuid();
  const timestamp = new Date().toISOString();

  logger.debug(`Enqueuing webhook event ${id}, "${event}"`, { id, event, uid: authUser.id });

  const { identities, factors, authMfaEnabled, email, verifiedAt, ...userData } = authUser;

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
    lastOnline: timestamp
  };

  const reducedWehbookSessionData = {
    appPid,
    keyId,
    clientId: authUser.clientId,
    connectionId: null,
    socketId: null,
    timestamp,
    exp: sessionExpiresAt || null,
    user: webhookUserData
  };

  const jobData: WebhookPayload = {
    id,
    event,
    timestamp,
    data: webhookData,
    session: reducedWehbookSessionData
  };

  return webhookQueue.add(WebhookJobName.WEBHOOK_PROCESS, jobData, defaultJobConfig);
}
