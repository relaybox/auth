import { Job } from 'bullmq';
import { WebhookEvent, WebhookPayload } from './webhook.types';
import { Logger } from 'winston';
import { v4 as uuid } from 'uuid';
import { defaultJobConfig, WebhookJobName, webhookQueue } from './webhook.queue';
import { AuthUser } from '@/types/auth.types';

export async function enqueueWebhookEvent(
  logger: Logger,
  event: WebhookEvent,
  appPid: string,
  keyId: string,
  user: AuthUser,
  filterAttributes?: Record<string, unknown>
): Promise<Job> {
  const id = uuid();

  logger.debug(`Enqueuing webhook event ${id}, "${event}"`, { id, event, user });

  const reducedWehbookSessionData = {
    appPid,
    keyId,
    clientId: user.clientId,
    connectionId: null,
    socketId: null,
    timestamp: new Date().toISOString(),
    user
  };

  const jobData: WebhookPayload = {
    id,
    event,
    data: null,
    session: reducedWehbookSessionData,
    filterAttributes
  };

  return webhookQueue.add(WebhookJobName.WEBHOOK_PROCESS, jobData, defaultJobConfig);
}
