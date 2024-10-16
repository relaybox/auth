import { JobsOptions, Queue } from 'bullmq';
import { connectionOptionsIo } from '@/lib/redis';
import { WebhookPayload } from './webhook.types';

const WEBHOOK_QUEUE_NAME = 'webhook-process';

const defaultQueueConfig = {
  streams: {
    events: {
      maxLen: 100
    }
  }
};

export enum WebhookJobName {
  WEBHOOK_PROCESS = 'webhook:process'
}

export const defaultJobConfig: JobsOptions = {
  removeOnComplete: true,
  removeOnFail: false
};

export const webhookQueue = new Queue<WebhookPayload>(WEBHOOK_QUEUE_NAME, {
  connection: connectionOptionsIo,
  prefix: 'queue',
  ...defaultQueueConfig
});

process.on('SIGTERM', async () => {
  await webhookQueue.close();
});

process.on('SIGINT', async () => {
  await webhookQueue.close();
});
