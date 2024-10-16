import { mockQueue } from 'test/__mocks__/external/bullmq';
import { enqueueWebhookEvent } from '@/modules/webhook/webhook.service';
import { WebhookEvent } from '@/modules/webhook/webhook.types';
import { getLogger } from '@/util/logger.util';
import { getAuthUser } from 'test/__mocks__/internal/user.mock';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebhookJobName } from '@/modules/webhook/webhook.queue';

const logger = getLogger('webhook-service');

describe('enqueueWebhookEvent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should enqueue a webhook event', async () => {
    const mockAuthUser = getAuthUser();
    const mockAppPid = 'appPid';
    const mockKeyId = 'keyId';
    const mockSessionExpiresAt = 123456789;

    const { identities, factors, authMfaEnabled, email, verifiedAt, ...mockAuthUserData } =
      mockAuthUser;

    await enqueueWebhookEvent(
      logger,
      WebhookEvent.AUTH_SIGNIN,
      mockAppPid,
      mockKeyId,
      mockAuthUser,
      mockSessionExpiresAt
    );

    const expeectedJobData = expect.objectContaining({
      identities,
      email,
      verifiedAt,
      factors,
      authMfaEnabled
    });

    const expectedJobSessionData = expect.objectContaining({
      appPid: mockAppPid,
      keyId: mockKeyId,
      clientId: mockAuthUser.clientId,
      connectionId: null,
      socketId: null,
      timestamp: expect.any(String),
      exp: mockSessionExpiresAt,
      user: expect.objectContaining({
        ...mockAuthUserData,
        isOnline: true,
        lastOnline: expect.any(String)
      })
    });

    expect(mockQueue.add).toHaveBeenCalledWith(
      WebhookJobName.WEBHOOK_PROCESS,
      expect.objectContaining({
        event: WebhookEvent.AUTH_SIGNIN,
        timestamp: expect.any(String),
        data: expeectedJobData,
        session: expectedJobSessionData
      }),
      expect.anything()
    );
  });

  it('should throw an error if webhook event fails to enqueue', async () => {
    const mockAuthUser = getAuthUser();
    const mockAppPid = 'appPid';
    const mockKeyId = 'keyId';
    const mockSessionExpiresAt = 123456789;

    mockQueue.add.mockImplementationOnce(() => {
      throw new Error('Failed to enqueue webhook event');
    });

    await expect(
      enqueueWebhookEvent(
        logger,
        WebhookEvent.AUTH_SIGNIN,
        mockAppPid,
        mockKeyId,
        mockAuthUser,
        mockSessionExpiresAt
      )
    ).rejects.toThrow('Failed to enqueue webhook event');
  });
});
