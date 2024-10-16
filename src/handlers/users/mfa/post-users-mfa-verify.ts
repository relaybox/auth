import { enqueueWebhookEvent } from '@/modules/webhook/webhook.service';
import { WebhookEvent } from '@/modules/webhook/webhook.types';
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { enableMfaForUser, verifyUserMfaChallenge } from 'src/modules/users/users.actions';
import {
  createUserMfaChallenge,
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getAuthSession,
  getRequestAuthParams
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-mfa-verify');

const schema = z.object({
  factorId: z.string().uuid(),
  code: z.string().length(6),
  challengeId: z.string().uuid().optional(),
  autoChallenge: z.boolean().optional()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;

    let { factorId, challengeId, code, autoChallenge } = validateEventSchema(event, schema);

    if (!challengeId && !autoChallenge) {
      throw new ValidationError('"challengeId" or "autoChallenge" required');
    }

    if (!challengeId) {
      challengeId = (await createUserMfaChallenge(logger, pgClient, uid, factorId)).id;
    }

    await verifyUserMfaChallenge(logger, pgClient, uid, factorId, challengeId, code);

    const { publicKey, appPid, keyId } = getRequestAuthParams(event);
    const { appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    const authenticateAction = false;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      uid,
      appId,
      publicKey,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    if (!authSession.user.authMfaEnabled) {
      await enableMfaForUser(logger, pgClient, uid, factorId);
    }

    await enqueueWebhookEvent(
      logger,
      WebhookEvent.AUTH_SIGNIN,
      appPid,
      keyId,
      authSession.user,
      authSession.session?.expiresAt
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
