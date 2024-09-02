import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { enableMfaForUser, verifyUserMfaChallenge } from 'src/modules/users/users.actions';
import {
  createUserMfaChallenge,
  getAuthDataByKeyId,
  getAuthSession,
  getRequestAuthParams
} from 'src/modules/users/users.service';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-mfa-challenge');

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

    const { keyName, keyId } = getRequestAuthParams(event);
    const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const expiresIn = 3600;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      uid,
      orgId,
      keyName,
      secretKey,
      expiresIn
    );

    if (!authSession.user.authMfaEnabled) {
      await enableMfaForUser(logger, pgClient, uid, factorId);
    }

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
