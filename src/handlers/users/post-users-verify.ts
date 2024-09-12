import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { AuthenticationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { verifyUser } from 'src/modules/users/users.actions';
import {
  createAuthenticationActivityLogEntry,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getRequestAuthParams,
  getUserIdentityByEmail
} from 'src/modules/users/users.service';
import {
  AuthenticationAction,
  AuthenticationActionResult,
  AuthProvider
} from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-verify');

const schema = z.object({
  email: z.string().email(),
  code: z.string().length(6)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Verifying user`);

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { email, code } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { appId } = await getAuthDataByKeyId(logger, pgClient, keyId, authenticationActionLog);

    const userIdentity = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL,
      authenticationActionLog
    );

    await verifyUser(logger, pgClient, appId, email, code, userIdentity);

    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.VERIFY,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    return httpResponse._200({ message: 'User verification successful' });
  } catch (err: any) {
    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.VERIFY,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    const genericError = new AuthenticationError('User verification failed');

    return handleErrorResponse(logger, genericError);
  } finally {
    pgClient.clean();
  }
};
