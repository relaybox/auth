import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { AuthenticationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { resetUserPassword } from 'src/modules/users/users.actions';
import {
  createAuthenticationActionLogEntry,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getRequestAuthParams,
  getUserIdentityByEmail,
  validatePassword
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
  code: z.string().length(6),
  password: z.string().min(5)
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
    const { email, code, password } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { appId } = await getAuthDataByKeyId(logger, pgClient, keyId, authenticationActionLog);
    await validatePassword(logger, pgClient, appId, password);
    const userIdentity = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL,
      authenticationActionLog
    );

    if (!userIdentity) {
      logger.warn(`User not found`, { email });
      throw new AuthenticationError('User not found');
    }

    const { identityId } = userIdentity;

    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.PASSWORD_RESET_CONFIRM,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    await resetUserPassword(logger, pgClient, identityId, code, password);

    return httpResponse._200({ message: 'Password reset successful' });
  } catch (err: any) {
    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.PASSWORD_RESET_CONFIRM,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    const genericError = new AuthenticationError('Password reset failed');

    return handleErrorResponse(logger, genericError);
  } finally {
    pgClient.clean();
  }
};
