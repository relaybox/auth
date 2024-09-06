import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { authenticateUser } from 'src/modules/users/users.actions';
import {
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getAuthSession,
  getRequestAuthParams,
  updateUserIdentityLastLogin
} from 'src/modules/users/users.service';
import { AuthProvider } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-authenticate');

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(5)
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Authenticating user with public key`);

  try {
    const { email, password } = validateEventSchema(event, schema);
    const { keyName, keyId } = getRequestAuthParams(event);
    const { appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    logger.info(`Auth data retreived`, { appId, keyName });

    const id = await authenticateUser(logger, pgClient, appId, email, password);

    logger.info(`Authenticated user found by id`, { id });

    await updateUserIdentityLastLogin(logger, pgClient, id, AuthProvider.EMAIL);

    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      appId,
      keyName,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    return httpResponse._200(authSession);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
