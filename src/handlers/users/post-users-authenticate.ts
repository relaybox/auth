import { enqueueWebhookEvent } from '@/modules/webhook/webhook.service';
import { WebhookEvent } from '@/modules/webhook/webhook.types';
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { SchemaValidationError, UnauthorizedError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { authenticateUser } from 'src/modules/users/users.actions';
import {
  createAuthenticationActivityLogEntry,
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getAuthSession,
  getRequestAuthParams,
  getUserIdentityByEmail,
  updateUserIdentityLastLogin
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

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { email, password } = validateEventSchema(event, schema);
    const { publicKey, appPid, keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { appId, secretKey } = await getAuthDataByKeyId(
      logger,
      pgClient,
      keyId,
      authenticationActionLog
    );

    logger.info(`Auth data retreived`, { appId, publicKey });

    const userIdentity = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL,
      authenticationActionLog
    );

    const id = await authenticateUser(logger, pgClient, appId, password, userIdentity);

    logger.info(`Authenticated user found by id`, { id });

    await updateUserIdentityLastLogin(logger, pgClient, id, AuthProvider.EMAIL);

    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      appId,
      publicKey,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
    );

    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.AUTHENTICATE,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    await enqueueWebhookEvent(logger, WebhookEvent.AUTH_SIGNIN, appPid, keyId, authSession);

    return httpResponse._200(authSession);
  } catch (err: any) {
    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.AUTHENTICATE,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    if (err instanceof SchemaValidationError) {
      return handleErrorResponse(logger, err);
    }

    const genericError = new UnauthorizedError('Login failed');

    return handleErrorResponse(logger, genericError);
  } finally {
    pgClient.clean();
  }
};
