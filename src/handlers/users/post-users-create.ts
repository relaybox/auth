import { enqueueWebhookEvent } from '@/modules/webhook/webhook.service';
import { WebhookEvent } from '@/modules/webhook/webhook.types';
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { AuthenticationError, PasswordRegexError, SchemaValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import { registerUser } from 'src/modules/users/users.actions';
import {
  createAuthenticationActivityLogEntry,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getRequestAuthParams,
  getUserDataByClientId,
  validatePassword,
  validateUsername
} from 'src/modules/users/users.service';
import { AuthenticationAction, AuthenticationActionResult } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-create');

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(5),
  username: z.string().min(3).optional(),
  firstName: z.string().min(3).optional(),
  lastName: z.string().min(3).optional()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Creating user`);

  const pgClient = await getPgClient();

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { email, password, username, firstName, lastName } = validateEventSchema(event, schema);

    const { appPid, keyId } = getRequestAuthParams(event, authenticationActionLog);

    const { orgId, appId } = await getAuthDataByKeyId(
      logger,
      pgClient,
      keyId,
      authenticationActionLog
    );

    await validateUsername(logger, pgClient, appId, username);
    await validatePassword(logger, pgClient, appId, password);

    const { uid, identityId, clientId } = await registerUser(
      logger,
      pgClient,
      orgId,
      appId,
      email,
      password,
      username,
      firstName,
      lastName
    );

    authenticationActionLog.uid = uid;
    authenticationActionLog.identityId = identityId;

    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.REGISTER,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    const userData = await getUserDataByClientId(logger, pgClient, appId, clientId);

    if (userData) {
      await enqueueWebhookEvent(logger, WebhookEvent.AUTH_SIGNUP, appPid, keyId, userData!);
    }

    return httpResponse._200({ message: 'Registration successful', id: uid, clientId });
  } catch (err: any) {
    await createAuthenticationActivityLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.REGISTER,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    if (err instanceof SchemaValidationError || err instanceof PasswordRegexError) {
      return handleErrorResponse(logger, err);
    }

    const genericError = new AuthenticationError('Registration failed');

    return handleErrorResponse(logger, genericError);
  } finally {
    pgClient.clean();
  }
};
