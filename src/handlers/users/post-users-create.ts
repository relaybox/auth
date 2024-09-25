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
    const { keyId } = getRequestAuthParams(event, authenticationActionLog);
    console.log('>>>>>', keyId);
    const { orgId, appId } = await getAuthDataByKeyId(
      logger,
      pgClient,
      keyId,
      authenticationActionLog
    );

    const { email, password, username, firstName, lastName } = validateEventSchema(event, schema);

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

    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
