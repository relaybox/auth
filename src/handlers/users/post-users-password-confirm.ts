import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserByEmail,
  resetUserPassword
} from 'src/modules/users/users.service';
import { AuthProvider } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-verify');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  logger.info(`Verifying user`);

  try {
    const { email, code, password } = JSON.parse(event.body!);

    if (!email || !code || !password) {
      throw new ValidationError('Email, password and code required');
    }

    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserByEmail(logger, pgClient, orgId, email, AuthProvider.EMAIL);

    if (!userData) {
      throw new NotFoundError(`User not found`);
    }

    const { id: uid } = userData;

    await resetUserPassword(logger, pgClient, uid, code, password);

    return httpResponse._200({ message: 'Password reset successful' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
