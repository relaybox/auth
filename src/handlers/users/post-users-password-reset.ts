import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserByEmail,
  sendAuthVerificationCode
} from 'src/modules/users/users.service';
import { AuthProvider, AuthVerificationCodeType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-password-reset');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Password reset request received`);

  const pgClient = await getPgClient();

  try {
    const { email } = JSON.parse(event.body!);

    if (!email) {
      throw new ValidationError('Email required');
    }

    const { keyId } = getRequestAuthParams(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserByEmail(logger, pgClient, orgId, email, AuthProvider.EMAIL);

    if (!userData) {
      throw new NotFoundError(`User not found`);
    }

    const { id: uid } = userData;

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      AuthVerificationCodeType.PASSWORD_RESET
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: 'Password reset request initialized' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
