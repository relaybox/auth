import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { validateEventSchema } from 'src/lib/validation';
import {
  createAuthenticationActionLogEntry,
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getAuthenticationActionLog,
  getRequestAuthParams,
  getUserIdentityByEmail,
  sendAuthVerificationCode
} from 'src/modules/users/users.service';
import {
  AuthenticationAction,
  AuthenticationActionResult,
  AuthProvider,
  AuthVerificationCodeType
} from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { z } from 'zod';

const logger = getLogger('post-users-password-reset');

const schema = z.object({
  email: z.string().email()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Password reset request received`);

  const pgClient = await getPgClient();

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { email } = validateEventSchema(event, schema);
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

    if (!userIdentity) {
      logger.warn(`User not found`, { email });
      authenticationActionLog.errorMessage = 'User not found';
      await createAuthenticationActionLogEntry(
        logger,
        pgClient,
        event,
        AuthenticationAction.PASSWORD_RESET,
        AuthenticationActionResult.FAIL,
        authenticationActionLog
      );

      return httpResponse._200({ message: 'Password reset request initialized' });
    }

    const { uid, identityId } = userIdentity;

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      identityId,
      AuthVerificationCodeType.PASSWORD_RESET
    );

    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.PASSWORD_RESET,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: 'Password reset request initialized' });
  } catch (err: any) {
    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.PASSWORD_RESET,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
