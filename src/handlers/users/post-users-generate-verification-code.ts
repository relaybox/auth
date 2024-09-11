import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, UnauthorizedError } from 'src/lib/errors';
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

const logger = getLogger('post-users-generate-verification-code');

const schema = z.object({
  email: z.string().email()
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Generating verification code`);

  const pgClient = await getPgClient();

  const authenticationActionLog = getAuthenticationActionLog();

  try {
    const { email } = validateEventSchema(event, schema);
    const { keyId } = getRequestAuthParams(event, authenticationActionLog);
    const { appId } = await getAuthDataByKeyId(logger, pgClient, keyId, authenticationActionLog);
    const userData = await getUserIdentityByEmail(
      logger,
      pgClient,
      appId,
      email,
      AuthProvider.EMAIL,
      authenticationActionLog
    );

    if (!userData) {
      logger.error(`User not found`);
      throw new NotFoundError('User not found');
    }

    const { uid, identityId, verifiedAt } = userData;

    if (verifiedAt) {
      logger.error(`User already verified`, { id: userData.uid, verifiedAt });
      throw new UnauthorizedError('User already verified');
    }

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      identityId,
      AuthVerificationCodeType.REGISTER
    );

    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.SEND_VERIFICATION_CODE,
      AuthenticationActionResult.SUCCESS,
      authenticationActionLog
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: `Verification code sent` });
  } catch (err: any) {
    logger.error(`Failed to send verification code`, { err });
    await createAuthenticationActionLogEntry(
      logger,
      pgClient,
      event,
      AuthenticationAction.SEND_VERIFICATION_CODE,
      AuthenticationActionResult.FAIL,
      authenticationActionLog,
      err
    );

    if (err instanceof UnauthorizedError || err instanceof NotFoundError) {
      return httpResponse._200({ message: `Verification code sent` });
    }

    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
