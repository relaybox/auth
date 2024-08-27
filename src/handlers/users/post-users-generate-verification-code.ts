import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  createAuthVerificationCode,
  getAuthDataByKeyId,
  getRequestAuthData,
  getUserByEmail,
  sendAuthVerificationCode
} from 'src/modules/users/users.service';
import { AuthProvider, AuthVerificationCodeType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-generate-verification-code');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Generating verification code`);

  const pgClient = await getPgClient();

  try {
    const { email } = JSON.parse(event.body!);

    if (!email) {
      throw new ValidationError('Missing email');
    }

    const { keyId } = getRequestAuthData(event);
    const { orgId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userData = await getUserByEmail(logger, pgClient, orgId, email, AuthProvider.EMAIL);

    if (!userData) {
      throw new NotFoundError(`User not found`);
    }

    const { id: uid, verifiedAt } = userData;

    if (verifiedAt) {
      throw new ValidationError(`User already verified`);
    }

    const code = await createAuthVerificationCode(
      logger,
      pgClient,
      uid,
      AuthVerificationCodeType.REGISTER
    );

    await sendAuthVerificationCode(logger, email, code);

    return httpResponse._200({ message: 'Verification code sent' });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
