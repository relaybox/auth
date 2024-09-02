import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { generateAuthMfaTotpQrCodeUrl } from 'src/lib/auth';
import { DuplicateKeyError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { getTmpToken } from 'src/lib/token';
import {
  createUserMfaFactor,
  getAuthDataByKeyId,
  getMfaFactorTypeForUser,
  getRequestAuthParams,
  getUserEmailAddress
} from 'src/modules/users/users.service';
import { AuthMfaFactorType } from 'src/types/auth.types';
import * as httpResponse from 'src/util/http.util';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-mfa-enroll');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;

    const existingFactor = await getMfaFactorTypeForUser(
      logger,
      pgClient,
      uid,
      AuthMfaFactorType.TOTP
    );

    if (existingFactor?.verifiedAt) {
      throw new DuplicateKeyError(`MFA type "${AuthMfaFactorType.TOTP}" already verified for user`);
    }

    const { id, type, secret } =
      existingFactor || (await createUserMfaFactor(logger, pgClient, uid));
    const email = await getUserEmailAddress(logger, pgClient, uid);
    const qrCodeUri = await generateAuthMfaTotpQrCodeUrl(secret, email, 'RelayBox');
    const { keyName, keyId } = getRequestAuthParams(event);
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const tmpToken = await getTmpToken(logger, uid, keyName, secretKey);

    return httpResponse._200({ id, type, secret, qrCodeUri, tmpToken });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
