import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { generateTotpQrCodeUrl } from 'src/lib/auth';
import { DuplicateKeyError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  createUserMfaFactor,
  getMfaFactorTypeForUser,
  getUserDataById
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

    if (existingFactor) {
      throw new DuplicateKeyError(`MFA type "${AuthMfaFactorType.TOTP}" already created for user`);
    }

    const { id, type, secret } = await createUserMfaFactor(logger, pgClient, uid);
    const { email } = await getUserDataById(logger, pgClient, uid);
    const qrCodeUri = await generateTotpQrCodeUrl(secret, email, 'RelayBox'); // GET ORG NAME BASED ON KEY NAME

    return httpResponse._200({ id, type, secret, qrCodeUri });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
