import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { NotFoundError, UnauthorizedError, ValidationError } from '@/lib/errors';
import { getPgClient } from '@/lib/postgres';
import {
  getAuthDataByKeyId,
  getRequestAuthParams,
  getUserDataByClientId,
  getUserIdentityByUid
} from '@/modules/users/users.service';
import * as httpResponse from '@/util/http.util';
import { handleErrorResponse } from '@/util/http.util';
import { getLogger } from '@/util/logger.util';
import { AuthProvider } from '@/types/auth.types';

const logger = getLogger('get-users-id-identity');

export async function handler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const uid = event.requestContext.authorizer!.principalId;
    const { provider } = event.queryStringParameters!;

    console.log(provider);

    if (!uid) {
      throw new ValidationError('Missing client id');
    }

    logger.info(`Getting session data for user`, { uid });

    const { keyId } = getRequestAuthParams(event);
    const { orgId, appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const userIdentity = await getUserIdentityByUid(
      logger,
      pgClient,
      uid,
      provider as AuthProvider
    );

    console.log(uid);

    if (!userIdentity) {
      throw new NotFoundError(`User not found`);
    }

    return httpResponse._200(userIdentity);
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
}
