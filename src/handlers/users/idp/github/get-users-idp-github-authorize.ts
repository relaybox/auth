import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import {
  getAuthDataByKeyId,
  getAuthProviderDataByProviderName,
  getKeyParts
} from 'src/modules/users/users.service';
import { AuthProvider } from 'src/types/auth.types';
import { handleErrorResponse, redirect } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-idp-github');

const API_SERVICE_URL = process.env.API_SERVICE_URL || '';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Redirecting auth request to github`);

  const pgClient = await getPgClient();

  try {
    const { publicKey } = event.queryStringParameters!;

    if (!publicKey) {
      throw new ValidationError('Missing publicKey query param');
    }

    const { keyId } = getKeyParts(publicKey);
    const { appId } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const { clientId } = await getAuthProviderDataByProviderName(
      logger,
      pgClient,
      appId,
      AuthProvider.GITHUB
    );

    const redirectUri = `${API_SERVICE_URL}/users/idp/github/callback`;
    const scope = 'user:email';
    const state = publicKey;
    const rawQueryparams = true;

    return redirect(
      logger,
      'https://github.com/login/oauth/authorize',
      {
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state
      },
      rawQueryparams
    );
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
