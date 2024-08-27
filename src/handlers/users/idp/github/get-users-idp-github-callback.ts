import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getGithubUserData } from 'src/lib/github';
import {
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthToken,
  getUserByProviderId,
  registerIdpUser,
  updateUserData
} from 'src/modules/users/users.service';
import { ValidationError } from 'src/lib/errors';
import { AuthProvider } from 'src/types/auth.types';
import { encrypt } from 'src/lib/encryption';
import { getUsersIdpCallbackHtml } from 'src/modules/users/users.html';

const logger = getLogger('post-users-idp-github');

const GITHUB_CLIENT_ID = 'Ov23liE7QYs1UQ9axuJr';
const GITHUB_CLIENT_SECRET = 'f1899c077d17dde34413a3e15e0939cd4aa20e57';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from github`);

  let clientId;

  const pgClient = await getPgClient();

  try {
    const { code, state: keyName } = event.queryStringParameters!;

    if (!code || !keyName) {
      throw new ValidationError('Missing authorization code or keyName params');
    }

    const [_, keyId] = keyName.split('.');
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    const { providerId, username, email } = await getGithubUserData(
      GITHUB_CLIENT_ID,
      GITHUB_CLIENT_SECRET,
      code
    );

    let userData = await getUserByProviderId(logger, pgClient, providerId, AuthProvider.GITHUB);

    if (userData) {
      await updateUserData(logger, pgClient, userData.id, [
        { key: 'email', value: encrypt(email) }
      ]);
    } else {
      const tmpPassword = Math.random().toString(36);

      userData = await registerIdpUser(
        logger,
        pgClient,
        keyId,
        email,
        tmpPassword,
        AuthProvider.GITHUB,
        providerId,
        username
      );
    }

    clientId = userData.clientId;

    if (!clientId) {
      throw new ValidationError('Failed to register user');
    }

    const authToken = await getAuthToken(logger, keyName, secretKey, clientId);
    const refreshToken = await getAuthRefreshToken(logger, keyName, secretKey, clientId);
    const htmlContent = getUsersIdpCallbackHtml(authToken, refreshToken);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'text/html'
      },
      body: htmlContent
    };
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
