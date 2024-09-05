import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getGitHubPrimaryData } from 'src/lib/github';
import {
  getAuthDataByKeyId,
  getAuthSession,
  getKeyParts,
  getUserIdentityByProviderId,
  updateUserIdentityData
} from 'src/modules/users/users.service';
import { ValidationError } from 'src/lib/errors';
import { AuthProvider } from 'src/types/auth.types';
import { encrypt, generateHash } from 'src/lib/encryption';
import { getUsersIdpCallbackHtml } from 'src/modules/users/users.templates';
import { registerIdpUser } from 'src/modules/users/users.actions';

const logger = getLogger('post-users-idp-github');

const GITHUB_CLIENT_ID = 'Ov23liE7QYs1UQ9axuJr';
const GITHUB_CLIENT_SECRET = 'f1899c077d17dde34413a3e15e0939cd4aa20e57';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from github`);

  const pgClient = await getPgClient();

  try {
    const { code, state: keyName } = event.queryStringParameters!;

    if (!code || !keyName) {
      throw new ValidationError('Missing authorization code or keyName params');
    }

    const { keyId } = getKeyParts(keyName);
    const { orgId, appId, appPid, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    const { providerId, username, email } = await getGitHubPrimaryData(
      GITHUB_CLIENT_ID,
      GITHUB_CLIENT_SECRET,
      code
    );

    let userData = await getUserIdentityByProviderId(
      logger,
      pgClient,
      orgId,
      providerId,
      AuthProvider.GITHUB
    );

    if (userData) {
      await updateUserIdentityData(logger, pgClient, userData.identityId, [
        { key: 'email', value: encrypt(email) },
        { key: 'emailHash', value: generateHash(email) },
        { key: 'lastLoginAt', value: new Date().toISOString() }
      ]);
    } else {
      const tmpPassword = Math.random().toString(36);

      userData = await registerIdpUser(
        logger,
        pgClient,
        orgId,
        appId,
        keyId,
        email,
        tmpPassword,
        AuthProvider.GITHUB,
        providerId,
        username
      );
    }

    const { id } = userData;

    if (!id) {
      throw new ValidationError('Failed to register user');
    }

    const expiresIn = 300;
    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      appId,
      keyName,
      secretKey,
      expiresIn,
      authenticateAction
    );
    const htmlContent = getUsersIdpCallbackHtml(authSession);

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
