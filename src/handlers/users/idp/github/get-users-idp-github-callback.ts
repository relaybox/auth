import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getGitHubPrimaryData } from 'src/lib/github';
import {
  getApplicationAuthenticationPreferences,
  getAuthDataByKeyId,
  getAuthProviderDataByProviderName,
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

const PROVIDER_NAME = 'github';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from github`);

  const pgClient = await getPgClient();

  try {
    const { code, state: publicKey } = event.queryStringParameters!;

    if (!code || !publicKey) {
      throw new ValidationError('Missing authorization code or publicKey params');
    }

    const { keyId } = getKeyParts(publicKey);
    const { orgId, appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    const { clientId, clientSecret } = await getAuthProviderDataByProviderName(
      logger,
      pgClient,
      appId,
      PROVIDER_NAME
    );

    const { providerId, username, email } = await getGitHubPrimaryData(
      clientId,
      clientSecret,
      code
    );

    let userData = await getUserIdentityByProviderId(
      logger,
      pgClient,
      appId,
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
        providerId
        // username
      );
    }

    const { id } = userData;

    if (!id) {
      throw new ValidationError('Failed to register user');
    }

    const { tokenExpiry, sessionExpiry, authStorageType } =
      await getApplicationAuthenticationPreferences(logger, pgClient, appId);

    const authenticateAction = true;
    const authSession = await getAuthSession(
      logger,
      pgClient,
      id,
      appId,
      publicKey,
      secretKey,
      tokenExpiry,
      sessionExpiry,
      authenticateAction,
      authStorageType
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
