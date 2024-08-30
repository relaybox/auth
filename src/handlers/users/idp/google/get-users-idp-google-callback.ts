import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import {
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthSession,
  getAuthToken,
  getKeyParts,
  getUserIdentityByProviderId,
  getUserDataById,
  REFRESH_TOKEN_EXPIRES_IN_SECS,
  registerIdpUser,
  updateUserData
} from 'src/modules/users/users.service';
import { ValidationError } from 'src/lib/errors';
import { AuthProvider, AuthStorageType } from 'src/types/auth.types';
import { encrypt, generateHash } from 'src/lib/encryption';
import { getUsersIdpCallbackHtml } from 'src/modules/users/users.templates';
import { getGoogleAuthToken, getGoogleUserData } from 'src/lib/google';

const logger = getLogger('post-users-idp-google-callback');

const GOOGLE_CLIENT_ID = '716987004698-2903nfndh2v79ldg6ltm7bu8b38dttuk.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';
const API_SERVICE_URL = process.env.API_SERVICE_URL || '';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from google`);

  const pgClient = await getPgClient();

  try {
    const { code, state: keyName } = event.queryStringParameters!;

    if (!code || !keyName) {
      throw new ValidationError('Missing authorization code or keyName params');
    }

    const { keyId } = getKeyParts(keyName);
    const { orgId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const redirectUri = `${API_SERVICE_URL}/users/idp/google/callback`;

    const authorization = await getGoogleAuthToken(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      code,
      redirectUri
    );

    const { providerId, email, username } = await getGoogleUserData(authorization);

    let userData = await getUserIdentityByProviderId(
      logger,
      pgClient,
      orgId,
      providerId,
      AuthProvider.GOOGLE
    );

    if (userData) {
      await updateUserData(logger, pgClient, userData.uid, [
        { key: 'email', value: encrypt(email) },
        { key: 'emailHash', value: generateHash(email) }
      ]);
    } else {
      const tmpPassword = Math.random().toString(36);

      userData = await registerIdpUser(
        logger,
        pgClient,
        orgId,
        keyId,
        email,
        tmpPassword,
        AuthProvider.GOOGLE,
        providerId,
        username
      );
    }

    const { uid, clientId } = userData;

    if (!clientId) {
      throw new ValidationError('Failed to register user');
    }

    const expiresIn = 300;
    const authSession = await getAuthSession(logger, pgClient, uid, keyName, secretKey, expiresIn);
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
