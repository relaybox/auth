import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
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
import { getGoogleAuthToken, getGoogleUserData } from 'src/lib/google';
import { registerIdpUser } from 'src/modules/users/users.actions';
import { enqueueWebhookEvent } from '@/modules/webhook/webhook.service';
import { WebhookEvent } from '@/modules/webhook/webhook.types';
import { lambdaProxyEventMiddleware } from '@/util/request.util';

const logger = getLogger('post-users-idp-google-callback');

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || '';
const PROVIDER_NAME = 'google';
const REDIRECT_URI = `${AUTH_SERVICE_URL}/users/idp/google/callback`;

export async function lambdaProxyEventHandler(
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from google`);

  const pgClient = await getPgClient();

  try {
    const { code, state: publicKey } = event.queryStringParameters!;

    if (!code || !publicKey) {
      throw new ValidationError('Missing authorization code or publicKey params');
    }

    const { appPid, keyId } = getKeyParts(publicKey);
    const { orgId, appId, secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);

    const { clientId, clientSecret, callbackTargetUrl } = await getAuthProviderDataByProviderName(
      logger,
      pgClient,
      appId,
      PROVIDER_NAME
    );

    const authorization = await getGoogleAuthToken(clientId, clientSecret, code, REDIRECT_URI);

    const { providerId, email, username } = await getGoogleUserData(authorization);

    let userData = await getUserIdentityByProviderId(
      logger,
      pgClient,
      appId,
      providerId,
      AuthProvider.GOOGLE
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
        AuthProvider.GOOGLE,
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
    const htmlContent = getUsersIdpCallbackHtml(authSession, callbackTargetUrl);

    if (!authSession.user.authMfaEnabled) {
      await enqueueWebhookEvent(
        logger,
        WebhookEvent.AUTH_SIGNIN,
        appPid,
        keyId,
        authSession.user,
        authSession.session?.expiresAt
      );
    }

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
}

export const handler = lambdaProxyEventMiddleware(logger, lambdaProxyEventHandler);
