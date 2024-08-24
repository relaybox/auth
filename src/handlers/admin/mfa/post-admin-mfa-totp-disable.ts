import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getPgClient } from 'src/lib/postgres';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getAuthenticatedUserData } from 'src/lib/auth';
import {
  processChallengeSoftwareToken,
  processSetUserMfaTotpPreference,
  setMfaDisabled
} from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-mfa-totp-disable');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { password, userCode, session } = JSON.parse(event.body!);
    const { email, id: uid } = getAuthenticatedUserData(event);

    logger.info(`Disabling mfa for user ${uid}`);

    if (!password || !userCode) {
      return httpResponse._400({ message: 'password, userCode and session required' });
    }

    const response = await processChallengeSoftwareToken(
      logger,
      cognitoClient,
      userCode,
      email,
      session
    );

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    await processSetUserMfaTotpPreference(logger, cognitoClient, accessToken!, email, false);
    await setMfaDisabled(logger, pgClient, uid);

    return httpResponse._200({ message: `Multi factor authentication disabled successfully` });
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
