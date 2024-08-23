import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getPgClient } from 'src/lib/postgres';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import {
  processSetUserMfaTotpPreference,
  processVerifySoftwareToken,
  setMfaEnabled
} from 'src/modules/~mfa/mfa.service';
import { getAuthenticatedUserData } from 'src/lib/auth';
import { processAuthentication } from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-mfa-totp-verify');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { password, userCode, friendlyDeviceName } = JSON.parse(event.body!);
    const { email, id: uid } = getAuthenticatedUserData(event);

    if (!password || !userCode) {
      return httpResponse._400({ message: 'Password required' });
    }

    const response = await processAuthentication(logger, cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processVerifySoftwareToken(
      logger,
      cognitoClient,
      accessToken!,
      userCode,
      friendlyDeviceName
    );

    await processSetUserMfaTotpPreference(logger, cognitoClient, accessToken!, email, true);
    await setMfaEnabled(logger, pgClient, uid);

    // @ts-ignore
    return httpResponse._200({ message: result.Status });
  } catch (err: any) {
    logger.error(`Failed to verify totp`, { err });
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
