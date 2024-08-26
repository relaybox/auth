import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getAuthenticatedUserData } from 'src/lib/auth';
import {
  processAuthentication,
  processSetUserMfaTotpPreference
} from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-mfa-totp-enable');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(event);

    if (!password) {
      return httpResponse._400({ message: 'Password required' });
    }

    const response = await processAuthentication(logger, cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processSetUserMfaTotpPreference(
      logger,
      cognitoClient,
      accessToken!,
      email,
      true
    );

    return httpResponse._200(result);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  }
};