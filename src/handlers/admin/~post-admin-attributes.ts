import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import {
  getAuthenticatedUserData,
  processAuthentication,
  processUpdateUserAttributes
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const logger = getLogger('post-admin-attributes');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { password, userAttributes } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(logger, event);

    if (!password || !userAttributes?.length) {
      return httpResponse._400({ message: 'password and userAttributes required' });
    }

    const response = await processAuthentication(cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processUpdateUserAttributes(
      logger,
      cognitoClient,
      accessToken!,
      userAttributes
    );

    return httpResponse._200(result);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  }
};
