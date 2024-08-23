import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  UserNotConfirmedException
} from '@aws-sdk/client-cognito-identity-provider';
import { formatAuthTokenResponse, processAuthentication } from 'src/modules/auth/auth.service';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-login');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { email, password } = JSON.parse(event.body!);

    const response = await processAuthentication(cognitoClient, email, password);
    const authTokenResponse = formatAuthTokenResponse(response);

    return httpResponse._200(authTokenResponse);
  } catch (err: any) {
    logger.error(`Login failed`, { err });

    if (err instanceof UserNotConfirmedException) {
      return httpResponse._422({ message: `Login failed: ${err.message}` });
    }

    return httpResponse._401({ message: `Login failed: ${err.message}` });
  }
};
