import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  UserNotConfirmedException
} from '@aws-sdk/client-cognito-identity-provider';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { processAuthentication } from 'src/modules/admin/admin.service';
import { formatAuthTokenResponse } from 'src/lib/auth';

const logger = getLogger('post-admin-login');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { email, password } = JSON.parse(event.body!);

    const response = await processAuthentication(logger, cognitoClient, email, password);
    const authTokenResponse = formatAuthTokenResponse(response);

    return httpResponse._200(authTokenResponse);
  } catch (err: any) {
    console.log(err);
    logger.error(`Login failed`, { err });

    if (err instanceof UserNotConfirmedException) {
      return httpResponse._422({ message: `Login failed: ${err.message}` });
    }

    return httpResponse._401({ message: `Login failed: ${err.message}` });
  }
};
