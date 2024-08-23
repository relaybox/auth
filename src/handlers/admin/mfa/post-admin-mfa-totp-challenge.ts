import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { processChallengeSoftwareToken } from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-mfa-totp-challenge');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    const { userCode, email, session } = JSON.parse(event.body!);

    if (!userCode || !email || !session) {
      return httpResponse._400({ message: 'userCode, email and session required' });
    }

    const response = await processChallengeSoftwareToken(
      logger,
      cognitoClient,
      userCode,
      email,
      session
    );

    const {
      IdToken: idToken,
      RefreshToken: refreshToken,
      ExpiresIn: expiresIn
    } = response.AuthenticationResult!;

    return httpResponse._200({ idToken, refreshToken, expiresIn });
  } catch (err: any) {
    logger.error(`Mfa challenge failed`, { err });
    return httpResponse._422({ message: err.message });
  }
};
