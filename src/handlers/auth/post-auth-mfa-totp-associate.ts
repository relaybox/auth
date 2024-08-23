import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import {
  generateTotpQrCodeUrl,
  getAuthenticatedUserData,
  processAssociateSoftwareToken,
  processAuthentication
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';
import { getPgClient } from 'src/lib/postgres';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const logger = getLogger('post-auth-mfa-totp-associate');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const { password } = JSON.parse(event.body!);
    const { email } = getAuthenticatedUserData(logger, event);

    if (!password) {
      return httpResponse._400({ message: 'Password required' });
    }

    const response = await processAuthentication(cognitoClient, email, password);

    const { AccessToken: accessToken } = response.AuthenticationResult!;

    const result = await processAssociateSoftwareToken(logger, cognitoClient, accessToken!);

    // @ts-ignore
    const secretCode = result.SecretCode;
    const qrCodeUrl = await generateTotpQrCodeUrl(secretCode, email);

    return httpResponse._200({ url: qrCodeUrl });
  } catch (err: any) {
    logger.error(`Failed to associate mfa`, { err });
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
