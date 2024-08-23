import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getConnection } from 'src/lib/postgres';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import {
  generateAuthHashId,
  getUserByHashId,
  processCodeConfirmation,
  saveUserVerification
} from 'src/modules/auth/auth.service';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-confirmation-code');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getConnection();

  try {
    const { email, confirmationCode } = JSON.parse(event.body!);

    if (!email || !confirmationCode) {
      return httpResponse._400({ message: 'Missing email or code' });
    }

    const codeConfirmation = await processCodeConfirmation(cognitoClient, email, confirmationCode);
    const hashId = generateAuthHashId(email);

    const { id } = await getUserByHashId(logger, pgClient, hashId);

    await saveUserVerification(logger, pgClient, id);

    return httpResponse._200(codeConfirmation);
  } catch (err: any) {
    return httpResponse._422({ message: err.message });
  } finally {
    pgClient.clean();
  }
};
