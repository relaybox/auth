import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import {
  generateAuthHashId,
  getUserNameFromEmail,
  processRegistration
} from 'src/modules/auth/auth.service';
import { syncUser } from 'src/modules/auth/auth.repository';
import { getPgClient } from 'src/lib/postgres';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-auth-register');

const cognitoClient = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getPgClient();

  try {
    const body = JSON.parse(event.body!);
    const { email, password } = body;
    const { UserSub: cognitoSub } = await processRegistration(cognitoClient, email, password);

    const hashId = generateAuthHashId(email);
    const username = getUserNameFromEmail(email);

    await syncUser(pgClient, cognitoSub!, username, hashId);

    return httpResponse._200({ message: 'Registration successful' });
  } catch (err: any) {
    logger.error(`Registration failed`, { err });

    return httpResponse._400({ message: `Registration failed: ${err.message}` });
  } finally {
    pgClient.clean();
  }
};
