import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getPgClient } from 'src/lib/postgres';
import * as httpResponse from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { generateAuthHashId } from 'src/util/hash.util';
import {
  getUserNameFromEmail,
  processRegistration,
  syncUser
} from 'src/modules/admin/admin.service';

const logger = getLogger('post-admin-register');

const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';

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
    const { UserSub: cognitoSub } = await processRegistration(
      logger,
      cognitoClient,
      email,
      password
    );

    const hashId = generateAuthHashId(email, AUTH_HASH_ID_SECRET);
    const username = getUserNameFromEmail(email);

    await syncUser(logger, pgClient, cognitoSub!, username, hashId);

    return httpResponse._200({ message: 'Registration successful' });
  } catch (err: any) {
    logger.error(`Registration failed`, { err });
    return httpResponse._400({ message: `Registration failed: ${err.message}` });
  } finally {
    pgClient.clean();
  }
};
