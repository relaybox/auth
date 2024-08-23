import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getLogger } from 'src/util/logger.util';
import * as httpResponse from 'src/util/http.util';
import { getGitHubUserData, getGitHubUserPrimaryEmail } from 'src/lib/auth';

const logger = getLogger('get-admin-idp-github-user');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching GitHub user data with id token`);

  try {
    const authorization = event.headers['Authorization'];

    if (!authorization) {
      throw new Error(`Authorization header not found`);
    }

    const userData = await getGitHubUserData(authorization);
    const userPrimaryEmail = await getGitHubUserPrimaryEmail(authorization);

    return httpResponse._200({
      sub: userData.id,
      ...userData,
      email: userPrimaryEmail
    });
  } catch (err: any) {
    logger.error(`Failed to get GitHub user / email data`, { err });
    return httpResponse._500(err);
  }
};
