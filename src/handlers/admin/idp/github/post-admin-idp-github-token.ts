import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getLogger } from 'src/util/logger.util';
import * as httpResponse from 'src/util/http.util';
import { getGitHubAuthToken } from 'src/lib/auth';

const logger = getLogger('poat-admin-idp-github-token');

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching GitHub id token from authorization code flow`);

  try {
    const token = await getGitHubAuthToken(event);

    return httpResponse._200(token);
  } catch (err: any) {
    logger.error(`Failed to get GitHub token using authorization code`, { err });
    return httpResponse._500(err);
  }
};
