import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse, redirect } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-idp-github');

const GITHUB_CLIENT_ID = 'Ov23liE7QYs1UQ9axuJr';
const GITHUB_CLIENT_SECRET = 'f1899c077d17dde34413a3e15e0939cd4aa20e57';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Redirecting auth request to github`);

  const pgClient = await getPgClient();

  try {
    const clientId = GITHUB_CLIENT_ID;
    const redirectUri = encodeURIComponent('http://localhost:4005/dev/users/idp/github/callback');
    const scope = 'user:email';

    return redirect(logger, 'https://github.com/login/oauth/authorize', {
      client_id: clientId,
      // redirect_uri: redirectUri,
      scope
    });
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
