import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse, redirect } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-idp-github');

const GITHUB_CLIENT_ID = 'Ov23liE7QYs1UQ9axuJr';
const API_SERVICE_URL = process.env.API_SERVICE_URL || '';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Redirecting auth request to github`);

  const pgClient = await getPgClient();

  try {
    const { keyName } = event.queryStringParameters!;

    if (!keyName) {
      throw new ValidationError('Missing keyName query param');
    }

    const clientId = GITHUB_CLIENT_ID;
    const redirectUri = `${API_SERVICE_URL}/users/idp/github/callback`;
    const scope = 'user:email';
    const state = keyName;
    const rawQueryparams = true;

    return redirect(
      logger,
      'https://github.com/login/oauth/authorize',
      {
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state
      },
      rawQueryparams
    );
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
