import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { ValidationError } from 'src/lib/errors';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse, redirect } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';

const logger = getLogger('post-users-idp-google-authorize');

const GOOGLE_CLIENT_ID = '716987004698-2903nfndh2v79ldg6ltm7bu8b38dttuk.apps.googleusercontent.com';
const API_SERVICE_URL = process.env.API_SERVICE_URL || '';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Redirecting auth request to google`);

  const pgClient = await getPgClient();

  try {
    const { keyName } = event.queryStringParameters!;

    if (!keyName) {
      throw new ValidationError('Missing keyName query param');
    }

    const clientId = GOOGLE_CLIENT_ID;
    const responseType = 'code';
    const redirectUri = `${API_SERVICE_URL}/users/idp/google/callback`;
    const scope = 'openid email profile';
    const state = keyName;
    const rawQueryparams = true;

    return redirect(
      logger,
      'https://accounts.google.com/o/oauth2/v2/auth',
      {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
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