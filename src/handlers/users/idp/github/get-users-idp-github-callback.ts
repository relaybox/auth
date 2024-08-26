import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { getPgClient } from 'src/lib/postgres';
import { handleErrorResponse } from 'src/util/http.util';
import { getLogger } from 'src/util/logger.util';
import { getGitHubUserPrimaryEmail } from 'src/lib/github';
import {
  getAuthDataByKeyId,
  getAuthRefreshToken,
  getAuthToken,
  registerIdpUser
} from 'src/modules/users/users.service';

const logger = getLogger('post-users-idp-github');

const GITHUB_CLIENT_ID = 'Ov23liE7QYs1UQ9axuJr';
const GITHUB_CLIENT_SECRET = 'f1899c077d17dde34413a3e15e0939cd4aa20e57';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  logger.info(`Fetching access token from github`);

  const pgClient = await getPgClient();

  try {
    const { code } = event.queryStringParameters!;
    const keyName = 'ewRnbOj5f2yR.S379hDiTPeB7';

    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });

    const data = <{ access_token: string }>await response.json();

    if (!response.ok) {
      logger.error(`Failed to fetch github token`, { data });
      throw new Error('Error fetching github token');
    }

    console.log(`Access token received`, { data });

    const email = await getGitHubUserPrimaryEmail(`Bearer ${data.access_token}`);

    console.log(`User data received`, { email });

    const [_, keyId] = keyName.split('.');
    const { clientId } = await registerIdpUser(logger, pgClient, keyId, email, '123', 'github');
    const { secretKey } = await getAuthDataByKeyId(logger, pgClient, keyId);
    const authToken = await getAuthToken(logger, keyName, secretKey, clientId);
    const refreshToken = await getAuthRefreshToken(logger, keyName, secretKey, clientId);

    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Callback</title>
            <script type="text/javascript">
                // Send the access token back to the parent window
                window.opener.postMessage({
                    token: "${authToken}",
                    refreshToken: "${refreshToken}"
                }, 'http://localhost:5173');

                // // Optionally close the popup window after sending the message
                window.close();
            </script>
        </head>
        <body>
            <h1>Authentication Successful!</h1>
            <p>You can close this window now.</p>
        </body>
        </html>
    `;

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'text/html'
      },
      body: htmlContent
    };
  } catch (err: any) {
    return handleErrorResponse(logger, err);
  } finally {
    pgClient.clean();
  }
};
