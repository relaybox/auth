import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as httpResponse from 'src/util/http.util';
import { getConnection } from 'src/util/db.util';
import { setAuthenticationComplete } from 'src/modules/auth/auth.repository';

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: any
): Promise<APIGatewayProxyResult> => {
  context.callbackWaitsForEmptyEventLoop = false;

  const pgClient = await getConnection();

  try {
    const { principalId } = event.requestContext.authorizer!.principalId;

    await setAuthenticationComplete(pgClient, principalId);

    return httpResponse._200();
  } catch (err: any) {
    return httpResponse._403(err.message);
  } finally {
    pgClient.clean();
  }
};
