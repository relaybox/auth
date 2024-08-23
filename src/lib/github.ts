import { APIGatewayProxyEvent } from 'aws-lambda';
import parser from 'lambda-multipart-parser';

const GITHUB_WEB_URL = 'https://github.com';
const GITHUB_API_URL = 'https://api.github.com';

export async function getGitHubAuthToken(event: APIGatewayProxyEvent): Promise<any> {
  const { client_id, client_secret, code } = await parser.parse(event);

  const queryParams = new URLSearchParams({
    client_id,
    client_secret,
    code
  });

  const requestUrl = `${GITHUB_WEB_URL}/login/oauth/access_token?${queryParams}`;

  const response = await fetch(requestUrl, {
    method: 'POST',
    headers: {
      accept: 'application/json'
    }
  });

  const token = await response.json();

  return token;
}

export async function getGitHubUserData(authorization: string): Promise<any> {
  const response = await fetch(`${GITHUB_API_URL}/user`, {
    method: 'GET',
    headers: {
      authorization,
      accept: 'application/json'
    }
  });

  const userData = <any>await response.json();

  return userData;
}

export async function getGitHubUserPrimaryEmail(authorization: string): Promise<any> {
  const response = await fetch(`${GITHUB_API_URL}/user/emails`, {
    method: 'GET',
    headers: {
      authorization,
      accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    }
  });

  const emailData = <any>await response.json();
  const primaryEmail = emailData.find((data: any) => data.primary);

  return primaryEmail.email;
}
