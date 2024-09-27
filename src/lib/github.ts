import { GithubUserData } from 'src/types/auth.types';

const GITHUB_WEB_URL = 'https://github.com';
const GITHUB_API_URL = 'https://api.github.com';

export async function getGitHubPrimaryData(
  clientId: string,
  clientSecret: string,
  code: string
): Promise<GithubUserData> {
  const accessToken = await getGitHubAuthTokenWeb(clientId, clientSecret, code);

  const authorization = `Bearer ${accessToken}`;

  const email = await getGitHubUserPrimaryEmail(authorization);
  const { id: providerId, login: username } = await getGitHubUserData(authorization);

  return { providerId, username, email };
}

export async function getGitHubAuthTokenWeb(
  clientId: string,
  clientSecret: string,
  code: string
): Promise<any> {
  const requestBody = {
    client_id: clientId,
    client_secret: clientSecret,
    code
  };

  const response = await fetch(`${GITHUB_WEB_URL}/login/oauth/access_token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(requestBody)
  });

  const data = <{ access_token: string }>await response.json();

  if (!response.ok) {
    throw new Error('Error fetching github token');
  }

  return data.access_token;
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
