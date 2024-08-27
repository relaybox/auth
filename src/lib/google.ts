const GOOGLE_API_OAUTH_URL = 'https://oauth2.googleapis.com';
const GOOGLE_API_URL = 'https://www.googleapis.com';

export async function getGoogleAuthToken(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string
): Promise<any> {
  const requestBody = {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code
  };

  const response = await fetch(`${GOOGLE_API_OAUTH_URL}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(requestBody)
  });

  const data = <{ access_token: string }>await response.json();

  if (!response.ok) {
    throw new Error('Error fetching google token');
  }

  return data.access_token;
}

export async function getGoogleUserData(authorization: string): Promise<any> {
  const response = await fetch(
    `${GOOGLE_API_URL}/oauth2/v3/userinfo?access_token=${authorization}`,
    {
      method: 'GET',
      headers: {
        authorization,
        accept: 'application/json'
      }
    }
  );

  const userData = <{ sub: string; email: string; given_name: string }>await response.json();

  if (!response.ok) {
    throw new Error('Error fetching google token');
  }

  const { sub: providerId, email, given_name: username } = userData;

  return { providerId, username, email };
}
