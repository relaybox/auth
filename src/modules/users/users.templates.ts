import { AuthUser } from 'src/types/auth.types';

export function getUsersIdpCallbackHtml(
  authToken: string,
  refreshToken: string,
  expiresIn: number,
  expiresAt: number,
  user: AuthUser
): string {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Callback</title>
      <script type="text/javascript">
        window.opener.postMessage({
          token: "${authToken}",
          refreshToken: "${refreshToken}",
          expiresIn: ${expiresIn},
          expiresAt: ${expiresAt},
          user: ${JSON.stringify(user)}
        }, 'http://localhost:5173');
        window.close();
      </script>
    </head>
    <body>
      <h1>Authentication Successful!</h1>
      <p>You can close this window now.</p>
    </body>
    </html>
  `;
}
