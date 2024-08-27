export function getUsersIdpCallbackHtml(authToken: string, refreshToken: string): string {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Callback</title>
      <script type="text/javascript">
        window.opener.postMessage({
          token: "${authToken}",
          refreshToken: "${refreshToken}"
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