import PgClient from 'serverless-postgres';

export async function getVerificationCode(pgClient: PgClient, uid: string): Promise<string> {
  const query = `
    SELECT code
    FROM authentication_user_verification
    WHERE "uid" = $1;
  `;

  const { rows } = await pgClient.query(query, [uid]);

  return rows[0].code;
}
