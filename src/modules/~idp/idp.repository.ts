import { QueryResult } from 'pg';
import PgClient from 'serverless-postgres';

export async function syncIdpUser(
  pgClient: PgClient,
  id: string,
  username: string,
  hashId: string,
  provider: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO admin_users (
      id, username, "hashId", "createdAt", provider, verified
    ) VALUES (
      $1, $2, $3, $4, $5, $6
    );
  `;

  return pgClient.query(query, [id, username, hashId, now, provider, now]);
}
