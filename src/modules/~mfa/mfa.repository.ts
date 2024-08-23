import { QueryResult } from 'pg';
import PgClient from 'serverless-postgres';

export async function setMfaEnabled(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const query = `
    UPDATE admin_users SET "mfaEnabled" = TRUE
    WHERE id = $1
  `;

  return pgClient.query(query, [uid]);
}

export async function setMfaDisabled(pgClient: PgClient, uid: string): Promise<QueryResult> {
  const query = `
    UPDATE admin_users SET "mfaEnabled" = FALSE
    WHERE id = $1
  `;

  return pgClient.query(query, [uid]);
}
