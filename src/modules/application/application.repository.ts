import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';

export function registerApplicationUser(
  pgClient: PgClient,
  email: string,
  password: string
): Promise<QueryResult> {
  const query = `
    INSERT INTO application_users (
      email, password
    ) VALUES (
      $1, $2
    )
  `;

  return pgClient.query(query, [email, password]);
}

export function getApplicationUserByEmail(pgClient: PgClient, email: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM application_users 
    WHERE email = $1;
  `;

  return pgClient.query(query, [email]);
}
