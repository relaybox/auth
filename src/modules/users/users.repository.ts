import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';

export function createUser(
  pgClient: PgClient,
  orgId: string,
  uid: string,
  username: string,
  email: string,
  emailHash: string,
  password: string,
  salt: string,
  keyVersion: number
): Promise<QueryResult> {
  const query = `
    INSERT INTO authentication_users (
      "orgId", uid, username, email, "emailHash", password, salt, "keyVersion"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8
    )
  `;

  return pgClient.query(query, [
    orgId,
    uid,
    username,
    email,
    emailHash,
    password,
    salt,
    keyVersion
  ]);
}

export function getUserByEmail(pgClient: PgClient, email: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_users 
    WHERE email = $1;
  `;

  return pgClient.query(query, [email]);
}
