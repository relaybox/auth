import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';

export function createUser(
  pgClient: PgClient,
  orgId: string,
  clientid: string,
  username: string,
  email: string,
  emailHash: string,
  password: string,
  salt: string,
  keyVersion: number
): Promise<QueryResult> {
  const query = `
    INSERT INTO authentication_users (
      "orgId", "clientId", username, email, "emailHash", password, salt, "keyVersion"
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8
    )
  `;

  return pgClient.query(query, [
    orgId,
    clientid,
    username,
    email,
    emailHash,
    password,
    salt,
    keyVersion
  ]);
}

export function getUserByEmailHash(pgClient: PgClient, emailHash: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM authentication_users 
    WHERE "emailHash" = $1;
  `;

  return pgClient.query(query, [emailHash]);
}

export function getAuthDataByKeyId(pgClient: PgClient, keyId: string): Promise<QueryResult> {
  const query = `
    SELECT "orgId", "secretKey" 
    FROM credentials
    WHERE "keyId" = $1;
  `;

  return pgClient.query(query, [keyId]);
}
