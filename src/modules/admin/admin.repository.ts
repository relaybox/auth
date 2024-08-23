import moment, { Moment } from 'moment-timezone';
import PgClient from 'serverless-postgres';
import { QueryResult } from 'pg';
import { User } from '../~auth/auth.types';

export async function syncUser(
  pgClient: PgClient,
  id: string,
  username: string,
  hashId: string
): Promise<QueryResult> {
  const now = new Date().toISOString();

  const query = `
    INSERT INTO admin_users (
      id, username, "hashId", "createdAt"
    ) VALUES (
      $1, $2, $3, $4
    )
  `;

  return pgClient.query(query, [id, username, hashId, now]);
}

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

export async function validateUsername(
  pgClient: PgClient,
  username: string,
  existingUid?: string
): Promise<QueryResult> {
  const params = [username];

  let query = `
    SELECT id 
    FROM admin_users 
    WHERE username = $1
  `;

  if (existingUid) {
    query += `AND id != $2`;
    params.push(existingUid);
  }

  return pgClient.query(query, params);
}

export async function saveAnonymousUser(
  pgClient: PgClient,
  sub: string,
  expires: Moment
): Promise<any> {
  const query = `
    INSERT INTO 
      admin_users(sub, "lastOnline", anonymous, expires, "createdAt") 
    VALUES 
      ($1, $2, $3, $4, $5)
    RETURNING id;
  `;

  const utc = moment.utc().toISOString();

  const { rows } = await pgClient.query(query, [sub, utc, true, expires.toISOString(), utc]);

  return rows[0];
}

export async function saveUserVerification(pgClient: PgClient, id: string): Promise<QueryResult> {
  const query = `
    UPDATE admin_users SET verified = $1
    WHERE id = $2
    RETURNING verified;
  `;

  const now = new Date().toISOString();

  return pgClient.query(query, [now, id]);
}

export function getSessionData(pgClient: PgClient, id: string): Promise<QueryResult> {
  const query = `
    SELECT
      id, username, verified, provider
    FROM admin_users
    WHERE id = $1;
  `;

  return pgClient.query(query, [id]);
}

export function confirmSession(
  pgClient: PgClient,
  sub: string,
  username: string
): Promise<QueryResult> {
  const query = `
    UPDATE admin_users SET 
      username = $1, confirmed = $2 
    WHERE sub = $3
    RETURNING
      id, username, confirmed;
  `;

  return pgClient.query(query, [username, moment.utc().toISOString(), sub]);
}

export async function getUserBySub(pgClient: PgClient, sub: string): Promise<User> {
  const query = `
    SELECT * FROM admin_users 
    WHERE sub = $1;
  `;

  const { rows } = await pgClient.query(query, [sub]);

  if (!rows.length) {
    throw new Error('Invalid authentication credentials');
  }

  return <User>(<unknown>rows[0]);
}

export async function getUserByEventSub(pgClient: PgClient, sub: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM admin_users 
    WHERE sub = $1;
  `;

  return pgClient.query(query, [sub]);
}

export async function getUserById(pgClient: PgClient, id: string): Promise<QueryResult> {
  const query = `
    SELECT * FROM admin_users 
    WHERE id = $1;
  `;

  return pgClient.query(query, [id]);
}

export async function getUserByHashId(pgClient: PgClient, hashId: string): Promise<QueryResult> {
  const query = `
    SELECT id, "hashId" FROM admin_users 
    WHERE "hashId" = $1;
  `;

  return pgClient.query(query, [hashId]);
}

export async function setAuthenticationComplete(
  pgClient: PgClient,
  id: string
): Promise<QueryResult> {
  const query = `
    UPDATE admin_users SET "authComplete" = $1 
    WHERE id = $2
  `;

  const now = new Date().toISOString();

  return pgClient.query(query, [now, id]);
}

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
