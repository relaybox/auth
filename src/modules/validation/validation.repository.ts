import { QueryResult } from 'pg';
import PgClient from 'serverless-postgres';

export async function getSecretKeybyKeyId(
  pgClient: PgClient,
  appPid: string,
  keyId: string
): Promise<QueryResult> {
  const query = `
    SELECT "secretKey", "deletedAt"
    FROM credentials
    WHERE "appPid" = $1 AND "keyId" = $2 AND "deletedAt" IS NULL;
  `;

  return pgClient.query(query, [appPid, keyId]);
}

export async function getTokenValidationCredentialsByKeyId(
  pgClient: PgClient,
  keyId: string
): Promise<QueryResult> {
  const query = `
    SELECT "secretKey", "deletedAt", "orgId"
    FROM credentials
    WHERE "keyId" = $1 AND "deletedAt" IS NULL;
  `;

  return pgClient.query(query, [keyId]);
}

export async function getPermissionsByKeyId(
  pgClient: PgClient,
  keyId: string
): Promise<QueryResult> {
  const query = `
    SELECT cpe.permission, cpa.pattern
    FROM credentials c
    LEFT JOIN credential_permissions cpe ON cpe."credentialId" = c.id
    LEFT JOIN credential_patterns cpa ON cpa."credentialId" = c.id
    WHERE c."keyId" = $1;
  `;

  return pgClient.query(query, [keyId]);
}
