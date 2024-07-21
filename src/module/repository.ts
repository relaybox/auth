import { QueryResult } from 'pg';
import PgClient from 'serverless-postgres';

export async function getSecretKeybyKeyId(
  pgClient: PgClient,
  appPid: string,
  keyId: string
): Promise<QueryResult> {
  const query = `
    SELECT "secretKey" 
    FROM credentials 
    WHERE "appPid" = $1 AND "keyId" = $2;
  `;

  return pgClient.query(query, [appPid, keyId]);
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
