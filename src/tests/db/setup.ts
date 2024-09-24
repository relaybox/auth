import { generateSecret } from '@/lib/encryption';
import { nanoid } from 'nanoid';
import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

async function createOrganisation(pgClient: PgClient, name: string): Promise<string> {
  const query = `
    INSERT INTO organisations (
      name, 
      "createdAt"
    ) VALUES ($1, $2) RETURNING id;
  `;

  const { rows } = await pgClient.query(query, [name, new Date().toISOString()]);

  return rows[0].id;
}

async function createApplication(
  pgClient: PgClient,
  orgId: string,
  name: string
): Promise<{ appId: string; appPid: string }> {
  const now = new Date().toISOString();
  const pid = nanoid(12);
  const historyTtlHours = 24;

  const query = `
    INSERT INTO applications (
      pid,
      "orgId", 
      name, 
      "createdAt",
      "historyTtlHours"
    ) VALUES ($1, $2, $3, $4, $5) RETURNING id as "appId", pid as "appPid";
  `;

  const { rows } = await pgClient.query(query, [pid, orgId, name, now, historyTtlHours]);

  return rows[0];
}

async function createApplicationCredentials(
  pgClient: PgClient,
  orgId: string,
  appId: string,
  appPid: string
): Promise<{ apiKey: string; publicKey: string }> {
  const keyId = nanoid(12);
  const secretKey = generateSecret();
  const now = new Date().toISOString();

  const query = `
    INSERT INTO credentials (
      "orgId",
      "appId", 
      "appPid", 
      "keyId", 
      "secretKey", 
      "createdAt"
    ) VALUES ($1, $2, $3, $4, $5, $6);`;

  const { rows } = await pgClient.query(query, [orgId, appId, appPid, keyId, secretKey, now]);

  return {
    apiKey: `${appPid}:${keyId}:${secretKey}`,
    publicKey: `${appPid}:${keyId}`
  };
}

export async function setupDb(
  logger: Logger,
  pgClient: PgClient
): Promise<{ apiKey: string; publicKey: string }> {
  const orgId = await createOrganisation(pgClient, 'Test Org');
  const { appId, appPid } = await createApplication(pgClient, orgId, 'Test App');
  const { apiKey, publicKey } = await createApplicationCredentials(pgClient, orgId, appId, appPid);

  return { apiKey, publicKey };
}
