import PgClient from 'serverless-postgres';
import jwt from 'jsonwebtoken';
import { Logger } from 'winston';
import { getPermissionsByKeyId, getSecretKeybyKeyId } from './repository';
import { nanoid } from 'nanoid';

const JWT_ISSUER = process.env.JWT_ISSUER!;
const JWT_HASHING_ALGORITHM = 'HS256';
const NSP_ANONYMOUS_ID = '__a__';

export function decodeAuthToken(token: string): any {
  return jwt.decode(token);
}

export function verifyAuthToken(token: string, secretKey: string) {
  const payload = jwt.verify(token, secretKey, {
    algorithms: [JWT_HASHING_ALGORITHM],
    issuer: JWT_ISSUER
  });

  return payload;
}

export async function getSecretKey(
  logger: Logger,
  pgClient: PgClient,
  appPid: string,
  keyId: string
): Promise<string> {
  logger.info(`Getting secret key`, { appPid, keyId });

  const { rows } = await getSecretKeybyKeyId(pgClient, appPid, keyId);

  if (!rows.length) {
    throw new Error('Secret key not found');
  }

  const secretKey = rows[0].secretKey;

  return secretKey;
}

export async function getPermissions(
  logger: Logger,
  pgClient: PgClient,
  keyId: string,
  inlinePermissions: any = {}
): Promise<Record<string, string[]> | string[]> {
  logger.info(`Getting permissions for key`, { keyId });

  const { rows } = await getPermissionsByKeyId(pgClient, keyId);

  if (!rows.length) {
    throw new Error(`Permissions for key ${keyId} not found`);
  }

  const formattedPermissions = formatPermissions(rows);

  if (Array.isArray(formattedPermissions) && Object.keys(inlinePermissions).length === 0) {
    return formattedPermissions;
  }

  return {
    ...formattedPermissions,
    ...inlinePermissions
  };
}

export function formatPermissions(
  rows: { pattern: string; permission: string }[]
): Record<string, string[]> | string[] {
  if (rows[0].pattern === null) {
    return rows.map((row) => row.permission);
  }

  const response = {} as Record<string, string[]>;

  for (const row of rows) {
    if (!response[row.pattern]) {
      response[row.pattern] = [];
    }

    response[row.pattern].push(row.permission);
  }

  return response;
}

export function getClientCredentials(
  logger: Logger,
  appPid: string,
  clientId?: string,
  connectionId?: string
): { uid: string; connectionId: string; clientId?: string } {
  logger.info(`Getting credentials for auth`, { appPid, clientId, connectionId });

  if (!connectionId) {
    const genId = nanoid(12);
    connectionId = clientId ? getNspId(appPid, genId) : getAnonymousNspId(appPid, genId);
  }

  if (clientId) {
    clientId = getNspId(appPid, clientId);
  }

  const uid = clientId || connectionId;

  return {
    uid,
    connectionId,
    ...(clientId && { clientId })
  };
}

export function getNspId(appPid: string, id: string): string {
  return `${appPid}:${id}`;
}

export function getAnonymousNspId(appPid: string, id: string): string {
  return `${appPid}:${NSP_ANONYMOUS_ID}${id}`;
}
