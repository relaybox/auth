import PgClient from 'serverless-postgres';
import { Logger } from 'winston';
import {
  getPermissionsByKeyId,
  getTokenValidationCredentialsByKeyId
} from './validation.repository';
import { nanoid } from 'nanoid';

const NSP_ANONYMOUS_ID = '__a__';

export async function getTokenValidationCredentials(
  logger: Logger,
  pgClient: PgClient,
  keyId: string
): Promise<{ secretKey: string; orgId: string; appId: string }> {
  logger.debug(`Getting token validation credentials`, { keyId });

  const { rows } = await getTokenValidationCredentialsByKeyId(pgClient, keyId);

  if (!rows.length) {
    throw new Error('Validation credentials not found');
  }

  return rows[0];
}

export async function getPermissions(
  logger: Logger,
  pgClient: PgClient,
  keyId: string,
  inlinePermissions: any = {}
): Promise<Record<string, string[]> | string[]> {
  logger.debug(`Getting permissions for key`, { keyId });

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
  logger.debug(`Getting credentials for auth`, { appPid, clientId, connectionId });

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

export function getUserClientId(clientId: string): string {
  return clientId.split(':')[1];
}
