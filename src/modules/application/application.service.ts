import * as repository from './application.repository';
import PgClient from 'serverless-postgres';
import { Logger } from 'winston';

export async function getApplicationUserByEmail(
  logger: Logger,
  pgClient: PgClient,
  email: string
): Promise<any> {
  logger.debug(`Getting application user by email`);

  const { rows } = await repository.getApplicationUserByEmail(pgClient, email);

  return rows[0];
}

export async function registerApplicationUser(
  logger: Logger,
  pgClient: PgClient,
  email: string
): Promise<void> {
  logger.debug(`Registering application user`);
}
