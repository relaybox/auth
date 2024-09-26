import PgClient from 'serverless-postgres';
import { AuthUser, AuthUserSession } from '@/types/auth.types';
import { registerUser } from '@/modules/users/users.actions';
import { Logger } from 'winston';
import { getUserDataByClientId } from '@/modules/users/users.service';

export class User {
  authUserSession: AuthUserSession | undefined;
  userData: AuthUser;
  pgClient: PgClient;
  logger: Logger;
  orgId: string;
  appId: string;
  publicKey: string;

  constructor(logger: Logger, pgClient: PgClient, orgId: string, appId: string, publicKey: string) {
    this.pgClient = pgClient;
    this.logger = logger;
    this.orgId = orgId;
    this.appId = appId;
    this.publicKey = publicKey;
  }

  async register(email: string, password: string) {
    const { clientId } = await registerUser(
      this.logger,
      this.pgClient,
      this.orgId,
      this.appId,
      email,
      password
    );

    return getUserDataByClientId(this.logger, this.pgClient, this.appId, clientId);
  }

  authenticate(email: string, password: string) {}
}
