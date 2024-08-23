import { APIGatewayProxyEvent } from 'aws-lambda';
import { OAuthTokenCredentials } from 'src/types/auth.types';
import { ExtendedJwtPayload } from 'src/types/jwt.types';
import { Logger } from 'winston';
import PgClient from 'serverless-postgres';
import jwt from 'jsonwebtoken';
import { getUserById, getUserNameFromEmail } from '../auth/auth.service';
import * as repository from './idp.repository';
import { AuthConflictError } from 'src/lib/errors';
import { User } from '../auth/auth.types';
import parser from 'lambda-multipart-parser';
import { generateAuthHashId } from 'src/util/hash.util';

const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
const COGNITO_USER_POOL_DOMAIN = process.env.COGNITO_USER_POOL_DOMAIN || '';
const COGNITO_OAUTH_CALLBACK_URL = process.env.COGNITO_OAUTH_CALLBACK_URL || '';
const AUTH_HASH_ID_SECRET = process.env.AUTH_HASH_ID_SECRET || '';
const OAUTH_GRANT_TYPE_AUTH_CODE = 'authorization_code';

export async function getIdpAuthCredentials(
  logger: Logger,
  code: string
): Promise<OAuthTokenCredentials> {
  logger.debug(`Fetching auth credentials from cognito oauth token endpoint`);

  const basicAuth = `Basic ${Buffer.from(`${COGNITO_CLIENT_ID}:${COGNITO_CLIENT_SECRET}`).toString(
    'base64'
  )}`;

  const requestBody = new URLSearchParams({
    grant_type: OAUTH_GRANT_TYPE_AUTH_CODE,
    client_id: COGNITO_CLIENT_ID,
    code,
    redirect_uri: COGNITO_OAUTH_CALLBACK_URL
  });

  const response = await fetch(`${COGNITO_USER_POOL_DOMAIN}/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: basicAuth,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: requestBody.toString()
  });

  const data = await response.json();

  return <OAuthTokenCredentials>data;
}

export async function syncIdpUser(
  logger: Logger,
  pgClient: PgClient,
  idToken: string
): Promise<void> {
  logger.debug(`Syncing idp user to local database`);

  const {
    email,
    sub: id,
    identities,
    preferred_username: preferredUsername
  } = <ExtendedJwtPayload>jwt.decode(idToken);

  const hashId = generateAuthHashId(email!, AUTH_HASH_ID_SECRET);
  const username = preferredUsername || getUserNameFromEmail(email!);

  if (!id || !username || !hashId) {
    throw new Error(`Failed to parse user data from token`);
  }

  try {
    await repository.syncIdpUser(
      pgClient,
      id,
      username,
      hashId,
      <string>identities?.[0]?.providerName
    );
  } catch (err: any) {
    if (err.message.includes(`duplicate key`)) {
      throw new AuthConflictError(`Existing user found`);
    } else {
      throw err;
    }
  }
}

export async function getIdpUser(
  logger: Logger,
  pgClient: PgClient,
  idToken: string
): Promise<User> {
  logger.debug(`Getting idp user from local database`);

  const { sub: uid } = <ExtendedJwtPayload>jwt.decode(idToken);

  return getUserById(logger, pgClient, uid!);
}

export async function getGitHubAuthToken(
  logger: Logger,
  event: APIGatewayProxyEvent
): Promise<any> {
  logger.debug(`Exchanging auth code for GitHub access tokens`);

  try {
    const { client_id, client_secret, code } = await parser.parse(event);

    const queryParams = new URLSearchParams({
      client_id,
      client_secret,
      code
    });

    const requestUrl = `https://github.com/login/oauth/access_token?${queryParams}`;

    const response = await fetch(requestUrl, {
      method: 'POST',
      headers: {
        accept: 'application/json'
      }
    });

    const token = await response.json();

    return token;
  } catch (err: any) {
    logger.error(`Failed to get GitHub auth token`, { err });
    throw err;
  }
}

export async function getGitHubUserData(logger: Logger, authorization: string): Promise<any> {
  logger.debug(`Fetching GitHub user data`);

  try {
    const response = await fetch(`https://api.github.com/user`, {
      method: 'GET',
      headers: {
        authorization,
        accept: 'application/json'
      }
    });

    const userData = <any>await response.json();

    return userData;
  } catch (err: any) {
    logger.error(`Failed to fetch GitHub user data`, { err });
    throw err;
  }
}

export async function getGitHubUserPrimaryEmail(
  logger: Logger,
  authorization: string
): Promise<any> {
  logger.debug(`Fetching GitHub user email`);

  try {
    const response = await fetch(`https://api.github.com/user/emails`, {
      method: 'GET',
      headers: {
        authorization,
        accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    });

    const emailData = <any>await response.json();
    const primaryEmail = emailData.find((data: any) => data.primary);

    return primaryEmail.email;
  } catch (err: any) {
    logger.error(`Failed to fetch GitHub user primary email`, { err });
    throw err;
  }
}
