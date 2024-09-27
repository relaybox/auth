import { AuthUserSession } from '@/types/auth.types';
import PgClient from 'serverless-postgres';
import { request } from './request';
import { getVerificationCode } from '../db/helpers';

interface CreateUserResponse {
  message: string;
  id: string;
  clientId: string;
}

export async function runAuthenticationFlow(
  pgClient: PgClient,
  email: string,
  password: string,
  headers: Record<string, string>,
  verify = true
): Promise<AuthUserSession | CreateUserResponse> {
  const { data: userRegistrationResponse } = await request<CreateUserResponse>('/users/create', {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, password })
  });

  if (!verify) {
    return userRegistrationResponse;
  }

  const code = await getVerificationCode(pgClient, userRegistrationResponse.id);

  await request('/users/verify', {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, code })
  });

  const { data } = await request<AuthUserSession>('/users/authenticate', {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, password })
  });

  return data;
}
