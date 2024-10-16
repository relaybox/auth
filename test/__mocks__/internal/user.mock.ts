import { generateUsername } from '@/modules/users/users.service';
import { AuthProvider } from '@/types/auth.types';
import { nanoid } from 'nanoid';
import { v4 as uuid } from 'uuid';

export function getAuthUser() {
  const id = uuid();
  const orgId = uuid();
  const appId = uuid();
  const clientId = nanoid(12);
  const username = generateUsername();
  const now = new Date().toISOString();
  const identityProviders = [AuthProvider.EMAIL, AuthProvider.GOOGLE, AuthProvider.GITHUB];

  return {
    id,
    orgId,
    appId,
    username,
    clientId,
    email: 'test@user.com',
    createdAt: now,
    updatedAt: now,
    verifiedAt: now,
    authMfaEnabled: false,
    blockedAt: null,
    firstName: null,
    lastName: null,
    identities: identityProviders.map((provider) => ({
      id: uuid(),
      provider,
      providerId: Math.random().toString(36),
      verifiedAt: now
    })),
    factors: []
  };
}
