import { JwtPayload } from 'jsonwebtoken';

export interface ExtendedJwtPayload extends JwtPayload {
  grant?: string;
  email_verified?: string;
}

export interface ExtendedClientJwtPayload extends JwtPayload {
  keyName: string;
  clientId?: string | string[];
  timestamp: string;
  // permissions?: Permissions | Permission[];
}
