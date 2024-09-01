import { JwtPayload } from 'jsonwebtoken';

export interface ExtendedJwtPayload extends JwtPayload {
  grant?: string;
  email_verified?: string;
}

export interface ExtendedClientJwtPayload extends JwtPayload {
  keyName: string;
  clientId?: string | string[];
  timestamp: string;
}

export enum TokenType {
  ID_TOKEN = 'id_token',
  REFRESH_TOKEN = 'refresh_token',
  TMP_TOKEN = 'tmp_token'
}

export interface ClientJwtPayload extends JwtPayload {
  keyName: string;
  clientId?: string | string[];
  tokenType: string;
  timestamp: string;
}

export interface TmpSessionJwtPayload extends JwtPayload {
  tokenType: string;
}
