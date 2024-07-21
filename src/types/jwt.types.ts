import { JwtPayload } from 'jsonwebtoken';

export interface ExtendedJwtPayload extends JwtPayload {
  grant?: string;
  email_verified?: string;
}
