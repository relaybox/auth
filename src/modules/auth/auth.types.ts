export interface User {
  id: string;
  sub: string;
  username: string;
  lastOnline: Date;
  anonymous: boolean;
  expires: Date;
  confirmed: Date;
  createdAt: Date;
  verified: Date;
  authComplete: Date;
  avatar: number;
  mfaEnabled: boolean;
  pricingPlan: number;
}
