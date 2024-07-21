export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn'
}

export interface GuardOptions {
  matchUidParam?: string;
  confirmed?: boolean;
  verified?: boolean;
}
