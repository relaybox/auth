import winston from 'winston';

enum LogLevel {
  LOG = 'log',
  INFO = 'info',
  WARN = 'warn',
  DEBUG = 'debug'
}

const easyLogFormat = winston.format.printf((info) => {
  const { level, service, message } = info;

  let baseLog = `[${level}]:${new Date().toISOString().slice(11)} ${service} - ${message}`;

  if (info.err && info.err.stack) {
    baseLog += `\n${info.err.stack}`;
  }

  return baseLog;
});

const easyPrint = new winston.transports.Console({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  format: winston.format.combine(
    winston.format.errors({ stack: true }),
    winston.format.timestamp(),
    winston.format.colorize(),
    easyLogFormat
  )
});

const flatPrint = new winston.transports.Console({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }) // Ensures stack trace is captured
  )
});

const transports = process.env.LOCALHOST === 'true' ? [easyPrint] : [flatPrint];

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  transports
});

// logger.transports[0].silent = true;

export function getLogger(service: string) {
  return logger.child({ service });
}
