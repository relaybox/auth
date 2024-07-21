import winston from 'winston';

enum LogLevel {
  LOG = 'log',
  INFO = 'info',
  WARN = 'warn',
  DEBUG = 'debug'
}

const easyLogFormat = winston.format.printf((info) => {
  const { level, service, message, ...rest } = info;

  const values = [];

  for (const key of Object.keys(rest)) {
    if (typeof rest[key] === 'string') {
      values.push(`${key}: ${rest[key]}`);
    }
  }

  return `[${level}]:${new Date().toISOString().slice(11)} ${service} - ${message}`;
});

const customLogFormat = winston.format.printf((info) => {
  const { level, ...rest } = info;

  const logDetails = JSON.stringify(rest, null, 4);

  return `[${level}]: ${logDetails}`;
});

const prettyPrint = new winston.transports.Console({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.colorize(),
    customLogFormat
  )
});

const easyPrint = new winston.transports.Console({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.colorize(),
    easyLogFormat
  )
});

const flatPrint = new winston.transports.Console();

const transports = process.env.LOCALHOST === 'true' ? [easyPrint] : [flatPrint];

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || LogLevel.INFO,
  transports
});

// logger.transports[0].silent = true;

export function getLogger(service: string) {
  return logger.child({ service });
}
