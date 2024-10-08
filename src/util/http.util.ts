import { APIGatewayProxyResult } from 'aws-lambda';
import {
  AuthConflictError,
  AuthenticationError,
  DuplicateKeyError,
  ForbiddenError,
  NotFoundError,
  PasswordRegexError,
  SchemaValidationError,
  TokenError,
  TokenExpiredError,
  UnauthorizedError,
  ValidationError,
  VerificationError
} from '../lib/errors';
import { Logger } from 'winston';

const defaultHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Credentials': true
};

export function _200(body?: any, headers: any = {}): APIGatewayProxyResult {
  const responseheaders = {
    ...defaultHeaders,
    ...headers
  };

  return {
    statusCode: 200,
    headers: responseheaders,
    body: JSON.stringify(body)
  };
}

export function _400(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 400,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _500(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 500,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _403(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 403,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _404(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 404,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _401(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 401,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _422(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 422,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function _409(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 409,
    headers: defaultHeaders,
    body: JSON.stringify(body)
  };
}

export function handleErrorResponse(logger: Logger, err: any): APIGatewayProxyResult {
  logger.warn(`Error response`, { err });

  if (err instanceof SchemaValidationError) {
    return _400({
      ...err,
      message: err.message
    });
  }

  const errorResponse = {
    name: err.name,
    message: err.message
  };

  if (err instanceof ValidationError || err.message.includes('duplicate key')) {
    return _400(errorResponse);
  }

  if (err instanceof AuthenticationError) {
    return _401(errorResponse);
  }

  if (err instanceof UnauthorizedError) {
    return _401(errorResponse);
  }

  if (err instanceof ForbiddenError) {
    return _403(errorResponse);
  }

  if (err instanceof NotFoundError) {
    return _404(errorResponse);
  }

  if (err instanceof AuthConflictError) {
    return _409(errorResponse);
  }

  if (err instanceof DuplicateKeyError) {
    return _409(errorResponse);
  }

  if (err instanceof VerificationError) {
    return _403(errorResponse);
  }

  if (err instanceof TokenError || err instanceof TokenExpiredError) {
    return _403(errorResponse);
  }

  if (err instanceof PasswordRegexError) {
    return _400(errorResponse);
  }

  logger.error(`Unknown internal error`, { err });

  return _500(errorResponse);
}

export function redirect(
  logger: Logger,
  requestUrl: string,
  queryParams?: Record<string, string>,
  rawQueryparams?: boolean
): APIGatewayProxyResult {
  logger.info(`Redirecting to ${requestUrl}`);

  if (queryParams) {
    const urlQueryParams = !rawQueryparams
      ? new URLSearchParams(queryParams).toString()
      : Object.entries(queryParams)
          .map(([key, value]) => `${key}=${value}`)
          .join('&');

    requestUrl = `${requestUrl}?${urlQueryParams}`;
  }

  return {
    statusCode: 302,
    headers: {
      Location: requestUrl
    },
    body: ''
  };
}
