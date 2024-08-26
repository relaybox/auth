import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  AuthConflictError,
  DuplicateKeyError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
  ValidationError,
  VerificationError
} from '../lib/errors';
import { Logger } from 'winston';

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Credentials': true
};

export function _200(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify(body)
  };
}

export function _400(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 400,
    headers,
    body: JSON.stringify(body)
  };
}

export function _500(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 500,
    headers,
    body: JSON.stringify(body)
  };
}

export function _403(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 403,
    headers,
    body: JSON.stringify(body)
  };
}

export function _404(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 404,
    headers,
    body: JSON.stringify(body)
  };
}

export function _401(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 401,
    headers,
    body: JSON.stringify(body)
  };
}

export function _422(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 422,
    headers,
    body: JSON.stringify(body)
  };
}

export function _409(body?: any): APIGatewayProxyResult {
  return {
    statusCode: 409,
    headers,
    body: JSON.stringify(body)
  };
}

export function handleErrorResponse(logger: Logger, err: any): APIGatewayProxyResult {
  logger.warn(`Error response`, { err });

  if (err instanceof ValidationError || err.message.includes('duplicate key')) {
    return _400({ message: err.message });
  }

  if (err instanceof UnauthorizedError) {
    return _401({ message: err.message });
  }

  if (err instanceof ForbiddenError) {
    return _403({ message: err.message });
  }

  if (err instanceof NotFoundError) {
    return _404({ message: err.message });
  }

  if (err instanceof AuthConflictError) {
    return _409({ message: err.message });
  }

  if (err instanceof DuplicateKeyError) {
    return _409({ message: err.message });
  }

  if (err instanceof VerificationError) {
    return _403({ message: err.message });
  }

  logger.error(`Unknown internal error`, { err });

  return _500({ message: err.message });
}

export function redirect(
  logger: Logger,
  url: string,
  queryParams?: Record<string, string>
): APIGatewayProxyResult {
  logger.info(`Redirecting to ${url}`);

  const urlQueryParams = new URLSearchParams(queryParams);
  const requestUrl = `${url}?${urlQueryParams.toString()}&redirect_uri=http://localhost:4005/dev/users/idp/github/callback`;

  return {
    statusCode: 302,
    headers: {
      Location: requestUrl
    },
    body: ''
  };
}
