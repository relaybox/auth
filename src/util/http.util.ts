import { APIGatewayProxyResult } from 'aws-lambda';
import {
  AuthConflictError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
  ValidationError
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
  logger.error(`Error response`, { err });

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

  return _500({ message: err.message });
}
