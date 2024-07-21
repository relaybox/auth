import { APIGatewayProxyResult } from 'aws-lambda';

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
