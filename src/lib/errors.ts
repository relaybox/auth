export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class DuplicateKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DuplicateKeyError';
  }
}

export class AuthConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthConflictError';
  }
}

export class PricingPlanQuotaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PricingPlanQuotaError';
  }
}

export class NetworkError extends Error {
  public status: number;

  constructor(message: string, status?: any) {
    super(message);
    this.status = status;
    this.name = 'NetworkError';
  }
}

export class AuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationError';

    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, this.constructor);
    } else {
      this.stack = new Error(message).stack;
    }
  }
}

export class TokenError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'TokenError';
  }
}

export class VerificationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'VerificationError';
  }
}

export class SchemaValidationError extends Error {
  public data?: any;

  constructor(message: string, data?: any) {
    super(message);
    this.name = 'SchemaValidationError';
    this.data = data;
  }
}

export class AuthenticationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'AuthenticationError';
  }
}
