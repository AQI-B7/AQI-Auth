import type { ApiErrorShape } from './types';

export class AuthServiceApiError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly requestId?: string;
  readonly retryAfterSeconds?: number;

  constructor(shape: ApiErrorShape) {
    super(Array.isArray(shape.message) ? shape.message.join('; ') : shape.message);
    this.name = 'AuthServiceApiError';
    this.statusCode = shape.statusCode;
    this.code = shape.code;
    this.requestId = shape.requestId;
    this.retryAfterSeconds = shape.retryAfterSeconds;
  }
}
