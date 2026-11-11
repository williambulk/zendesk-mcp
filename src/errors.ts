export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

export class PolicyViolationError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PolicyViolationError";
    this.code = code;
  }
}

export class ReauthorizationRequiredError extends Error {
  public readonly reason: string;
  constructor(reason: string, message?: string) {
    super(
      message ??
        `Zendesk OAuth authorization is required (${reason}). Run 'npm run auth' (or 'zendesk-mcp auth') on the host machine to complete OAuth authorization.`
    );
    this.name = "ReauthorizationRequiredError";
    this.reason = reason;
  }
}

export interface RateLimitMetadata {
  limit?: number;
  remaining?: number;
  resetSeconds?: number;
  retryAfterSeconds?: number;
}

export class ZendeskApiError extends Error {
  public readonly status: number;
  public readonly errorCode?: string;
  public readonly rateLimit?: RateLimitMetadata;

  constructor(
    status: number,
    message: string,
    options?: {
      errorCode?: string;
      rateLimit?: RateLimitMetadata;
    }
  ) {
    super(message);
    this.name = "ZendeskApiError";
    this.status = status;
    this.errorCode = options?.errorCode;
    this.rateLimit = options?.rateLimit;
  }
}

export class RateLimitExceededError extends ZendeskApiError {
  constructor(message: string, rateLimit?: RateLimitMetadata) {
    super(429, message, { errorCode: "rate_limit_exceeded", rateLimit });
    this.name = "RateLimitExceededError";
  }
}
