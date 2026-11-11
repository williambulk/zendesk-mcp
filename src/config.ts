import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigurationError, PolicyViolationError } from "./errors.js";
import { LogLevel } from "./logger.js";
import { validateSubdomain } from "./security.js";

export type OAuthGrantMode = "authorization_code" | "client_credentials";
export type McpTransportMode = "stdio" | "http";

export interface ZendeskMcpConfig {
  subdomain: string;
  oauthClientId: string;
  oauthClientSecret?: string;
  oauthGrantType: OAuthGrantMode;
  oauthRedirectUri: string;
  oauthScopes: string[];
  tokenFilePath: string;
  requestTimeoutMs: number;
  maxRetries: number;
  maxRetryAfterMs: number;
  maxConcurrentRequests: number;
  maxBodyChars: number;
  enableUserTool: boolean;
  resolveCustomFields: boolean;
  logLevel: LogLevel;
  transport: McpTransportMode;
  httpHost: string;
  httpPort: number;
  httpBearerToken?: string;
}

const ALLOWED_READ_SCOPES = new Set([
  "tickets:read",
  "users:read",
  "organizations:read",
]);

export function validateOAuthScopes(rawScopes: string | string[]): string[] {
  const tokens = (Array.isArray(rawScopes) ? rawScopes.join(" ") : rawScopes)
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  if (tokens.length === 0) {
    throw new ConfigurationError(
      "At least one read-only OAuth scope is required (e.g. 'tickets:read')."
    );
  }

  for (const scope of tokens) {
    if (
      scope === "write" ||
      scope === "read" ||
      scope === "impersonate" ||
      scope.endsWith(":write") ||
      !ALLOWED_READ_SCOPES.has(scope)
    ) {
      throw new PolicyViolationError(
        "INVALID_OAUTH_SCOPE",
        `OAuth scope "${scope}" is not permitted. Only narrow read-only scopes (${Array.from(
          ALLOWED_READ_SCOPES
        ).join(", ")}) are allowed.`
      );
    }
  }

  if (!tokens.includes("tickets:read")) {
    throw new ConfigurationError(
      "OAuth scopes must include 'tickets:read' for Zendesk ticket tools."
    );
  }

  return Array.from(new Set(tokens));
}

export function parseEnvFileContent(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eqIndex = line.indexOf("=");
    if (eqIndex <= 0) continue;
    const key = line.slice(0, eqIndex).trim();
    let value = line.slice(eqIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

function loadFallbackEnvFiles(env: NodeJS.ProcessEnv): Record<string, string> {
  const merged: Record<string, string> = {};
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const parentCandidate = path.resolve(moduleDir, "..");
  const repoRootCandidate = path.resolve(moduleDir, "../..");

  const candidates = [
    path.join(repoRootCandidate, ".env"),
    path.join(parentCandidate, ".env"),
    path.join(process.cwd(), ".env"),
    path.join(os.homedir(), ".config", "zendesk-mcp", ".env"),
  ];
  if (env.ZENDESK_ENV_FILE) {
    candidates.push(path.resolve(env.ZENDESK_ENV_FILE));
  }

  for (const filePath of candidates) {
    try {
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const parsed = parseEnvFileContent(fs.readFileSync(filePath, "utf8"));
        Object.assign(merged, parsed);
      }
    } catch {
      // Ignore unreadable fallback files
    }
  }
  return merged;
}

function parseBoundedInt(
  rawValue: string | undefined,
  defaultValue: number,
  min: number,
  max: number,
  name: string
): number {
  if (rawValue === undefined || rawValue.trim() === "") {
    return defaultValue;
  }
  const num = Number(rawValue);
  if (!Number.isInteger(num) || num < min || num > max) {
    throw new ConfigurationError(
      `${name} must be an integer between ${min} and ${max} (got "${rawValue}").`
    );
  }
  return num;
}

function parseBoolean(
  rawValue: string | undefined,
  defaultValue: boolean
): boolean {
  if (rawValue === undefined || rawValue.trim() === "") {
    return defaultValue;
  }
  const normalized = rawValue.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new ConfigurationError(`Invalid boolean value "${rawValue}".`);
}

export function loadConfig(
  overrides: Partial<ZendeskMcpConfig> = {},
  env: NodeJS.ProcessEnv = process.env
): ZendeskMcpConfig {
  const fileEnv = loadFallbackEnvFiles(env);
  const get = (key: string): string | undefined => env[key] ?? fileEnv[key];

  const rawSubdomain = overrides.subdomain ?? get("ZENDESK_SUBDOMAIN");
  if (!rawSubdomain) {
    throw new ConfigurationError(
      "ZENDESK_SUBDOMAIN is required (e.g. ZENDESK_SUBDOMAIN=acme)."
    );
  }
  const subdomain = validateSubdomain(rawSubdomain);

  const oauthClientId = (
    overrides.oauthClientId ??
    get("ZENDESK_OAUTH_CLIENT_ID") ??
    ""
  ).trim();
  if (!oauthClientId) {
    throw new ConfigurationError(
      "ZENDESK_OAUTH_CLIENT_ID is required. Register an OAuth client in Zendesk Admin Center and set its unique identifier."
    );
  }

  const oauthClientSecret =
    (
      overrides.oauthClientSecret ??
      get("ZENDESK_OAUTH_CLIENT_SECRET") ??
      ""
    ).trim() || undefined;

  const rawGrantType = (
    overrides.oauthGrantType ??
    get("ZENDESK_OAUTH_GRANT_TYPE") ??
    "authorization_code"
  )
    .trim()
    .toLowerCase();

  if (
    rawGrantType !== "authorization_code" &&
    rawGrantType !== "client_credentials"
  ) {
    throw new ConfigurationError(
      `ZENDESK_OAUTH_GRANT_TYPE must be "authorization_code" or "client_credentials" (got "${rawGrantType}").`
    );
  }

  if (rawGrantType === "client_credentials" && !oauthClientSecret) {
    throw new ConfigurationError(
      "ZENDESK_OAUTH_CLIENT_SECRET is required when ZENDESK_OAUTH_GRANT_TYPE=client_credentials."
    );
  }

  const oauthRedirectUri = (
    overrides.oauthRedirectUri ??
    get("ZENDESK_OAUTH_REDIRECT_URI") ??
    "http://127.0.0.1:18492/callback"
  ).trim();

  // Validate redirect URI is loopback http or https
  try {
    const parsedRedirect = new URL(oauthRedirectUri);
    const isLoopback =
      parsedRedirect.hostname === "127.0.0.1" ||
      parsedRedirect.hostname === "localhost" ||
      parsedRedirect.hostname === "[::1]";
    if (
      parsedRedirect.protocol !== "https:" &&
      !(parsedRedirect.protocol === "http:" && isLoopback)
    ) {
      throw new ConfigurationError(
        `ZENDESK_OAUTH_REDIRECT_URI must use https: or loopback http://127.0.0.1 (got "${oauthRedirectUri}").`
      );
    }
  } catch (err) {
    if (err instanceof ConfigurationError) throw err;
    throw new ConfigurationError(
      `Invalid ZENDESK_OAUTH_REDIRECT_URI: "${oauthRedirectUri}".`
    );
  }

  const oauthScopes = validateOAuthScopes(
    overrides.oauthScopes ??
      get("ZENDESK_OAUTH_SCOPES") ??
      "tickets:read users:read"
  );

  const defaultTokenFile = path.join(
    os.homedir(),
    ".config",
    "zendesk-mcp",
    "tokens.json"
  );
  const rawTokenFile =
    overrides.tokenFilePath ?? get("ZENDESK_TOKEN_FILE") ?? defaultTokenFile;
  const tokenFilePath = path.resolve(
    rawTokenFile.startsWith("~/")
      ? path.join(os.homedir(), rawTokenFile.slice(2))
      : rawTokenFile
  );

  const requestTimeoutMs =
    overrides.requestTimeoutMs ??
    parseBoundedInt(
      get("ZENDESK_REQUEST_TIMEOUT_MS"),
      15000,
      1000,
      60000,
      "ZENDESK_REQUEST_TIMEOUT_MS"
    );

  const maxRetries =
    overrides.maxRetries ??
    parseBoundedInt(
      get("ZENDESK_MAX_RETRIES"),
      3,
      0,
      5,
      "ZENDESK_MAX_RETRIES"
    );

  const maxRetryAfterMs =
    overrides.maxRetryAfterMs ??
    parseBoundedInt(
      get("ZENDESK_MAX_RETRY_AFTER_MS"),
      30000,
      1000,
      120000,
      "ZENDESK_MAX_RETRY_AFTER_MS"
    );

  const maxConcurrentRequests =
    overrides.maxConcurrentRequests ??
    parseBoundedInt(
      get("ZENDESK_MAX_CONCURRENT_REQUESTS"),
      4,
      1,
      16,
      "ZENDESK_MAX_CONCURRENT_REQUESTS"
    );

  const maxBodyChars =
    overrides.maxBodyChars ??
    parseBoundedInt(
      get("ZENDESK_MAX_BODY_CHARS"),
      16000,
      500,
      100000,
      "ZENDESK_MAX_BODY_CHARS"
    );

  const enableUserTool =
    overrides.enableUserTool ??
    parseBoolean(get("ZENDESK_ENABLE_USER_TOOL"), true);

  const resolveCustomFields =
    overrides.resolveCustomFields ??
    parseBoolean(get("ZENDESK_RESOLVE_CUSTOM_FIELDS"), true);

  const rawLogLevel = (
    overrides.logLevel ??
    get("ZENDESK_LOG_LEVEL") ??
    "info"
  )
    .trim()
    .toLowerCase() as LogLevel;
  const validLogLevels: Set<LogLevel> = new Set([
    "debug",
    "info",
    "warn",
    "error",
    "silent",
  ]);
  const logLevel: LogLevel = validLogLevels.has(rawLogLevel)
    ? rawLogLevel
    : "info";

  const rawTransport = (
    overrides.transport ??
    get("MCP_TRANSPORT") ??
    "stdio"
  )
    .trim()
    .toLowerCase();
  if (rawTransport !== "stdio" && rawTransport !== "http") {
    throw new ConfigurationError(
      `MCP_TRANSPORT must be "stdio" or "http" (got "${rawTransport}").`
    );
  }

  const httpHost = (
    overrides.httpHost ??
    get("MCP_HTTP_HOST") ??
    "127.0.0.1"
  ).trim();
  const httpPort =
    overrides.httpPort ??
    parseBoundedInt(get("MCP_HTTP_PORT"), 3849, 1, 65535, "MCP_HTTP_PORT");

  const httpBearerToken =
    (
      overrides.httpBearerToken ??
      get("MCP_HTTP_BEARER_TOKEN") ??
      ""
    ).trim() || undefined;

  if (rawTransport === "http") {
    if (!httpBearerToken || httpBearerToken.length < 16) {
      throw new ConfigurationError(
        "MCP_HTTP_BEARER_TOKEN (minimum 16 characters) is required when MCP_TRANSPORT=http to authenticate MCP clients separately from Zendesk OAuth."
      );
    }
  }

  return {
    subdomain,
    oauthClientId,
    oauthClientSecret,
    oauthGrantType: rawGrantType,
    oauthRedirectUri,
    oauthScopes,
    tokenFilePath,
    requestTimeoutMs,
    maxRetries,
    maxRetryAfterMs,
    maxConcurrentRequests,
    maxBodyChars,
    enableUserTool,
    resolveCustomFields,
    logLevel,
    transport: rawTransport,
    httpHost,
    httpPort,
    httpBearerToken,
  };
}
