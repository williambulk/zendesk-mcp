import { ConfigurationError, PolicyViolationError } from "./errors.js";

const SUBDOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const ALLOWLISTED_GET_PATH_PATTERNS: readonly RegExp[] = [
  /^\/api\/v2\/tickets\/[1-9]\d*\.json$/,
  /^\/api\/v2\/tickets\/[1-9]\d*\/comments\.json$/,
  /^\/api\/v2\/ticket_fields\.json$/,
  /^\/api\/v2\/search\.json$/,
  /^\/api\/v2\/users\/(?:me|[1-9]\d*)\.json$/,
  /^\/api\/v2\/attachments\/[1-9]\d*\.json$/,
];

const OAUTH_GRANT_PATH = "/oauth/tokens";
const DEPRECATED_OAUTH_PATH_PREFIX = "/api/v2/oauth/tokens";

export function validateSubdomain(rawSubdomain: string): string {
  const normalized = rawSubdomain.trim().toLowerCase();
  if (!normalized || !SUBDOMAIN_REGEX.test(normalized)) {
    throw new ConfigurationError(
      `Invalid Zendesk subdomain "${rawSubdomain}". Expected a single DNS label such as "acme" (letters, digits, hyphens only).`
    );
  }
  return normalized;
}

export function getTenantOrigin(subdomain: string): string {
  const valid = validateSubdomain(subdomain);
  return `https://${valid}.zendesk.com`;
}

/**
 * Parses a ticket identifier from either a positive integer, a numeric string (optionally prefixed with #),
 * or an exact configured-tenant Zendesk ticket URL.
 */
export function parseTicketIdentifier(
  input: number | string,
  expectedSubdomain: string
): number {
  const validSubdomain = validateSubdomain(expectedSubdomain);

  if (typeof input === "number") {
    if (!Number.isSafeInteger(input) || input <= 0) {
      throw new PolicyViolationError(
        "INVALID_TICKET_ID",
        `Ticket ID must be a positive integer, got: ${String(input)}`
      );
    }
    return input;
  }

  const trimmed = input.trim();
  if (!trimmed) {
    throw new PolicyViolationError("INVALID_TICKET_ID", "Ticket ID cannot be empty.");
  }

  // Direct numeric ID or #12345
  const directMatch = /^#?([1-9]\d*)$/.exec(trimmed);
  if (directMatch) {
    const parsed = Number(directMatch[1]);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      throw new PolicyViolationError(
        "INVALID_TICKET_ID",
        `Ticket ID out of safe integer range: ${trimmed}`
      );
    }
    return parsed;
  }

  // Must be an exact configured-tenant URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(trimmed);
  } catch {
    throw new PolicyViolationError(
      "INVALID_TICKET_ID",
      `Invalid ticket identifier or URL: "${trimmed}". Provide a positive ticket ID or an exact https://${validSubdomain}.zendesk.com/agent/tickets/{id} URL.`
    );
  }

  if (parsedUrl.protocol !== "https:") {
    throw new PolicyViolationError(
      "UNTRUSTED_TICKET_URL",
      `Ticket URL must use https: protocol (received "${parsedUrl.protocol}").`
    );
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new PolicyViolationError(
      "UNTRUSTED_TICKET_URL",
      "Ticket URL must not contain embedded credentials."
    );
  }

  const expectedHost = `${validSubdomain}.zendesk.com`;
  if (parsedUrl.hostname.toLowerCase() !== expectedHost || parsedUrl.port !== "") {
    throw new PolicyViolationError(
      "CROSS_TENANT_URL",
      `Ticket URL host "${parsedUrl.host}" does not match configured tenant "${expectedHost}".`
    );
  }

  const rawPath = parsedUrl.pathname;
  if (
    rawPath.includes("..") ||
    rawPath.includes("\\") ||
    /%2e|%2f|%5c/i.test(rawPath)
  ) {
    throw new PolicyViolationError(
      "UNTRUSTED_TICKET_URL",
      "Ticket URL contains disallowed path sequences."
    );
  }

  const pathMatch =
    /^\/(?:agent\/tickets|api\/v2\/tickets|hc\/[a-z0-9-]+\/requests|tickets)\/([1-9]\d*)(?:\.json)?\/?$/i.exec(
      rawPath
    );
  if (!pathMatch) {
    throw new PolicyViolationError(
      "UNTRUSTED_TICKET_URL",
      `Unrecognized Zendesk ticket URL path "${rawPath}". Expected /agent/tickets/{id}.`
    );
  }

  const id = Number(pathMatch[1]);
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new PolicyViolationError(
      "INVALID_TICKET_ID",
      `Parsed ticket ID out of safe integer range: ${pathMatch[1]}`
    );
  }

  return id;
}

/**
 * Enforces tenant pinning, HTTP method policy, and route allowlisting before any network call is made.
 */
export function validateOutboundRequest(
  requestUrl: string | URL,
  method: string,
  expectedSubdomain: string
): URL {
  const validSubdomain = validateSubdomain(expectedSubdomain);
  const expectedHost = `${validSubdomain}.zendesk.com`;
  const normalizedMethod = method.trim().toUpperCase();

  const url =
    typeof requestUrl === "string" ? new URL(requestUrl) : new URL(requestUrl.toString());

  if (url.protocol !== "https:") {
    throw new PolicyViolationError(
      "INSECURE_PROTOCOL",
      `Refusing non-HTTPS outbound request to "${url.protocol}//${url.host}".`
    );
  }

  if (url.username || url.password) {
    throw new PolicyViolationError(
      "EMBEDDED_CREDENTIALS",
      "Refusing outbound request with embedded URL credentials."
    );
  }

  if (url.hostname.toLowerCase() !== expectedHost || url.port !== "") {
    throw new PolicyViolationError(
      "TENANT_MISMATCH",
      `Refusing outbound request to "${url.host}"; pinned tenant is "${expectedHost}".`
    );
  }

  const pathname = url.pathname;
  if (
    pathname.includes("..") ||
    pathname.includes("//") ||
    pathname.includes("\\") ||
    /%2e|%2f|%5c/i.test(pathname)
  ) {
    throw new PolicyViolationError(
      "PATH_TRAVERSAL",
      `Refusing outbound request with suspicious path "${pathname}".`
    );
  }

  if (pathname.startsWith(DEPRECATED_OAUTH_PATH_PREFIX)) {
    throw new PolicyViolationError(
      "DEPRECATED_OAUTH_ENDPOINT",
      "The legacy /api/v2/oauth/tokens endpoint is deprecated and disallowed. Use POST /oauth/tokens."
    );
  }

  // Narrow POST exception for OAuth token grant / refresh
  if (pathname === OAUTH_GRANT_PATH) {
    if (normalizedMethod !== "POST") {
      throw new PolicyViolationError(
        "METHOD_NOT_ALLOWED",
        `OAuth grant endpoint ${OAUTH_GRANT_PATH} only allows POST (attempted ${normalizedMethod}).`
      );
    }
    if (url.search !== "") {
      throw new PolicyViolationError(
        "INVALID_OAUTH_REQUEST",
        "OAuth grant endpoint must not include query string parameters."
      );
    }
    return url;
  }

  // All business API routes are strictly GET-only
  if (normalizedMethod !== "GET") {
    throw new PolicyViolationError(
      "READ_ONLY_POLICY",
      `Zendesk MCP is strictly read-only. HTTP ${normalizedMethod} to "${pathname}" is prohibited.`
    );
  }

  const isAllowlisted = ALLOWLISTED_GET_PATH_PATTERNS.some((pattern) =>
    pattern.test(pathname)
  );
  if (!isAllowlisted) {
    throw new PolicyViolationError(
      "ROUTE_NOT_ALLOWLISTED",
      `Outbound route "${pathname}" is not in the Zendesk MCP read-only allowlist.`
    );
  }

  return url;
}

/**
 * Enforces `type:ticket` on Zendesk search queries and blocks attempts to query other object types.
 */
export function enforceTicketSearchQuery(rawQuery: string): string {
  const trimmed = rawQuery.trim();
  if (!trimmed) {
    throw new PolicyViolationError(
      "INVALID_SEARCH_QUERY",
      "Search query cannot be empty."
    );
  }

  // Detect any `type:something` or `-type:something` tokens
  const typeTokens = trimmed.match(/(?:^|\s)-?type:([^\s]+)/gi) ?? [];
  for (const token of typeTokens) {
    const cleaned = token.trim().toLowerCase();
    if (cleaned.startsWith("-type:")) {
      throw new PolicyViolationError(
        "SEARCH_TYPE_POLICY",
        `Negating type filter ("${token.trim()}") is prohibited; searches are restricted to type:ticket.`
      );
    }
    const value = cleaned.slice("type:".length);
    if (value !== "ticket") {
      throw new PolicyViolationError(
        "SEARCH_TYPE_POLICY",
        `Searching non-ticket type "type:${value}" is prohibited; only type:ticket is allowed.`
      );
    }
  }

  // Strip existing type:ticket tokens so we can place a canonical leading `type:ticket`
  const withoutTypeTicket = trimmed
    .replace(/(?:^|\s)type:ticket(?=\s|$)/gi, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!withoutTypeTicket) {
    throw new PolicyViolationError(
      "INVALID_SEARCH_QUERY",
      "Search query must contain search terms or filters in addition to type:ticket."
    );
  }

  return `type:ticket ${withoutTypeTicket}`;
}

/**
 * Converts HTML to plain text safely when plain_body is unavailable.
 */
export function stripHtmlToText(html: string): string {
  if (!html) return "";
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export interface BoundedTextResult {
  text: string;
  truncated: boolean;
  originalLength: number;
}

export function boundPlainText(
  input: string | null | undefined,
  maxChars: number
): BoundedTextResult {
  const safe = (input ?? "").replace(/\r\n/g, "\n");
  const originalLength = safe.length;
  if (originalLength <= maxChars) {
    return { text: safe, truncated: false, originalLength };
  }
  return {
    text: `${safe.slice(0, maxChars)}\n...[TRUNCATED: showing ${maxChars} of ${originalLength} characters]`,
    truncated: true,
    originalLength,
  };
}

export function sanitizeFileName(rawName: string | null | undefined): string {
  const fallback = "unnamed_attachment";
  if (!rawName) return fallback;
  const cleaned = rawName
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[/\\]+/g, "_")
    .replace(/\.\.+/g, ".")
    .trim();
  return cleaned || fallback;
}

export interface InspectedAttachmentUrl {
  contentUrl: string | null;
  isExternalUrl: boolean;
  securityNote: string;
}

export function inspectAttachmentUrl(
  rawUrl: string | null | undefined,
  expectedSubdomain: string
): InspectedAttachmentUrl {
  if (!rawUrl) {
    return {
      contentUrl: null,
      isExternalUrl: false,
      securityNote: "No content URL provided.",
    };
  }

  const validSubdomain = validateSubdomain(expectedSubdomain);
  const expectedHost = `${validSubdomain}.zendesk.com`;

  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:") {
      return {
        contentUrl: null,
        isExternalUrl: true,
        securityNote: `Blocked non-HTTPS attachment URL (${parsed.protocol}).`,
      };
    }
    const host = parsed.hostname.toLowerCase();
    const isTenantHost = host === expectedHost;
    // Strip any query token from display if needed? Wait: Zendesk attachment content_urls may have `?name=...` or token;
    // we keep the URL metadata as returned by Zendesk but explicitly warn if external and never forward credentials.
    return {
      contentUrl: parsed.toString(),
      isExternalUrl: !isTenantHost,
      securityNote: isTenantHost
        ? "Tenant-hosted attachment URL. Do not fetch automatically without operator authorization."
        : `EXTERNAL attachment host (${host}). Never forward Zendesk OAuth credentials to this URL.`,
    };
  } catch {
    return {
      contentUrl: null,
      isExternalUrl: true,
      securityNote: "Malformed attachment content URL omitted for safety.",
    };
  }
}

const SECRET_JSON_KEY_PATTERN =
  /("(?:access_token|refresh_token|client_secret|code|code_verifier|authorization|bearer)"\s*:\s*")([^"]*)(")/gi;

const SECRET_QUERY_PARAM_PATTERN =
  /([?&](?:access_token|refresh_token|client_secret|code|code_verifier|token)=)([^&#\s"']+)/gi;

const BEARER_TOKEN_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi;

/**
 * Redacts sensitive tokens, secrets, and authorization values from any string before logging or surfacing errors.
 */
export function redactSecrets(
  text: string,
  knownSecrets: readonly (string | undefined)[] = []
): string {
  if (!text) return text;
  let output = text
    .replace(SECRET_JSON_KEY_PATTERN, "$1[REDACTED]$3")
    .replace(SECRET_QUERY_PARAM_PATTERN, "$1[REDACTED]")
    .replace(BEARER_TOKEN_PATTERN, "$1[REDACTED]");

  for (const secret of knownSecrets) {
    if (secret && secret.trim().length >= 4) {
      output = output.split(secret.trim()).join("[REDACTED]");
    }
  }
  return output;
}
