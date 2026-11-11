import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ZendeskMcpConfig, validateOAuthScopes } from "./config.js";
import {
  PolicyViolationError,
  ReauthorizationRequiredError,
  ZendeskApiError,
} from "./errors.js";
import { SafeLogger } from "./logger.js";
import {
  getTenantOrigin,
  redactSecrets,
  validateOutboundRequest,
} from "./security.js";

export interface StoredTokenSet {
  access_token: string;
  token_type: string;
  scope: string;
  refresh_token?: string;
  expires_in?: number;
  expires_at?: number;
  refresh_token_expires_in?: number;
  refresh_token_expires_at?: number;
  obtained_at: number;
  subdomain: string;
  grant_type: "authorization_code" | "client_credentials";
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

export function generatePkcePair(): PkcePair {
  const codeVerifier = crypto.randomBytes(48).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
  };
}

export function generateOAuthState(): string {
  return crypto.randomBytes(24).toString("base64url");
}

export function buildAuthorizationUrl(params: {
  subdomain: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  codeChallenge: string;
}): string {
  const validatedScopes = validateOAuthScopes(params.scopes);
  const origin = getTenantOrigin(params.subdomain);
  const url = new URL("/oauth/authorizations/new", origin);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", validatedScopes.join(" "));
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function ensureSecureParentDir(filePath: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    await fs.promises.chmod(dir, 0o700);
  } catch {
    // Ignore on platforms that do not support POSIX chmod
  }
}

export async function saveTokenSetAtomically(
  filePath: string,
  tokenSet: StoredTokenSet
): Promise<void> {
  await ensureSecureParentDir(filePath);
  const dir = path.dirname(filePath);
  const tmpName = `.${path.basename(filePath)}.tmp.${process.pid}.${crypto
    .randomBytes(6)
    .toString("hex")}`;
  const tmpPath = path.join(dir, tmpName);

  const payload = JSON.stringify(tokenSet, null, 2) + "\n";
  const handle = await fs.promises.open(tmpPath, "w", 0o600);
  try {
    await handle.writeFile(payload, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }

  try {
    await fs.promises.chmod(tmpPath, 0o600);
  } catch {
    // Ignore on non-POSIX
  }

  await fs.promises.rename(tmpPath, filePath);
}

export async function loadTokenSet(
  filePath: string
): Promise<StoredTokenSet | null> {
  let raw: string;
  try {
    raw = await fs.promises.readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }

  try {
    await fs.promises.chmod(filePath, 0o600);
  } catch {
    // Ignore if chmod unsupported
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ReauthorizationRequiredError(
      "corrupted_token_file",
      `Stored OAuth token file at "${filePath}" is not valid JSON. Please re-run OAuth authorization.`
    );
  }

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as StoredTokenSet).access_token !== "string" ||
    !(parsed as StoredTokenSet).access_token.trim()
  ) {
    throw new ReauthorizationRequiredError(
      "invalid_token_file",
      `Stored OAuth token file at "${filePath}" is missing a valid access_token. Please re-run OAuth authorization.`
    );
  }

  return parsed as StoredTokenSet;
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface FileLockOptions {
  timeoutMs?: number;
  staleMs?: number;
  pollIntervalMs?: number;
}

/**
 * Acquires an exclusive cross-process lock file (`{tokenFilePath}.lock`) to serialize OAuth refresh operations.
 */
export async function withFileLock<T>(
  targetFilePath: string,
  fn: () => Promise<T>,
  options?: FileLockOptions
): Promise<T> {
  await ensureSecureParentDir(targetFilePath);
  const lockPath = `${targetFilePath}.lock`;
  const timeoutMs = options?.timeoutMs ?? 15000;
  const staleMs = options?.staleMs ?? 30000;
  const pollIntervalMs = options?.pollIntervalMs ?? 40;
  const deadline = Date.now() + timeoutMs;

  const lockContent = JSON.stringify({
    pid: process.pid,
    createdAt: Date.now(),
    nonce: crypto.randomBytes(8).toString("hex"),
  });

  let acquired = false;
  while (!acquired) {
    try {
      const handle = await fs.promises.open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(lockContent, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      acquired = true;
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") {
        throw err;
      }

      // Inspect existing lock to see if it is stale or held by a dead process
      try {
        const stat = await fs.promises.stat(lockPath);
        const ageMs = Date.now() - stat.mtimeMs;
        let holderDead = false;
        try {
          const rawLock = await fs.promises.readFile(lockPath, "utf8");
          const parsedLock = JSON.parse(rawLock) as {
            pid?: number;
            createdAt?: number;
          };
          if (
            typeof parsedLock.pid === "number" &&
            parsedLock.pid !== process.pid &&
            !isProcessAlive(parsedLock.pid)
          ) {
            holderDead = true;
          }
        } catch {
          // Lock might be mid-write; rely on ageMs
        }

        if (ageMs > staleMs || holderDead) {
          await fs.promises.unlink(lockPath).catch(() => undefined);
          continue;
        }
      } catch {
        // Lock was just removed by holder
        continue;
      }

      if (Date.now() >= deadline) {
        throw new Error(
          `Timed out waiting ${timeoutMs}ms for OAuth token refresh lock at "${lockPath}".`
        );
      }

      const jitter = Math.floor(Math.random() * 25);
      await sleep(pollIntervalMs + jitter);
    }
  }

  try {
    return await fn();
  } finally {
    try {
      const currentContent = await fs.promises.readFile(lockPath, "utf8");
      if (currentContent === lockContent) {
        await fs.promises.unlink(lockPath);
      }
    } catch {
      // Ignore if already cleaned up
    }
  }
}

interface RawOAuthTokenResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  refresh_token?: string;
  expires_in?: number;
  refresh_token_expires_in?: number;
  error?: string;
  error_description?: string;
}

export interface OAuthManagerOptions {
  config: ZendeskMcpConfig;
  logger: SafeLogger;
  fetchFn?: typeof fetch;
  refreshSkewMs?: number;
  lockOptions?: FileLockOptions;
}

export class ZendeskOAuthManager {
  private readonly config: ZendeskMcpConfig;
  private readonly logger: SafeLogger;
  private readonly fetchFn: typeof fetch;
  private readonly refreshSkewMs: number;
  private readonly lockOptions?: FileLockOptions;

  private cachedToken: StoredTokenSet | null = null;
  private inFlightRefresh: Promise<StoredTokenSet> | null = null;

  constructor(options: OAuthManagerOptions) {
    this.config = options.config;
    this.logger = options.logger;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
    this.refreshSkewMs = options.refreshSkewMs ?? 60_000;
    this.lockOptions = options.lockOptions;
  }

  public getKnownSecrets(): readonly (string | undefined)[] {
    return [
      this.config.oauthClientSecret,
      this.cachedToken?.access_token,
      this.cachedToken?.refresh_token,
    ];
  }

  private assertGrantedScopes(token: StoredTokenSet): void {
    const granted = new Set(token.scope.split(/\s+/));
    const missing = this.config.oauthScopes.filter(scope => !granted.has(scope) && !(granted.has("read") && scope.endsWith(":read")));
    if (missing.length) throw new ReauthorizationRequiredError("scope_change", `Saved OAuth token lacks configured scopes: ${missing.join(" ")}. Run 'npm run auth' for fresh consent.`);
  }

  private isTokenFresh(
    token: StoredTokenSet,
    now: number = Date.now()
  ): boolean {
    if (token.subdomain !== this.config.subdomain) {
      return false;
    }
    if (
      typeof token.refresh_token_expires_at === "number" &&
      now >= token.refresh_token_expires_at &&
      typeof token.expires_at === "number" &&
      now >= token.expires_at
    ) {
      return false;
    }
    if (typeof token.expires_at === "number") {
      return now + this.refreshSkewMs < token.expires_at;
    }
    // If no expires_at was provided by Zendesk, treat as valid unless forced
    return true;
  }

  /**
   * Returns a valid access token, automatically loading from disk and refreshing if expired.
   * Serializes refreshes across concurrent calls and across multiple OS processes.
   */
  public async getValidAccessToken(options?: {
    forceRefresh?: boolean;
    failedAccessToken?: string;
  }): Promise<string> {
    const forceRefresh = options?.forceRefresh ?? false;

    if (!forceRefresh && this.cachedToken && this.isTokenFresh(this.cachedToken)) {
      this.assertGrantedScopes(this.cachedToken);
      return this.cachedToken.access_token;
    }

    // Check disk before triggering a network refresh if we haven't loaded yet
    if (!forceRefresh && !this.cachedToken) {
      const diskToken = await loadTokenSet(this.config.tokenFilePath);
      if (diskToken && diskToken.subdomain === this.config.subdomain) this.assertGrantedScopes(diskToken);
      if (diskToken && this.isTokenFresh(diskToken)) {
        this.cachedToken = diskToken;
        return diskToken.access_token;
      }
      if (diskToken) {
        this.cachedToken = diskToken;
      }
    }

    const rotated = await this.refreshOrObtainToken({
      forceRefresh,
      failedAccessToken:
        options?.failedAccessToken ?? this.cachedToken?.access_token,
    });
    this.assertGrantedScopes(rotated);
    return rotated.access_token;
  }

  /**
   * Exchanges an authorization code + PKCE code_verifier for an initial OAuth token set and saves it atomically.
   */
  public async exchangeAuthorizationCode(params: {
    code: string;
    codeVerifier: string;
    redirectUri?: string;
  }): Promise<StoredTokenSet> {
    const code = params.code.trim();
    const codeVerifier = params.codeVerifier.trim();
    if (!code || !codeVerifier) {
      throw new PolicyViolationError(
        "INVALID_OAUTH_CODE",
        "Authorization code and PKCE code_verifier are both required."
      );
    }

    return withFileLock(
      this.config.tokenFilePath,
      async () => {
        const body: Record<string, string> = {
          grant_type: "authorization_code",
          code,
          client_id: this.config.oauthClientId,
          redirect_uri: params.redirectUri ?? this.config.oauthRedirectUri,
          code_verifier: codeVerifier,
          scope: this.config.oauthScopes.join(" "),
        };
        if (this.config.oauthClientSecret) {
          body.client_secret = this.config.oauthClientSecret;
        }

        const tokenSet = await this.executeGrantRequest(
          body,
          "authorization_code"
        );
        await saveTokenSetAtomically(this.config.tokenFilePath, tokenSet);
        this.cachedToken = tokenSet;
        this.logger.info(
          "Successfully exchanged OAuth authorization code and persisted token set.",
          {
            subdomain: this.config.subdomain,
            scope: tokenSet.scope,
            hasRefreshToken: Boolean(tokenSet.refresh_token),
          }
        );
        return tokenSet;
      },
      this.lockOptions
    );
  }

  private async refreshOrObtainToken(params: {
    forceRefresh: boolean;
    failedAccessToken?: string;
  }): Promise<StoredTokenSet> {
    if (this.inFlightRefresh) {
      return this.inFlightRefresh;
    }

    const promise = withFileLock(
      this.config.tokenFilePath,
      async () => {
        // Re-read token file inside the lock in case another process just rotated the token!
        const diskToken = await loadTokenSet(this.config.tokenFilePath);

        if (diskToken && diskToken.subdomain === this.config.subdomain) {
          const rotatedByOtherProcess =
            params.failedAccessToken !== undefined &&
            diskToken.access_token !== params.failedAccessToken;

          if (
            this.isTokenFresh(diskToken) &&
            (!params.forceRefresh || rotatedByOtherProcess)
          ) {
            this.logger.debug(
              "Using fresh OAuth token already rotated by another process."
            );
            this.cachedToken = diskToken;
            return diskToken;
          }
        }

        // If refreshing a stored refresh_token
        if (diskToken?.refresh_token) {
          if (
            typeof diskToken.refresh_token_expires_at === "number" &&
            Date.now() >= diskToken.refresh_token_expires_at
          ) {
            throw new ReauthorizationRequiredError(
              "refresh_token_expired",
              "Stored Zendesk OAuth refresh token has expired. Run 'npm run auth' to reauthorize."
            );
          }

          const body: Record<string, string> = {
            grant_type: "refresh_token",
            refresh_token: diskToken.refresh_token,
            client_id: this.config.oauthClientId,
            scope: this.config.oauthScopes.join(" "),
          };
          if (this.config.oauthClientSecret) {
            body.client_secret = this.config.oauthClientSecret;
          }

          const refreshed = await this.executeGrantRequest(
            body,
            diskToken.grant_type ?? "authorization_code",
            diskToken.refresh_token
          );
          await saveTokenSetAtomically(this.config.tokenFilePath, refreshed);
          this.cachedToken = refreshed;
          this.logger.info("Rotated Zendesk OAuth token via refresh_token grant.");
          return refreshed;
        }

        // If configured for client_credentials grant (unattended service identity)
        if (this.config.oauthGrantType === "client_credentials") {
          if (!this.config.oauthClientSecret) {
            throw new ReauthorizationRequiredError(
              "missing_client_secret",
              "ZENDESK_OAUTH_CLIENT_SECRET is required for client_credentials grant."
            );
          }
          const body: Record<string, string> = {
            grant_type: "client_credentials",
            client_id: this.config.oauthClientId,
            client_secret: this.config.oauthClientSecret,
            scope: this.config.oauthScopes.join(" "),
          };
          const obtained = await this.executeGrantRequest(
            body,
            "client_credentials"
          );
          await saveTokenSetAtomically(this.config.tokenFilePath, obtained);
          this.cachedToken = obtained;
          this.logger.info(
            "Obtained Zendesk OAuth token via client_credentials grant."
          );
          return obtained;
        }

        // Otherwise we have no refresh token and we are in authorization_code mode
        if (!diskToken) {
          throw new ReauthorizationRequiredError(
            "no_stored_token",
            `No Zendesk OAuth token found at "${this.config.tokenFilePath}". Run 'npm run auth' to authorize with Zendesk.`
          );
        }

        throw new ReauthorizationRequiredError(
          "access_token_expired_no_refresh_token",
          "Zendesk OAuth access token expired and no refresh_token is available. Run 'npm run auth' to reauthorize."
        );
      },
      this.lockOptions
    );

    this.inFlightRefresh = promise;
    try {
      return await promise;
    } finally {
      this.inFlightRefresh = null;
    }
  }

  private async executeGrantRequest(
    body: Record<string, string>,
    grantType: "authorization_code" | "client_credentials",
    previousRefreshToken?: string
  ): Promise<StoredTokenSet> {
    const origin = getTenantOrigin(this.config.subdomain);
    const grantUrl = validateOutboundRequest(
      `${origin}/oauth/tokens`,
      "POST",
      this.config.subdomain
    );

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.requestTimeoutMs
    );

    let response: Response;
    try {
      response = await this.fetchFn(grantUrl.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "zendesk-mcp/0.1.0",
        },
        body: JSON.stringify(body),
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      const safeMsg = redactSecrets(
        err instanceof Error ? err.message : String(err),
        [
          this.config.oauthClientSecret,
          body.refresh_token,
          body.code,
          body.code_verifier,
        ]
      );
      throw new ZendeskApiError(
        0,
        `OAuth token request to ${grantUrl.origin}/oauth/tokens failed: ${safeMsg}`
      );
    } finally {
      clearTimeout(timer);
    }

    const rawText = await response.text();
    let parsed: RawOAuthTokenResponse = {};
    try {
      parsed = JSON.parse(rawText) as RawOAuthTokenResponse;
    } catch {
      // Non-JSON response body
    }

    if (!response.ok) {
      const errCode = parsed.error ?? `http_${response.status}`;
      const errDesc = redactSecrets(
        parsed.error_description ?? rawText.slice(0, 300),
        [
          this.config.oauthClientSecret,
          body.refresh_token,
          body.code,
          body.code_verifier,
        ]
      );

      if (
        response.status === 400 ||
        response.status === 401 ||
        errCode === "invalid_grant" ||
        errCode === "invalid_client" ||
        errCode === "unauthorized_client"
      ) {
        throw new ReauthorizationRequiredError(
          errCode,
          `Zendesk OAuth grant (${body.grant_type}) rejected with ${errCode}: ${errDesc}. Run 'npm run auth' to reauthorize.`
        );
      }

      throw new ZendeskApiError(
        response.status,
        `Zendesk OAuth endpoint returned HTTP ${response.status} (${errCode}): ${errDesc}`,
        { errorCode: errCode }
      );
    }

    if (
      typeof parsed.access_token !== "string" ||
      !parsed.access_token.trim()
    ) {
      throw new ZendeskApiError(
        response.status,
        "Zendesk OAuth endpoint returned 200 OK without a valid access_token."
      );
    }

    const now = Date.now();
    const expiresInSec =
      typeof parsed.expires_in === "number" && parsed.expires_in > 0
        ? parsed.expires_in
        : undefined;
    const refreshExpiresInSec =
      typeof parsed.refresh_token_expires_in === "number" &&
      parsed.refresh_token_expires_in > 0
        ? parsed.refresh_token_expires_in
        : undefined;

    return {
      access_token: parsed.access_token,
      token_type: parsed.token_type ?? "bearer",
      scope: parsed.scope ?? this.config.oauthScopes.join(" "),
      refresh_token: parsed.refresh_token ?? previousRefreshToken,
      expires_in: expiresInSec,
      expires_at: expiresInSec ? now + expiresInSec * 1000 : undefined,
      refresh_token_expires_in: refreshExpiresInSec,
      refresh_token_expires_at: refreshExpiresInSec
        ? now + refreshExpiresInSec * 1000
        : undefined,
      obtained_at: now,
      subdomain: this.config.subdomain,
      grant_type: grantType,
    };
  }
}
