import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import readline from "node:readline";
import { ZendeskMcpConfig } from "./config.js";
import { SafeLogger } from "./logger.js";
import {
  ZendeskOAuthManager,
  buildAuthorizationUrl,
  generateOAuthState,
  generatePkcePair,
  loadTokenSet,
} from "./oauth.js";
import { ZendeskApiClient } from "./zendesk-client.js";

function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function extractCodeAndStateFromInput(
  rawInput: string,
  expectedRedirectUri: string
): { code: string; state: string } {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error("Empty callback input.");
  }

  let parsedUrl: URL;
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    parsedUrl = new URL(trimmed);
    const expected = new URL(expectedRedirectUri);
    if (
      parsedUrl.origin !== expected.origin ||
      parsedUrl.pathname !== expected.pathname
    ) {
      throw new Error(
        `Callback URL origin/path "${parsedUrl.origin}${parsedUrl.pathname}" does not match configured redirect URI "${expected.origin}${expected.pathname}".`
      );
    }
  } else if (trimmed.startsWith("/")) {
    const expected = new URL(expectedRedirectUri);
    parsedUrl = new URL(trimmed, expected.origin);
  } else {
    parsedUrl = new URL(
      `http://127.0.0.1/?${trimmed.replace(/^\?/, "")}`
    );
  }

  const error = parsedUrl.searchParams.get("error");
  if (error) {
    const desc = parsedUrl.searchParams.get("error_description") ?? "";
    throw new Error(`Zendesk OAuth authorization denied (${error}): ${desc}`);
  }

  const code = parsedUrl.searchParams.get("code")?.trim() ?? "";
  const state = parsedUrl.searchParams.get("state")?.trim() ?? "";
  if (!code || !state) {
    throw new Error(
      "Callback input must include both 'code' and 'state' query parameters (paste the full redirect URL from your browser address bar)."
    );
  }

  return { code, state };
}

export async function runOAuthSetupCli(options: {
  config: ZendeskMcpConfig;
  oauthManager: ZendeskOAuthManager;
  client: ZendeskApiClient;
  logger: SafeLogger;
  manualOnly?: boolean;
}): Promise<void> {
  const { config, oauthManager, client, manualOnly } = options;

  if (config.oauthGrantType === "client_credentials") {
    process.stderr.write(
      `\n[zendesk-mcp] Configured for OAuth client_credentials grant (tenant: ${config.subdomain}).\n` +
        `Requesting token from https://${config.subdomain}.zendesk.com/oauth/tokens ...\n`
    );
    await oauthManager.getValidAccessToken({ forceRefresh: true });
    process.stderr.write(
      `[zendesk-mcp] Token saved to ${config.tokenFilePath} (mode 0600).\n`
    );
    return;
  }

  const pkce = generatePkcePair();
  const expectedState = generateOAuthState();
  const authUrl = buildAuthorizationUrl({
    subdomain: config.subdomain,
    clientId: config.oauthClientId,
    redirectUri: config.oauthRedirectUri,
    scopes: config.oauthScopes,
    state: expectedState,
    codeChallenge: pkce.codeChallenge,
  });

  const redirectUrl = new URL(config.oauthRedirectUri);
  const listenPort = Number(redirectUrl.port || "80");
  const listenHost = redirectUrl.hostname === "localhost" ? "127.0.0.1" : redirectUrl.hostname;

  process.stderr.write(
    `\n================================================================================\n` +
      `Zendesk MCP — OAuth 2.0 Authorization Code + PKCE Setup\n` +
      `================================================================================\n` +
      `Tenant Subdomain : ${config.subdomain} (https://${config.subdomain}.zendesk.com)\n` +
      `OAuth Client ID  : ${config.oauthClientId}\n` +
      `Requested Scopes : ${config.oauthScopes.join(" ")}\n` +
      `Redirect URI     : ${config.oauthRedirectUri}\n` +
      `Token File       : ${config.tokenFilePath}\n` +
      `--------------------------------------------------------------------------------\n` +
      `Remote Homelab Tip:\n` +
      `  • Either forward the callback port over SSH before opening the URL:\n` +
      `      ssh -L ${listenPort}:127.0.0.1:${listenPort} <user>@<homelab-host>\n` +
      `  • OR after authorizing in your browser, copy the full redirected URL\n` +
      `    (http://127.0.0.1:${listenPort}/callback?code=...&state=...) from your\n` +
      `    browser's address bar and paste it directly below!\n` +
      `--------------------------------------------------------------------------------\n` +
      `\n1. Open this URL in your browser to authorize:\n\n   ${authUrl}\n\n`
  );

  const { code, state } = await waitForCallbackOrPaste({
    expectedRedirectUri: config.oauthRedirectUri,
    listenHost,
    listenPort,
    callbackPath: redirectUrl.pathname,
    manualOnly: Boolean(manualOnly),
  });

  if (!timingSafeEqualString(state, expectedState)) {
    throw new Error(
      "OAuth state parameter mismatch! Aborting authorization to prevent CSRF."
    );
  }

  process.stderr.write(
    `\n[zendesk-mcp] Authorization code received and state verified. Exchanging code with PKCE verifier...\n`
  );

  const tokenSet = await oauthManager.exchangeAuthorizationCode({
    code,
    codeVerifier: pkce.codeVerifier,
    redirectUri: config.oauthRedirectUri,
  });

  process.stderr.write(
    `[zendesk-mcp] OAuth tokens saved atomically to ${config.tokenFilePath} (permissions: 0600).\n` +
      `  • Granted scopes : ${tokenSet.scope}\n` +
      `  • Access expiry  : ${
        tokenSet.expires_at
          ? new Date(tokenSet.expires_at).toISOString()
          : "unspecified"
      }\n` +
      `  • Refresh token  : ${
        tokenSet.refresh_token ? "present (rotation enabled)" : "not returned"
      }\n`
  );

  if (config.enableUserTool) {
    try {
      const me = await client.getUser("me");
      process.stderr.write(
        `  • Verified user  : ${me.user.name} (id=${me.user.id}, role=${
          me.user.role ?? "unknown"
        })\n`
      );
    } catch (err) {
      process.stderr.write(
        `  • Note: Could not verify /api/v2/users/me.json (${
          err instanceof Error ? err.message : String(err)
        }). Ticket endpoints can still be used if 'tickets:read' is granted.\n`
      );
    }
  }
}

async function waitForCallbackOrPaste(params: {
  expectedRedirectUri: string;
  listenHost: string;
  listenPort: number;
  callbackPath: string;
  manualOnly: boolean;
}): Promise<{ code: string; state: string }> {
  return new Promise<{ code: string; state: string }>((resolve, reject) => {
    let settled = false;
    let server: http.Server | null = null;
    let rl: readline.Interface | null = null;

    const cleanup = () => {
      if (rl) {
        rl.close();
        rl = null;
      }
      if (server) {
        server.close();
        server = null;
      }
    };

    const finishSuccess = (result: { code: string; state: string }) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    const finishError = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    if (!params.manualOnly) {
      server = http.createServer((req, res) => {
        try {
          const reqUrl = new URL(
            req.url ?? "/",
            `http://${params.listenHost}:${params.listenPort}`
          );
          if (reqUrl.pathname !== params.callbackPath) {
            res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Not Found");
            return;
          }

          const result = extractCodeAndStateFromInput(
            reqUrl.toString(),
            params.expectedRedirectUri
          );
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(
            `<!doctype html><html><body style="font-family:sans-serif;padding:2rem;">` +
              `<h2>Zendesk MCP Authorization Received</h2>` +
              `<p>You may close this browser tab and return to your terminal.</p>` +
              `</body></html>`
          );
          finishSuccess(result);
        } catch (err) {
          res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
          res.end(
            `Authorization callback error: ${
              err instanceof Error ? err.message : String(err)
            }`
          );
          finishError(err instanceof Error ? err : new Error(String(err)));
        }
      });

      server.on("error", (err) => {
        process.stderr.write(
          `[zendesk-mcp] Note: Could not bind loopback callback listener on ${params.listenHost}:${params.listenPort} (${err.message}). Waiting for pasted redirect URL on stdin...\n`
        );
      });

      server.listen(params.listenPort, params.listenHost, () => {
        process.stderr.write(
          `2. Listening for loopback redirect on http://${params.listenHost}:${params.listenPort}${params.callbackPath}\n` +
            `   OR paste the full redirected callback URL here and press Enter:\n> `
        );
      });
    } else {
      process.stderr.write(
        `2. Paste the full redirected callback URL from your browser address bar and press Enter:\n> `
      );
    }

    if (process.stdin.isTTY || params.manualOnly) {
      rl = readline.createInterface({
        input: process.stdin,
        output: process.stderr,
      });
      rl.on("line", (line) => {
        if (!line.trim()) return;
        try {
          const parsed = extractCodeAndStateFromInput(
            line,
            params.expectedRedirectUri
          );
          finishSuccess(parsed);
        } catch (err) {
          process.stderr.write(
            `[zendesk-mcp] Invalid callback URL: ${
              err instanceof Error ? err.message : String(err)
            }\nPaste the full redirect URL (including ?code=...&state=...):\n> `
          );
        }
      });
    }
  });
}

export async function runStatusCli(options: {
  config: ZendeskMcpConfig;
  client: ZendeskApiClient;
  verifyLive: boolean;
}): Promise<void> {
  const { config, client, verifyLive } = options;
  process.stderr.write(
    `Zendesk MCP Status\n` +
      `  • Tenant Subdomain : ${config.subdomain} (https://${config.subdomain}.zendesk.com)\n` +
      `  • Grant Mode       : ${config.oauthGrantType}\n` +
      `  • Configured Scopes: ${config.oauthScopes.join(" ")}\n` +
      `  • Token File Path  : ${config.tokenFilePath}\n`
  );

  const token = await loadTokenSet(config.tokenFilePath);
  if (!token) {
    process.stderr.write(
      `  • Token Status     : NOT FOUND (run 'npm run auth' to authorize)\n`
    );
    process.exitCode = 1;
    return;
  }

  let modeStr = "unknown";
  try {
    const stat = await fs.promises.stat(config.tokenFilePath);
    modeStr = "0" + (stat.mode & 0o777).toString(8);
  } catch {
    // ignore
  }

  const now = Date.now();
  const accessExpired =
    typeof token.expires_at === "number" ? now >= token.expires_at : false;
  const refreshExpired =
    typeof token.refresh_token_expires_at === "number"
      ? now >= token.refresh_token_expires_at
      : false;

  process.stderr.write(
    `  • Token File Mode  : ${modeStr}\n` +
      `  • Token Subdomain  : ${token.subdomain}\n` +
      `  • Granted Scopes   : ${token.scope}\n` +
      `  • Access Token     : [REDACTED] (${
        accessExpired ? "EXPIRED — will refresh on next call" : "VALID"
      }${
        token.expires_at
          ? `, expires ${new Date(token.expires_at).toISOString()}`
          : ""
      })\n` +
      `  • Refresh Token    : ${
        token.refresh_token
          ? `[REDACTED] (${refreshExpired ? "EXPIRED" : "PRESENT"})`
          : "NONE"
      }\n`
  );

  if (verifyLive) {
    process.stderr.write(
      `  • Live API Check   : Calling GET /api/v2/users/me.json ...\n`
    );
    const me = await client.getUser("me");
    process.stderr.write(
      `  • Live API Result  : OK — Authenticated as ${me.user.name} (id=${
        me.user.id
      }, role=${me.user.role ?? "unknown"})\n`
    );
  }
}
