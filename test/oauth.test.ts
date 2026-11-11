import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config.js";
import { ReauthorizationRequiredError } from "../src/errors.js";
import { SafeLogger } from "../src/logger.js";
import {
  ZendeskOAuthManager,
  buildAuthorizationUrl,
  generateOAuthState,
  generatePkcePair,
  loadTokenSet,
  saveTokenSetAtomically,
} from "../src/oauth.js";

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "zendesk-mcp-oauth-test-"));
}

describe("OAuth 2.0 + PKCE, Atomic Token Persistence & Cross-Process Locking", () => {
  it("generates valid S256 PKCE pairs and authorization URLs", () => {
    const pkce = generatePkcePair();
    const expectedChallenge = crypto
      .createHash("sha256")
      .update(pkce.codeVerifier)
      .digest("base64url");
    assert.equal(pkce.codeChallenge, expectedChallenge);

    const state = generateOAuthState();
    const authUrl = new URL(
      buildAuthorizationUrl({
        subdomain: "acme",
        clientId: "zd_client_1",
        redirectUri: "http://127.0.0.1:18492/callback",
        scopes: ["tickets:read", "users:read"],
        state,
        codeChallenge: pkce.codeChallenge,
      })
    );

    assert.equal(authUrl.origin, "https://acme.zendesk.com");
    assert.equal(authUrl.pathname, "/oauth/authorizations/new");
    assert.equal(authUrl.searchParams.get("response_type"), "code");
    assert.equal(authUrl.searchParams.get("client_id"), "zd_client_1");
    assert.equal(authUrl.searchParams.get("scope"), "tickets:read users:read");
    assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
  });

  it("exchanges authorization code and persists tokens atomically with 0600/0700 permissions", async () => {
    const tmpDir = createTempDir();
    const tokenDir = path.join(tmpDir, "nested-secrets");
    const tokenFilePath = path.join(tokenDir, "tokens.json");

    const config = loadConfig({
      subdomain: "acme",
      oauthClientId: "zd_client_1",
      tokenFilePath,
      oauthScopes: ["tickets:read", "users:read"],
      logLevel: "silent",
    });

    const logger = new SafeLogger({ level: "silent" });
    let capturedBody: Record<string, string> | null = null;

    const mockFetch: typeof fetch = async (input, init) => {
      assert.equal(String(input), "https://acme.zendesk.com/oauth/tokens");
      assert.equal(init?.method, "POST");
      capturedBody = JSON.parse(String(init?.body)) as Record<string, string>;
      return new Response(
        JSON.stringify({
          access_token: "initial_access_tok_1",
          refresh_token: "initial_refresh_tok_1",
          token_type: "bearer",
          scope: "tickets:read users:read",
          expires_in: 1800,
          refresh_token_expires_in: 2592000,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const manager = new ZendeskOAuthManager({
      config,
      logger,
      fetchFn: mockFetch,
    });

    const saved = await manager.exchangeAuthorizationCode({
      code: "auth_code_xyz",
      codeVerifier: "pkce_verifier_123",
    });

    assert.equal(saved.access_token, "initial_access_tok_1");
    assert.equal(saved.refresh_token, "initial_refresh_tok_1");
    assert.equal(capturedBody?.["grant_type"], "authorization_code");
    assert.equal(capturedBody?.["code_verifier"], "pkce_verifier_123");

    const dirStat = fs.statSync(tokenDir);
    const fileStat = fs.statSync(tokenFilePath);
    assert.equal(dirStat.mode & 0o777, 0o700);
    assert.equal(fileStat.mode & 0o777, 0o600);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("serializes concurrent token refreshes across multiple instances without racing rotated refresh tokens", async () => {
    const tmpDir = createTempDir();
    const tokenFilePath = path.join(tmpDir, "tokens.json");

    // Seed an expired token on disk
    await saveTokenSetAtomically(tokenFilePath, {
      access_token: "expired_access_token_v1",
      refresh_token: "single_use_refresh_token_v1",
      token_type: "bearer",
      scope: "tickets:read users:read",
      expires_in: 1800,
      expires_at: Date.now() - 10_000, // already expired
      obtained_at: Date.now() - 1_810_000,
      subdomain: "acme",
      grant_type: "authorization_code",
    });

    const config = loadConfig({
      subdomain: "acme",
      oauthClientId: "zd_client_1",
      tokenFilePath,
      oauthScopes: ["tickets:read", "users:read"],
      logLevel: "silent",
    });
    const logger = new SafeLogger({ level: "silent" });

    let refreshCallCount = 0;
    let validRefreshToken = "single_use_refresh_token_v1";

    // Simulate Zendesk rotating refresh tokens and immediately invalidating used ones
    const mockFetch: typeof fetch = async (_input, init) => {
      refreshCallCount += 1;
      const body = JSON.parse(String(init?.body)) as Record<string, string>;

      // Small delay to ensure concurrent callers contend on the lock
      await new Promise((r) => setTimeout(r, 50));

      if (body.refresh_token !== validRefreshToken) {
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description:
              "Refresh token was already used and invalidated by rotation.",
          }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      validRefreshToken = "rotated_refresh_token_v2";
      return new Response(
        JSON.stringify({
          access_token: "rotated_access_token_v2",
          refresh_token: validRefreshToken,
          token_type: "bearer",
          scope: "tickets:read users:read",
          expires_in: 1800,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    // Create 5 separate ZendeskOAuthManager instances (simulating 5 concurrent stdio processes)
    const managers = Array.from({ length: 5 }, () =>
      new ZendeskOAuthManager({
        config,
        logger,
        fetchFn: mockFetch,
        lockOptions: { pollIntervalMs: 15, timeoutMs: 5000 },
      })
    );

    const results = await Promise.all(
      managers.map((m) =>
        m.getValidAccessToken({
          forceRefresh: true,
          failedAccessToken: "expired_access_token_v1",
        })
      )
    );

    // Every single instance must receive the new rotated token, and only 1 network call must have occurred!
    assert.equal(refreshCallCount, 1);
    for (const token of results) {
      assert.equal(token, "rotated_access_token_v2");
    }

    // Verify a fresh manager after "restart" loads the rotated token from disk without network call
    const restartedManager = new ZendeskOAuthManager({
      config,
      logger,
      fetchFn: async () => {
        throw new Error("Should not make network call after restart");
      },
    });
    const afterRestartToken = await restartedManager.getValidAccessToken();
    assert.equal(afterRestartToken, "rotated_access_token_v2");

    const diskState = await loadTokenSet(tokenFilePath);
    assert.equal(diskState?.refresh_token, "rotated_refresh_token_v2");

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("surfaces a clear ReauthorizationRequiredError when refresh credentials are revoked or expired", async () => {
    const tmpDir = createTempDir();
    const tokenFilePath = path.join(tmpDir, "tokens.json");

    await saveTokenSetAtomically(tokenFilePath, {
      access_token: "expired_tok",
      refresh_token: "revoked_refresh_tok_secret",
      token_type: "bearer",
      scope: "tickets:read",
      expires_at: Date.now() - 5000,
      obtained_at: Date.now() - 20000,
      subdomain: "acme",
      grant_type: "authorization_code",
    });

    const config = loadConfig({
      subdomain: "acme",
      oauthClientId: "zd_client_1",
      tokenFilePath,
      oauthScopes: ["tickets:read"],
      logLevel: "silent",
    });
    const logger = new SafeLogger({ level: "silent" });

    const manager = new ZendeskOAuthManager({
      config,
      logger,
      fetchFn: async () =>
        new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description:
              "The provided refresh token revoked_refresh_tok_secret is revoked.",
          }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        ),
    });

    await assert.rejects(
      () => manager.getValidAccessToken(),
      (err: unknown) => {
        assert.ok(err instanceof ReauthorizationRequiredError);
        assert.equal(err.reason, "invalid_grant");
        assert.ok(!err.message.includes("revoked_refresh_tok_secret"));
        return true;
      }
    );

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
