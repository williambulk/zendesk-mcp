import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { validateOAuthScopes } from "../src/config.js";
import { PolicyViolationError } from "../src/errors.js";
import { SafeLogger } from "../src/logger.js";
import {
  boundPlainText,
  enforceTicketSearchQuery,
  inspectAttachmentUrl,
  parseTicketIdentifier,
  redactSecrets,
  sanitizeFileName,
  stripHtmlToText,
  validateOutboundRequest,
  validateSubdomain,
} from "../src/security.js";

describe("Security, Tenant Pinning & Sanitization", () => {
  it("validates Zendesk tenant subdomains strictly", () => {
    assert.equal(validateSubdomain("acme"), "acme");
    assert.equal(validateSubdomain("  ACME-dev "), "acme-dev");

    assert.throws(() => validateSubdomain(""), /Invalid Zendesk subdomain/);
    assert.throws(
      () => validateSubdomain("acme.zendesk.com"),
      /Invalid Zendesk subdomain/
    );
    assert.throws(
      () => validateSubdomain("https://acme.zendesk.com"),
      /Invalid Zendesk subdomain/
    );
    assert.throws(
      () => validateSubdomain("-badsubdomain"),
      /Invalid Zendesk subdomain/
    );
  });

  it("parses valid ticket IDs and configured-tenant ticket URLs while rejecting malicious URLs", () => {
    assert.equal(parseTicketIdentifier(12345, "acme"), 12345);
    assert.equal(parseTicketIdentifier("12345", "acme"), 12345);
    assert.equal(parseTicketIdentifier("#12345", "acme"), 12345);
    assert.equal(
      parseTicketIdentifier(
        "https://acme.zendesk.com/agent/tickets/12345",
        "acme"
      ),
      12345
    );
    assert.equal(
      parseTicketIdentifier(
        "https://acme.zendesk.com/api/v2/tickets/12345.json",
        "acme"
      ),
      12345
    );

    // Reject cross-tenant URLs
    assert.throws(
      () =>
        parseTicketIdentifier(
          "https://othercorp.zendesk.com/agent/tickets/12345",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError && err.code === "CROSS_TENANT_URL"
    );

    // Reject non-HTTPS URLs
    assert.throws(
      () =>
        parseTicketIdentifier(
          "http://acme.zendesk.com/agent/tickets/12345",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError &&
        err.code === "UNTRUSTED_TICKET_URL"
    );

    // Reject embedded credentials
    assert.throws(
      () =>
        parseTicketIdentifier(
          "https://admin:secret@acme.zendesk.com/agent/tickets/12345",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError &&
        err.code === "UNTRUSTED_TICKET_URL"
    );

    // Reject path traversal tricks
    assert.throws(
      () =>
        parseTicketIdentifier(
          "https://acme.zendesk.com/agent/tickets/12345/../../users/me",
          "acme"
        ),
      PolicyViolationError
    );

    // Reject non-positive integers
    assert.throws(() => parseTicketIdentifier(0, "acme"), PolicyViolationError);
    assert.throws(
      () => parseTicketIdentifier(-5, "acme"),
      PolicyViolationError
    );
  });

  it("enforces outbound route allowlist and GET-only business data policy", () => {
    // Allowed GET routes
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/api/v2/tickets/12345.json",
        "GET",
        "acme"
      )
    );
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/api/v2/tickets/12345/comments.json?page%5Bsize%5D=50",
        "GET",
        "acme"
      )
    );
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/api/v2/search.json?query=type%3Aticket+vpn",
        "GET",
        "acme"
      )
    );
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/api/v2/users/me.json",
        "GET",
        "acme"
      )
    );
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/api/v2/users/42.json",
        "GET",
        "acme"
      )
    );

    // Narrow POST exception for /oauth/tokens
    assert.doesNotThrow(() =>
      validateOutboundRequest(
        "https://acme.zendesk.com/oauth/tokens",
        "POST",
        "acme"
      )
    );

    // Disallow deprecated /api/v2/oauth/tokens
    assert.throws(
      () =>
        validateOutboundRequest(
          "https://acme.zendesk.com/api/v2/oauth/tokens.json",
          "POST",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError &&
        err.code === "DEPRECATED_OAUTH_ENDPOINT"
    );

    // Block all mutation methods on business endpoints
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      assert.throws(
        () =>
          validateOutboundRequest(
            "https://acme.zendesk.com/api/v2/tickets/12345.json",
            method,
            "acme"
          ),
        (err: unknown) =>
          err instanceof PolicyViolationError && err.code === "READ_ONLY_POLICY"
      );
    }

    // Block non-allowlisted GET routes
    assert.throws(
      () =>
        validateOutboundRequest(
          "https://acme.zendesk.com/api/v2/tickets.json",
          "GET",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError &&
        err.code === "ROUTE_NOT_ALLOWLISTED"
    );

    // Block cross-tenant requests
    assert.throws(
      () =>
        validateOutboundRequest(
          "https://attacker.zendesk.com/api/v2/tickets/12345.json",
          "GET",
          "acme"
        ),
      (err: unknown) =>
        err instanceof PolicyViolationError && err.code === "TENANT_MISMATCH"
    );
  });

  it("enforces type:ticket in search queries and blocks other resource types", () => {
    assert.equal(
      enforceTicketSearchQuery("status:open vpn"),
      "type:ticket status:open vpn"
    );
    assert.equal(
      enforceTicketSearchQuery("type:ticket priority:high type:ticket"),
      "type:ticket priority:high"
    );

    assert.throws(
      () => enforceTicketSearchQuery("type:user role:admin"),
      (err: unknown) =>
        err instanceof PolicyViolationError && err.code === "SEARCH_TYPE_POLICY"
    );
    assert.throws(
      () => enforceTicketSearchQuery("-type:ticket secret"),
      (err: unknown) =>
        err instanceof PolicyViolationError && err.code === "SEARCH_TYPE_POLICY"
    );
  });

  it("allows broad read and narrow ticket writes while rejecting other writes", () => {
    assert.deepEqual(validateOAuthScopes("tickets:read users:read"), [
      "tickets:read",
      "users:read",
    ]);
    assert.deepEqual(validateOAuthScopes("read tickets:write"), ["read", "tickets:write"]);
    assert.throws(() => validateOAuthScopes("tickets:read users:write"), PolicyViolationError);
    assert.throws(
      () => validateOAuthScopes("read write"),
      PolicyViolationError
    );
  });

  it("inspects attachment URLs, flags external origins, and sanitizes filenames", () => {
    const internal = inspectAttachmentUrl(
      "https://acme.zendesk.com/attachments/token/abc/?name=screenshot.png",
      "acme"
    );
    assert.equal(internal.isExternalUrl, false);

    const external = inspectAttachmentUrl(
      "https://malicious.example.com/phish.exe",
      "acme"
    );
    assert.equal(external.isExternalUrl, true);
    assert.match(external.securityNote, /EXTERNAL attachment host/);

    const insecure = inspectAttachmentUrl(
      "javascript:alert(1)",
      "acme"
    );
    assert.equal(insecure.contentUrl, null);
    assert.equal(insecure.isExternalUrl, true);

    assert.equal(sanitizeFileName("../../etc/passwd\x00"), "._._etc_passwd");
  });

  it("strips HTML safely and bounds oversized text", () => {
    const cleaned = stripHtmlToText(
      "<p>Hello <b>Operator</b>!<script> evil() </script><br/>Line 2 &amp; more</p>"
    );
    assert.equal(cleaned, "Hello Operator!\nLine 2 & more");

    const bounded = boundPlainText("abcdefghij", 5);
    assert.equal(bounded.truncated, true);
    assert.match(bounded.text, /^abcde\n\.\.\.\[TRUNCATED/);
  });

  it("redacts tokens and secrets from logs and error messages", () => {
    const lines: string[] = [];
    const logger = new SafeLogger({
      level: "debug",
      knownSecrets: () => ["my-super-secret-value-12345"],
      sink: (line) => lines.push(line),
    });

    logger.error(
      'Failed with Authorization: Bearer zd_live_token_999 and {"access_token":"tok_abc","refresh_token":"ref_xyz"} plus my-super-secret-value-12345'
    );

    assert.equal(lines.length, 1);
    assert.ok(!lines[0].includes("zd_live_token_999"));
    assert.ok(!lines[0].includes("tok_abc"));
    assert.ok(!lines[0].includes("ref_xyz"));
    assert.ok(!lines[0].includes("my-super-secret-value-12345"));
    assert.ok(lines[0].includes("[REDACTED]"));

    const redactedUrl = redactSecrets(
      "http://127.0.0.1:18492/callback?code=secret_auth_code_123&state=xyz"
    );
    assert.ok(!redactedUrl.includes("secret_auth_code_123"));
  });
});
