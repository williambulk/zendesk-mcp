import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config.js";
import {
  PolicyViolationError,
  RateLimitExceededError,
  ZendeskApiError,
} from "../src/errors.js";
import { SafeLogger } from "../src/logger.js";
import { ZendeskOAuthManager, saveTokenSetAtomically } from "../src/oauth.js";
import { ZendeskApiClient } from "../src/zendesk-client.js";

async function createTestClientEnv(
  fetchFn: typeof fetch,
  overrides?: {
    maxRetries?: number;
    maxRetryAfterMs?: number;
    maxBodyChars?: number;
    sleepCalls?: number[];
  }
) {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "zendesk-mcp-client-test-")
  );
  const tokenFilePath = path.join(tmpDir, "tokens.json");

  await saveTokenSetAtomically(tokenFilePath, {
    access_token: "valid_access_token_12345",
    refresh_token: "valid_refresh_token_12345",
    token_type: "bearer",
    scope: "tickets:read users:read",
    expires_at: Date.now() + 3600_000,
    obtained_at: Date.now(),
    subdomain: "acme",
    grant_type: "authorization_code",
  });

  const config = loadConfig({
    enableWrites: false,
    subdomain: "acme",
    oauthClientId: "zd_client_1",
    tokenFilePath,
    oauthScopes: ["tickets:read", "users:read"],
    maxRetries: overrides?.maxRetries ?? 2,
    maxRetryAfterMs: overrides?.maxRetryAfterMs ?? 10_000,
    maxBodyChars: overrides?.maxBodyChars ?? 16_000,
    logLevel: "silent",
  });

  const logger = new SafeLogger({ level: "silent" });
  const oauthManager = new ZendeskOAuthManager({
    config,
    logger,
    fetchFn,
  });

  const client = new ZendeskApiClient({
    config,
    oauthManager,
    logger,
    fetchFn,
    sleepFn: async (ms) => {
      overrides?.sleepCalls?.push(ms);
    },
  });

  return {
    client,
    tmpDir,
    cleanup: () => fs.rmSync(tmpDir, { recursive: true, force: true }),
  };
}

describe("ZendeskApiClient — Read Tools, Pagination, Rate Limits & Error Handling", () => {
  it("retrieves ticket metadata via configured-tenant URL and resolves custom field labels", async () => {
    const requestedUrls: string[] = [];

    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      requestedUrls.push(url);

      if (url === "https://acme.zendesk.com/api/v2/tickets/12345.json") {
        return new Response(
          JSON.stringify({
            ticket: {
              id: 12345,
              subject: "Production PLC connectivity drop on Line 4",
              status: "open",
              priority: "high",
              type: "incident",
              requester_id: 501,
              submitter_id: 501,
              assignee_id: 777,
              organization_id: 88,
              group_id: 12,
              created_at: "2026-11-10T14:20:00Z",
              updated_at: "2026-11-11T09:15:30Z",
              tags: ["plc", "line-4", "urgent"],
              description: "Initial report from operator on shift.",
              custom_fields: [
                { id: 360011, value: "plant_north" },
                { id: 360022, value: "fw_2.4.1" },
              ],
            },
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Rate-Limit": "400",
              "X-Rate-Limit-Remaining": "395",
            },
          }
        );
      }

      if (url === "https://acme.zendesk.com/api/v2/ticket_fields.json") {
        return new Response(
          JSON.stringify({
            ticket_fields: [
              { id: 360011, title: "Facility Location" },
              { id: 360022, title: "Firmware Version" },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      throw new Error(`Unexpected URL: ${url}`);
    };

    const env = await createTestClientEnv(mockFetch);
    try {
      const result = await env.client.getTicket(
        "https://acme.zendesk.com/agent/tickets/12345"
      );

      assert.equal(result.ticket.id, 12345);
      assert.equal(
        result.ticket.subject,
        "Production PLC connectivity drop on Line 4"
      );
      assert.equal(result.ticket.created_at, "2026-11-10T14:20:00Z");
      assert.deepEqual(result.ticket.custom_fields, [
        { id: 360011, value: "plant_north", label: "Facility Location" },
        { id: 360022, value: "fw_2.4.1", label: "Firmware Version" },
      ]);
      assert.equal(result.rate_limit?.limit, 400);
      assert.equal(result.rate_limit?.remaining, 395);
      assert.match(
        result.ticket.description_note,
        /zendesk_list_ticket_comments/
      );
    } finally {
      env.cleanup();
    }
  });

  it("paginates ticket comments across multiple cursor pages and labels PUBLIC vs INTERNAL_PRIVATE_NOTE visibility", async () => {
    const mockFetch: typeof fetch = async (input) => {
      const url = new URL(String(input));
      assert.equal(url.pathname, "/api/v2/tickets/12345/comments.json");
      assert.equal(url.searchParams.get("include_inline_images"), "true");

      const afterCursor = url.searchParams.get("page[after]");
      if (!afterCursor) {
        return new Response(
          JSON.stringify({
            comments: [
              {
                id: 9001,
                author_id: 501,
                created_at: "2026-11-10T14:20:00Z",
                public: true,
                plain_body: "Customer reported intermittent packet loss.",
                attachments: [
                  {
                    id: 111,
                    file_name: "packet_capture.pcap",
                    content_type: "application/vnd.tcpdump.pcap",
                    size: 40960,
                    inline: false,
                    content_url:
                      "https://acme.zendesk.com/attachments/token/xyz/?name=packet_capture.pcap",
                  },
                ],
              },
              {
                id: 9002,
                author_id: 777,
                created_at: "2026-11-10T15:00:00Z",
                public: false,
                plain_body:
                  "Internal escalation note: checking switch port 14.",
                attachments: [
                  {
                    id: 112,
                    file_name: "../diagram.png",
                    content_type: "image/png",
                    size: 12000,
                    inline: true,
                    content_url: "https://external-cdn.example.org/diagram.png",
                  },
                ],
              },
            ],
            meta: {
              has_more: true,
              after_cursor: "cursor_page_2_token",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      assert.equal(afterCursor, "cursor_page_2_token");
      return new Response(
        JSON.stringify({
          comments: [
            {
              id: 9003,
              author_id: 777,
              created_at: "2026-11-11T09:15:30Z",
              public: true,
              plain_body: "Replaced patch cable on port 14; monitoring stable.",
              attachments: [],
            },
          ],
          meta: {
            has_more: false,
            after_cursor: null,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const env = await createTestClientEnv(mockFetch);
    try {
      const page1 = await env.client.listTicketComments(12345, { pageSize: 2 });
      assert.equal(page1.has_more, true);
      assert.equal(page1.next_cursor, "cursor_page_2_token");
      assert.match(page1.continuation_notice, /MORE COMMENTS REMAIN/);

      assert.equal(page1.comments[0].visibility, "PUBLIC");
      assert.equal(
        page1.comments[0].attachments[0].file_name,
        "packet_capture.pcap"
      );
      assert.equal(page1.comments[0].attachments[0].is_external_url, false);

      assert.equal(page1.comments[1].visibility, "INTERNAL_PRIVATE_NOTE");
      assert.equal(
        page1.comments[1].inline_attachments[0].file_name,
        "._diagram.png"
      );
      assert.equal(
        page1.comments[1].inline_attachments[0].is_external_url,
        true
      );

      // Fetch page 2 using next_cursor
      const page2 = await env.client.listTicketComments(12345, {
        pageSize: 2,
        cursor: page1.next_cursor ?? undefined,
      });
      assert.equal(page2.has_more, false);
      assert.equal(page2.next_cursor, null);
      assert.equal(page2.comments.length, 1);
      assert.equal(page2.comments[0].id, 9003);
      assert.match(page2.continuation_notice, /END OF THREAD/);
    } finally {
      env.cleanup();
    }
  });

  it("enforces type:ticket in search, reports 1,000-result search cap, and blocks beyond cap", async () => {
    let capturedQuery = "";
    const mockFetch: typeof fetch = async (input) => {
      const url = new URL(String(input));
      capturedQuery = url.searchParams.get("query") ?? "";
      return new Response(
        JSON.stringify({
          results: [
            {
              id: 12345,
              result_type: "ticket",
              subject: "Production PLC connectivity drop on Line 4",
              status: "open",
              priority: "high",
              created_at: "2026-11-10T14:20:00Z",
              updated_at: "2026-11-11T09:15:30Z",
              tags: ["plc"],
              description: "Initial report",
            },
          ],
          count: 1420,
          next_page:
            "https://acme.zendesk.com/api/v2/search.json?page=2&per_page=100",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const env = await createTestClientEnv(mockFetch);
    try {
      const searchRes = await env.client.searchTickets({
        query: "status:open plc",
        page: 1,
        perPage: 100,
      });

      assert.equal(capturedQuery, "type:ticket status:open plc");
      assert.equal(searchRes.enforced_query, "type:ticket status:open plc");
      assert.equal(searchRes.total_count, 1420);
      assert.equal(searchRes.search_cap_reached, true);
      assert.equal(searchRes.has_more, true);
      assert.equal(searchRes.next_page, 2);
      assert.match(searchRes.indexing_lag_notice, /indexing may lag/i);

      // Requesting page 11 at 100 per page exceeds the 1,000-result cap
      await assert.rejects(
        () =>
          env.client.searchTickets({
            query: "status:open plc",
            page: 11,
            perPage: 100,
          }),
        (err: unknown) =>
          err instanceof PolicyViolationError &&
          err.code === "SEARCH_RESULT_CAP_EXCEEDED"
      );
    } finally {
      env.cleanup();
    }
  });

  it("handles 401 with automatic token refresh, 429 with Retry-After backoff, and 403/404 cleanly", async () => {
    const sleepCalls: number[] = [];
    let ticketAttempts = 0;

    const mockFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url === "https://acme.zendesk.com/oauth/tokens") {
        return new Response(
          JSON.stringify({
            access_token: "fresh_token_after_401",
            refresh_token: "fresh_refresh_after_401",
            token_type: "bearer",
            scope: "tickets:read users:read",
            expires_in: 1800,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (url === "https://acme.zendesk.com/api/v2/tickets/12345.json") {
        ticketAttempts += 1;
        const authHeader = (init?.headers as Record<string, string>)?.[
          "Authorization"
        ];

        // 1st call: simulate 401 expired token
        if (ticketAttempts === 1) {
          assert.equal(authHeader, "Bearer valid_access_token_12345");
          return new Response(JSON.stringify({ error: "Couldn't authenticate you" }), {
            status: 401,
          });
        }

        // 2nd call: after token refresh, simulate 429 rate limit with Retry-After: 3
        if (ticketAttempts === 2) {
          assert.equal(authHeader, "Bearer fresh_token_after_401");
          return new Response(JSON.stringify({ error: "Rate limit exceeded" }), {
            status: 429,
            headers: { "Retry-After": "3" },
          });
        }

        // 3rd call: succeeds
        return new Response(
          JSON.stringify({
            ticket: {
              id: 12345,
              subject: "Recovered after 401 and 429",
              status: "solved",
              created_at: "2026-11-10T00:00:00Z",
              updated_at: "2026-11-11T00:00:00Z",
              description: "All good.",
              custom_fields: [],
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (url === "https://acme.zendesk.com/api/v2/tickets/99999.json") {
        return new Response(JSON.stringify({ error: "RecordNotFound" }), {
          status: 404,
        });
      }

      if (url === "https://acme.zendesk.com/api/v2/tickets/88888.json") {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403,
        });
      }

      if (url === "https://acme.zendesk.com/api/v2/tickets/77777.json") {
        return new Response(JSON.stringify({ error: "Rate limit too high" }), {
          status: 429,
          headers: { "Retry-After": "120" },
        });
      }

      throw new Error(`Unexpected URL: ${url}`);
    };

    const env = await createTestClientEnv(mockFetch, {
      maxRetries: 2,
      maxRetryAfterMs: 10_000,
      sleepCalls,
    });

    try {
      const recovered = await env.client.getTicket(12345, {
        resolveCustomFields: false,
      });
      assert.equal(recovered.ticket.subject, "Recovered after 401 and 429");
      assert.deepEqual(sleepCalls, [3000]);

      // 404 Not Found
      await assert.rejects(
        () => env.client.getTicket(99999),
        (err: unknown) =>
          err instanceof ZendeskApiError && err.status === 404
      );

      // 403 Forbidden
      await assert.rejects(
        () => env.client.getTicket(88888),
        (err: unknown) =>
          err instanceof ZendeskApiError && err.status === 403
      );

      // 429 Retry-After exceeding maxRetryAfterMs fails fast with RateLimitExceededError
      await assert.rejects(
        () => env.client.getTicket(77777),
        (err: unknown) =>
          err instanceof RateLimitExceededError &&
          err.status === 429 &&
          err.rateLimit?.retryAfterSeconds === 120
      );
    } finally {
      env.cleanup();
    }
  });
});
