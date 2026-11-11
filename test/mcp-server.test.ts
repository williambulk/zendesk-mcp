import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig } from "../src/config.js";
import { startStreamableHttpServer } from "../src/http-transport.js";
import { SafeLogger } from "../src/logger.js";
import { ZendeskOAuthManager, saveTokenSetAtomically } from "../src/oauth.js";
import { createZendeskMcpServer } from "../src/server.js";
import { ZendeskApiClient } from "../src/zendesk-client.js";

describe("MCP Server Protocol, Tool Registry, Read-Only Enforcement & HTTP Auth Boundary", () => {
  it("initializes MCP protocol, registers read and local checking tools with annotations, without ticket writes, and executes tool calls", async () => {
    const tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "zendesk-mcp-server-test-")
    );
    const tokenFilePath = path.join(tmpDir, "tokens.json");

    await saveTokenSetAtomically(tokenFilePath, {
      access_token: "mcp_test_secret_access_token",
      refresh_token: "mcp_test_secret_refresh_token",
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
      logLevel: "silent",
    });

    const logger = new SafeLogger({ level: "silent" });
    const mockFetch: typeof fetch = async (input) => {
      const url = new URL(String(input));
      if (url.pathname === "/api/v2/tickets/12345.json") {
        return new Response(
          JSON.stringify({
            ticket: {
              id: 12345,
              subject: "Sample Ticket #12345",
              status: "open",
              priority: "normal",
              created_at: "2026-11-11T01:00:00Z",
              updated_at: "2026-11-11T02:00:00Z",
              description: "Initial description body.",
              tags: ["sample"],
              custom_fields: [],
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.pathname === "/api/v2/users/me.json") {
        return new Response(
          JSON.stringify({
            user: {
              id: 777,
              name: "Jane Doe",
              email: "jane@example.com",
              role: "agent",
              active: true,
              verified: true,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      throw new Error(`Unexpected URL ${url.toString()}`);
    };

    const oauthManager = new ZendeskOAuthManager({
      config,
      logger,
      fetchFn: mockFetch,
    });
    const zdClient = new ZendeskApiClient({
      config,
      oauthManager,
      logger,
      fetchFn: mockFetch,
    });

    const mcpServer = createZendeskMcpServer({
      config,
      client: zdClient,
      logger,
      knownSecrets: () => oauthManager.getKnownSecrets(),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const mcpClient = new Client({
      name: "test-mcp-client",
      version: "1.0.0",
    });

    await mcpServer.connect(serverTransport);
    await mcpClient.connect(clientTransport);

    try {
      const { tools } = await mcpClient.listTools();
      const toolNames = tools.map((t) => t.name).sort();

      // Ticket writes remain absent when disabled.
      assert.deepEqual(toolNames, [
        "zendesk_check_replies",
        "zendesk_get_attachment",
        "zendesk_get_reply_updates",
        "zendesk_get_ticket",
        "zendesk_get_user",
        "zendesk_list_ticket_comments",
        "zendesk_list_ticket_fields",
        "zendesk_search_tickets",
      ]);

      for (const tool of tools) {
        assert.equal(
          tool.annotations?.readOnlyHint,
          tool.name !== "zendesk_check_replies",
          `Tool ${tool.name} read-only annotation`
        );
        assert.equal(
          tool.annotations?.destructiveHint,
          false,
          `Tool ${tool.name} must have destructiveHint=false`
        );
        assert.equal(
          tool.annotations?.idempotentHint,
          true,
          `Tool ${tool.name} must have idempotentHint=true`
        );
        assert.equal(
          tool.annotations?.openWorldHint,
          false,
          `Tool ${tool.name} must have openWorldHint=false`
        );
      }

      // Execute zendesk_get_ticket
      const ticketRes = await mcpClient.callTool({
        name: "zendesk_get_ticket",
        arguments: {
          ticket_id: "https://acme.zendesk.com/agent/tickets/12345",
          resolve_custom_fields: false,
        },
      });
      assert.ok(!ticketRes.isError);
      const contentArr = ticketRes.content as Array<{
        type: string;
        text: string;
      }>;
      const parsedTicket = JSON.parse(contentArr[0].text) as {
        untrusted_content_notice: string;
        ticket: { id: number; subject: string };
      };
      assert.equal(parsedTicket.ticket.id, 12345);
      assert.equal(parsedTicket.ticket.subject, "Sample Ticket #12345");
      assert.match(
        parsedTicket.untrusted_content_notice,
        /UNTRUSTED_TICKET_DATA/
      );

      // Execute zendesk_get_user
      const userRes = await mcpClient.callTool({
        name: "zendesk_get_user",
        arguments: { user_id: "me" },
      });
      assert.ok(!userRes.isError);
      const parsedUser = JSON.parse(
        (userRes.content as Array<{ type: string; text: string }>)[0].text
      ) as { user: { id: number; name: string; role: string } };
      assert.equal(parsedUser.user.id, 777);
      assert.equal(parsedUser.user.name, "Jane Doe");

      // Verify malicious cross-tenant URL returns structured PolicyViolationError
      const badRes = await mcpClient.callTool({
        name: "zendesk_get_ticket",
        arguments: {
          ticket_id: "https://evil.zendesk.com/agent/tickets/12345",
        },
      });
      assert.equal(badRes.isError, true);
      const parsedErr = JSON.parse(
        (badRes.content as Array<{ type: string; text: string }>)[0].text
      ) as { error_type: string; error_code: string };
      assert.equal(parsedErr.error_type, "PolicyViolationError");
      assert.equal(parsedErr.error_code, "CROSS_TENANT_URL");
    } finally {
      await mcpClient.close();
      await mcpServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("enforces distinct MCP_HTTP_BEARER_TOKEN authentication on Streamable HTTP transport", async () => {
    const tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "zendesk-mcp-http-test-")
    );
    const tokenFilePath = path.join(tmpDir, "tokens.json");

    await saveTokenSetAtomically(tokenFilePath, {
      access_token: "zd_oauth_token_distinct_from_mcp",
      token_type: "bearer",
      scope: "tickets:read",
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
      oauthScopes: ["tickets:read"],
      enableUserTool: false,
      transport: "http",
      httpHost: "127.0.0.1",
      httpPort: 0, // ephemeral port
      httpBearerToken: "mcp-gateway-secret-token-987654321",
      logLevel: "silent",
    });

    const logger = new SafeLogger({ level: "silent" });
    const oauthManager = new ZendeskOAuthManager({ config, logger });
    const zdClient = new ZendeskApiClient({ config, oauthManager, logger });

    const httpServer = await startStreamableHttpServer({
      config,
      client: zdClient,
      logger,
      knownSecrets: () => oauthManager.getKnownSecrets(),
    });

    const addr = httpServer.address();
    assert.ok(addr && typeof addr === "object");
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    try {
      // 1. Unauthenticated request must be rejected with 401
      const unauthRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      assert.equal(unauthRes.status, 401);

      // 2. Trying to use the Zendesk OAuth token as the MCP Bearer token must ALSO be rejected with 401
      const wrongTokenRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer zd_oauth_token_distinct_from_mcp",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      assert.equal(wrongTokenRes.status, 401);

      // 3. Authenticated MCP client with MCP_HTTP_BEARER_TOKEN succeeds
      const mcpClient = new Client({
        name: "http-mcp-client",
        version: "1.0.0",
      });
      const transport = new StreamableHTTPClientTransport(
        new URL(`${baseUrl}/mcp`),
        {
          requestInit: {
            headers: {
              Authorization: "Bearer mcp-gateway-secret-token-987654321",
            },
          },
        }
      );
      await mcpClient.connect(transport);
      const { tools } = await mcpClient.listTools();
      // Identity tool is omitted when disabled.
      assert.deepEqual(
        tools.map((t) => t.name).sort(),
        [
          "zendesk_check_replies",
          "zendesk_get_attachment",
        "zendesk_get_reply_updates",
          "zendesk_get_ticket",
          "zendesk_list_ticket_comments",
          "zendesk_list_ticket_fields",
          "zendesk_search_tickets",
        ]
      );
      await mcpClient.close();
    } finally {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("spawns the compiled dist/index.js entrypoint over real stdio pipes and completes MCP tool discovery", async () => {
    const tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "zendesk-mcp-stdio-proc-test-")
    );
    const tokenFilePath = path.join(tmpDir, "tokens.json");

    const stdioTransport = new StdioClientTransport({
      command: process.execPath,
      args: [path.resolve(process.cwd(), "dist/index.js")],
      env: {
        ...process.env,
        ZENDESK_SUBDOMAIN: "acme",
        ZENDESK_ENABLE_WRITES: "false",
        ZENDESK_OAUTH_CLIENT_ID: "zd_stdio_client",
        ZENDESK_TOKEN_FILE: tokenFilePath,
        ZENDESK_LOG_LEVEL: "info",
      },
      stderr: "pipe",
    });

    const mcpClient = new Client({
      name: "stdio-subprocess-client",
      version: "1.0.0",
    });

    await mcpClient.connect(stdioTransport);
    try {
      const { tools } = await mcpClient.listTools();
      assert.equal(tools.length, 8);

      // Calling a tool without a token file should return a structured ReauthorizationRequiredError over stdio
      const res = await mcpClient.callTool({
        name: "zendesk_get_ticket",
        arguments: { ticket_id: 12345 },
      });
      assert.equal(res.isError, true);
      const parsed = JSON.parse(
        (res.content as Array<{ type: string; text: string }>)[0].text
      ) as { error_type: string; error_code: string };
      assert.equal(parsed.error_type, "ReauthorizationRequiredError");
      assert.equal(parsed.error_code, "no_stored_token");
    } finally {
      await mcpClient.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
