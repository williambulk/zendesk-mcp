import crypto from "node:crypto";
import http from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ZendeskMcpConfig } from "./config.js";
import { ConfigurationError } from "./errors.js";
import { SafeLogger } from "./logger.js";
import { createZendeskMcpServer } from "./server.js";
import { ZendeskApiClient } from "./zendesk-client.js";

function verifyBearerHeader(
  authHeader: string | undefined,
  expectedToken: string
): boolean {
  if (!authHeader) return false;
  const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  if (!match) return false;
  const candidate = match[1].trim();
  const bufA = Buffer.from(candidate, "utf8");
  const bufB = Buffer.from(expectedToken, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export async function startStreamableHttpServer(options: {
  config: ZendeskMcpConfig;
  client: ZendeskApiClient;
  logger: SafeLogger;
  knownSecrets: () => readonly (string | undefined)[];
}): Promise<http.Server> {
  const { config, client, logger, knownSecrets } = options;

  if (!config.httpBearerToken || config.httpBearerToken.length < 16) {
    throw new ConfigurationError(
      "MCP_HTTP_BEARER_TOKEN (minimum 16 characters) is required for Streamable HTTP transport."
    );
  }
  const expectedBearer = config.httpBearerToken;

  const httpServer = http.createServer(async (req, res) => {
    try {
      const reqUrl = new URL(
        req.url ?? "/",
        `http://${config.httpHost}:${config.httpPort}`
      );

      if (reqUrl.pathname === "/healthz" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", service: "zendesk-mcp" }));
        return;
      }

      if (reqUrl.pathname !== "/mcp") {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not Found. Use /mcp endpoint." }));
        return;
      }

      // Enforce agent-to-MCP authentication boundary (distinct from Zendesk OAuth)
      if (!verifyBearerHeader(req.headers.authorization, expectedBearer)) {
        res.writeHead(401, {
          "Content-Type": "application/json",
          "WWW-Authenticate": 'Bearer realm="zendesk-mcp"',
        });
        res.end(
          JSON.stringify({
            error: "Unauthorized. Valid MCP_HTTP_BEARER_TOKEN is required.",
          })
        );
        return;
      }

      const mcpServer = createZendeskMcpServer({
        config,
        client,
        logger,
        knownSecrets,
      });

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });

      res.on("close", () => {
        void transport.close();
        void mcpServer.close();
      });

      await mcpServer.connect(transport);
      await transport.handleRequest(req, res);
    } catch (err) {
      logger.error("Unhandled error in Streamable HTTP handler", {
        error: err instanceof Error ? err.message : String(err),
      });
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal Server Error" }));
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(config.httpPort, config.httpHost, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });

  logger.info("Zendesk MCP Streamable HTTP server listening", {
    endpoint: `http://${config.httpHost}:${config.httpPort}/mcp`,
    tenant: config.subdomain,
  });

  return httpServer;
}
