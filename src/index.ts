#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { runOAuthSetupCli, runStatusCli } from "./auth-cli.js";
import { loadConfig } from "./config.js";
import { startStreamableHttpServer } from "./http-transport.js";
import { SafeLogger } from "./logger.js";
import { ZendeskOAuthManager } from "./oauth.js";
import { redactSecrets } from "./security.js";
import { createZendeskMcpServer } from "./server.js";
import { ZendeskApiClient } from "./zendesk-client.js";
import { checkTicketReplies } from "./watcher.js";

function printHelp(): void {
  process.stderr.write(
    `zendesk-mcp — Read-only MCP Server for Zendesk Support API\n\n` +
      `Usage:\n` +
      `  zendesk-mcp [serve] [--transport=stdio|http]   Start the MCP server (default: stdio)\n` +
      `  zendesk-mcp auth [--manual]                    Run OAuth 2.0 + PKCE authorization flow\n` +
      `  zendesk-mcp status [--verify]                  Inspect local OAuth token status\n` +
      `  zendesk-mcp --help                             Show this help message\n`
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }

  const transportArg = args.find((a) => a.startsWith("--transport="));
  const transportOverride = transportArg
    ? (transportArg.split("=")[1] as "stdio" | "http")
    : undefined;

  const config = loadConfig(
    transportOverride ? { transport: transportOverride } : {}
  );

  let oauthManagerRef: ZendeskOAuthManager | null = null;
  const knownSecrets = (): readonly (string | undefined)[] => [
    config.oauthClientSecret,
    config.httpBearerToken,
    ...(oauthManagerRef ? oauthManagerRef.getKnownSecrets() : []),
  ];

  const logger = new SafeLogger({
    level: config.logLevel,
    knownSecrets,
  });

  const oauthManager = new ZendeskOAuthManager({
    config,
    logger,
  });
  oauthManagerRef = oauthManager;

  const client = new ZendeskApiClient({
    config,
    oauthManager,
    logger,
  });

  const subcommand = args.find((a) => !a.startsWith("-")) ?? "serve";

  if (subcommand === "watch") {
    process.stderr.write(JSON.stringify(await checkTicketReplies(client, config)) + "\n");
    return;
  }

  if (subcommand === "auth") {
    const manualOnly = args.includes("--manual");
    await runOAuthSetupCli({
      config,
      oauthManager,
      client,
      logger,
      manualOnly,
    });
    return;
  }

  if (subcommand === "status") {
    const verifyLive = args.includes("--verify");
    await runStatusCli({
      config,
      client,
      verifyLive,
    });
    return;
  }

  if (subcommand !== "serve") {
    throw new Error(`Unknown command "${subcommand}". Run with --help for usage.`);
  }

  if (config.transport === "http") {
    const httpServer = await startStreamableHttpServer({
      config,
      client,
      logger,
      knownSecrets,
    });

    const shutdown = () => {
      logger.info("Shutting down Streamable HTTP server...");
      httpServer.close(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    return;
  }

  // Default: MCP stdio transport
  const mcpServer = createZendeskMcpServer({
    config,
    client,
    logger,
    knownSecrets,
  });
  const stdioTransport = new StdioServerTransport();
  await mcpServer.connect(stdioTransport);
  logger.info("Zendesk MCP server running on stdio", {
    tenant: config.subdomain,
    enableUserTool: config.enableUserTool,
  });
}

main().catch((err) => {
  const raw = err instanceof Error ? err.message : String(err);
  const safe = redactSecrets(raw, [
    process.env.ZENDESK_OAUTH_CLIENT_SECRET,
    process.env.MCP_HTTP_BEARER_TOKEN,
  ]);
  process.stderr.write(`[zendesk-mcp] [FATAL] ${safe}\n`);
  process.exit(1);
});
