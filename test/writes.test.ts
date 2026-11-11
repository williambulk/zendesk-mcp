import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig } from "../src/config.js";
import { SafeLogger } from "../src/logger.js";
import { ZendeskOAuthManager, saveTokenSetAtomically } from "../src/oauth.js";
import { ZendeskApiClient } from "../src/zendesk-client.js";
import { createZendeskMcpServer } from "../src/server.js";
import { validateOutboundRequest } from "../src/security.js";

const stamp = "2026-11-11T00:00:00Z";
async function setup(run: (client: ZendeskApiClient, config: ReturnType<typeof loadConfig>, calls: Array<{method: string; body: any}>) => Promise<void>, response: number | "timeout" = 200) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "zendesk-writes-"));
  const config = loadConfig({ subdomain: "acme", oauthClientId: "test", tokenFilePath: path.join(dir, "tokens.json"), oauthScopes: ["read", "tickets:write"], enableWrites: true, logLevel: "silent" });
  await saveTokenSetAtomically(config.tokenFilePath, { access_token: "test", token_type: "bearer", scope: "read tickets:write", obtained_at: Date.now(), expires_at: Date.now()+3600_000, subdomain: "acme", grant_type: "authorization_code" });
  const calls: Array<{method: string; body: any}> = [];
  const fetchFn: typeof fetch = async (_, init) => {
    calls.push({method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null});
    if (init?.method === "GET") return Response.json({user: {id: 777, name: "William", role: "admin"}});
    if (response === "timeout") throw new Error("timeout");
    return Response.json({ticket: {id: 123, updated_at: stamp, status: "open"}, audit: {id: 456}}, {status: response});
  };
  const logger = new SafeLogger({level: "silent"});
  const manager = new ZendeskOAuthManager({config, logger, fetchFn});
  try { await run(new ZendeskApiClient({config, logger, oauthManager: manager, fetchFn}), config, calls); }
  finally { await fs.rm(dir, {recursive: true, force: true}); }
}

it("limits write routes even with write mode enabled", () => {
  assert.doesNotThrow(() => validateOutboundRequest("https://acme.zendesk.com/api/v2/tickets/123.json", "PUT", "acme", true));
  for (const route of ["tickets.json", "tickets/update_many.json", "users/123.json", "tickets/123/comments.json"]) {
    assert.throws(() => validateOutboundRequest(`https://acme.zendesk.com/api/v2/${route}`, "PUT", "acme", true));
  }
  assert.throws(() => validateOutboundRequest("https://evil.zendesk.com/api/v2/tickets/123.json", "PUT", "acme", true));
});

it("requires explicit write enablement and scope", async () => {
  assert.throws(() => loadConfig({subdomain:"acme",oauthClientId:"test",enableWrites:true,oauthScopes:["read"]}), /tickets:write/);
  await setup(async (client, config, calls) => {
    config.enableWrites = false;
    await assert.rejects(client.updateTicket({ticket_id:123,updated_stamp:stamp,fields:{priority:"high"}}), /require/);
    assert.equal(calls.length, 0);
  });
});

it("sends only specified fields with optimistic concurrency protection", async () => {
  await setup(async (client, _, calls) => {
    await client.updateTicket({ticket_id:123,updated_stamp:stamp,fields:{priority:"high",custom_fields:[{id:11,value:"option_tag"}]}});
    assert.deepEqual(calls[0], {method:"PUT",body:{ticket:{priority:"high",custom_fields:[{id:11,value:"option_tag"}],safe_update:true,updated_stamp:stamp}}});
    await assert.rejects(client.updateTicket({ticket_id:123,updated_stamp:stamp,fields:{comment:{body:"injected"}}} as any));
    assert.equal(calls.length, 1);
  });
});

it("pins comment author to authenticated user and explicitly distinguishes public/internal", async () => {
  await setup(async (client, _, calls) => {
    for (const visibility of ["public", "internal"] as const) await client.replyTicket({ticket_id:123,updated_stamp:stamp,body:"Reviewed reply",visibility});
    const writes=calls.filter(c=>c.method==="PUT");
    assert.equal(writes[0].body.ticket.comment.public, true);
    assert.equal(writes[1].body.ticket.comment.public, false);
    assert.equal(writes[0].body.ticket.comment.author_id, 777);
    await assert.rejects(client.replyTicket({ticket_id:123,updated_stamp:stamp,body:"no visibility"} as any));
    await assert.rejects(client.replyTicket({ticket_id:123,updated_stamp:stamp,body:"bad",visibility:"public",author_id:999} as any));
    assert.equal(calls.filter(c=>c.method==="PUT").length, 2);
  });
});

for (const failure of [409, 429, 500, "timeout"] as const) it(`never retries a write after ${failure}`, async () => {
  await setup(async (client, _, calls) => {
    await assert.rejects(client.replyTicket({ticket_id:123,updated_stamp:stamp,body:"Reply",visibility:"public"}), failure===409 ? /changed/ : failure==="timeout" ? /outcome is unknown/ : /No automatic retry/);
    assert.equal(calls.filter(c=>c.method==="PUT").length, 1);
  }, failure);
});

it("registers write tools with mutation annotations and executes validated calls over MCP", async () => {
  await setup(async (api, config, calls) => {
    const server = createZendeskMcpServer({config, client:api, logger:new SafeLogger({level:"silent"})});
    const client = new Client({name:"writes-test",version:"1"});
    const [ct,st] = InMemoryTransport.createLinkedPair();
    await server.connect(st); await client.connect(ct);
    try {
      const {tools}=await client.listTools();
      const writes=tools.filter(t=>["zendesk_reply_ticket","zendesk_update_ticket_fields"].includes(t.name));
      assert.equal(writes.length,2);
      for (const tool of writes) {assert.equal(tool.annotations?.readOnlyHint,false);assert.equal(tool.annotations?.idempotentHint,false);}
      const bad = await client.callTool({name:"zendesk_reply_ticket",arguments:{ticket_id:123,updated_stamp:stamp,body:"missing visibility"}});
      assert.equal(bad.isError,true); assert.equal(calls.length,0);
      const good=await client.callTool({name:"zendesk_reply_ticket",arguments:{ticket_id:123,updated_stamp:stamp,body:"Reply",visibility:"public"}});
      assert.ok(!good.isError); assert.equal(calls.filter(c=>c.method==="PUT").length,1);
    } finally {await client.close(); await server.close();}
  });
});
