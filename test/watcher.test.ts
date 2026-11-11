import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { it } from "node:test";
import { loadConfig } from "../src/config.js";
import { ZendeskApiClient } from "../src/zendesk-client.js";
import { checkTicketReplies, readReplyInbox } from "../src/watcher.js";

it("baselines all tickets, follows comment pages, deduplicates replies, and reads complete timestamp batches", async () => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),"zendesk-watch-"));
  const config=loadConfig({subdomain:"acme",oauthClientId:"test",oauthScopes:["read"],enableWrites:false,tokenFilePath:path.join(dir,"tokens.json")});
  let searches=0, pages=0;
  const future=new Date(Date.now()+1000).toISOString();
  const mock={
    searchTickets: async (args: any) => { searches++; assert.ok(!args.query.includes("assignee")); return {tickets:[{id:123}],total_count:1,has_more:false}; },
    listTicketComments: async (_: number,args: any) => {
      pages++;
      return {comments:[{id:args.cursor?2:1,created_at:future,public:!args.cursor,author_id:777}],has_more:!args.cursor,next_cursor:args.cursor?null:"next"};
    },
  } as unknown as Pick<ZendeskApiClient,"searchTickets"|"listTicketComments">;
  try {
    assert.equal((await checkTicketReplies(mock,config)).status,"baseline_created");
    assert.equal(searches,0);
    assert.equal((await checkTicketReplies(mock,config)).new_comments,2);
    assert.equal(pages,2);
    assert.equal((await checkTicketReplies(mock,config)).new_comments,0);
    const inbox=await readReplyInbox(config,undefined,1);
    assert.equal(inbox.updates.length,2); // Don't truncate equal detected_at values.
    assert.equal((await readReplyInbox(config,inbox.next_since!)).updates.length,0);
    assert.equal((await fs.stat(path.join(dir,"watch-acme","state.json"))).mode&0o777,0o600);
  } finally {await fs.rm(dir,{recursive:true,force:true});}
});

it("does not advance checkpoint after an incomplete poll", async () => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),"zendesk-watch-fail-"));
  const config=loadConfig({subdomain:"acme",oauthClientId:"test",oauthScopes:["read"],enableWrites:false,tokenFilePath:path.join(dir,"tokens.json")});
  const mock={searchTickets:async()=>({total_count:1001,tickets:[],has_more:true})} as unknown as ZendeskApiClient;
  try {
    await checkTicketReplies(mock,config);
    const before=await fs.readFile(path.join(dir,"watch-acme","state.json"),"utf8");
    await assert.rejects(checkTicketReplies(mock,config), /1,000/);
    const after=JSON.parse(await fs.readFile(path.join(dir,"watch-acme","state.json"),"utf8"));
    assert.equal(after.checked_through,JSON.parse(before).checked_through);
    assert.match(after.last_error,/1,000/);
    await assert.rejects(fs.stat(path.join(dir,"watch-acme","poll.lock")));
  } finally {await fs.rm(dir,{recursive:true,force:true});}
});
