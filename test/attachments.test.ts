import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { attachmentImageMime, attachmentText, downloadAttachment, MAX_ATTACHMENT_BYTES, validateAttachmentDownloadUrl } from "../src/attachment-reader.js";
import { loadConfig } from "../src/config.js";
import { SafeLogger } from "../src/logger.js";
import { ZendeskOAuthManager, saveTokenSetAtomically } from "../src/oauth.js";
import { ZendeskApiClient } from "../src/zendesk-client.js";
import { createZendeskMcpServer } from "../src/server.js";

const tenantUrl = "https://acme.zendesk.com/attachments/token/file/?name=test.txt";
const download = (fetchFn: typeof fetch, url = tenantUrl) => downloadAttachment({url,subdomain:"acme",accessToken:"private-token",timeoutMs:1000,fetchFn});

it("allows only HTTPS Zendesk attachment hosts and rejects arbitrary URLs", () => {
  for (const url of ["http://acme.zendesk.com/attachments/a", "https://acme.zendesk.com/api/v2/users/me.json", "https://evil.zendesk.com/attachments/a", "https://127.0.0.1/file", "https://p1.zdusercontent.com.evil.test/a", "https://user:password@acme.zendesk.com/attachments/a", "https://acme.zendesk.com:8443/attachments/a"]) assert.throws(()=>validateAttachmentDownloadUrl(url,"acme"));
  assert.equal(validateAttachmentDownloadUrl(tenantUrl,"acme").sameTenant,true);
  assert.equal(validateAttachmentDownloadUrl("https://p17.zdusercontent.com/attachment/a","acme").sameTenant,false);
});

it("never sends credentials to storage or restores them after a CDN redirect", async () => {
  const calls: Array<{url:string;init:RequestInit|undefined}>=[];
  const fetchFn: typeof fetch=async (input,init) => {
    calls.push({url:String(input),init});
    if (calls.length===1) return new Response(null,{status:302,headers:{location:"https://p17.zdusercontent.com/attachment/a"}});
    if (calls.length===2) return new Response(null,{status:302,headers:{location:tenantUrl}});
    return new Response("file",{headers:{"content-type":"text/plain"}});
  };
  assert.equal((await download(fetchFn)).bytes.toString(),"file");
  assert.equal(new Headers(calls[0].init?.headers).get("authorization"),"Bearer private-token");
  for (const call of calls.slice(1)) assert.equal(new Headers(call.init?.headers).has("authorization"),false);
  for (const call of calls) assert.equal(call.init?.redirect,"manual");
});

it("rejects an untrusted redirect before fetching it", async () => {
  let calls=0;
  await assert.rejects(download(async()=>{calls++;return new Response(null,{status:302,headers:{location:"http://169.254.169.254/latest/meta-data/"}});}),/HTTPS/);
  assert.equal(calls,1);
});

it("enforces declared and streamed download limits", async () => {
  await assert.rejects(download(async()=>new Response("small",{headers:{"content-length":String(MAX_ATTACHMENT_BYTES+1)}})),/10 MiB/);
  const stream=new ReadableStream<Uint8Array>({start(c){c.enqueue(new Uint8Array(MAX_ATTACHMENT_BYTES));c.enqueue(new Uint8Array(1));c.close();}});
  await assert.rejects(download(async()=>new Response(stream)),/10 MiB/);
});

it("bounds redirect chains and redacts signed URLs from network failures", async () => {
  let calls=0;
  await assert.rejects(download(async()=>{calls++;return new Response(null,{status:302,headers:{location:tenantUrl}});}),/too long/);
  assert.equal(calls,5);
  await assert.rejects(download(async()=>{throw new Error("failed private-token https://signed-url.example/secret");}), e=> e instanceof Error && !/private-token|signed-url/.test(e.message));
});

it("sniffs images and treats HTML and oversized text as untrusted bounded text", () => {
  assert.equal(attachmentImageMime(Buffer.from([137,80,78,71,13,10,26,10])),"image/png");
  assert.equal(attachmentImageMime(Buffer.from("<script>fake image</script>")),null);
  assert.deepEqual(attachmentText(Buffer.from("abcdef"),"text/plain",3),{text:"abc",truncated:true});
  assert.equal(attachmentText(Buffer.from("<p>Hello</p><script>bad()</script>"),"text/html",100)?.text,"Hello");
});

async function attachmentEnv(run:(client:ZendeskApiClient,config:ReturnType<typeof loadConfig>,calls:string[])=>Promise<void>, options: { scan?:string; belongs?:boolean; content?:Buffer; mime?:string }={}) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),"zendesk-attachment-"));
  const config=loadConfig({subdomain:"acme",oauthClientId:"test",enableWrites:false,oauthScopes:["read","ticket_attachments:read"],tokenFilePath:path.join(dir,"tokens.json"),logLevel:"silent"});
  await saveTokenSetAtomically(config.tokenFilePath,{access_token:"token",scope:"read ticket_attachments:read",token_type:"bearer",obtained_at:Date.now(),expires_at:Date.now()+3600_000,subdomain:"acme",grant_type:"authorization_code"});
  const calls:string[]=[];
  const fetchFn: typeof fetch=async input=> {
    const url=new URL(String(input));calls.push(url.pathname);
    if (url.pathname==="/api/v2/tickets/123/comments.json") return Response.json({comments:[{id:1,attachments:options.belongs===false?[]:[{id:11,file_name:"file",content_url:tenantUrl}]}],meta:{has_more:false}});
    if (url.pathname==="/api/v2/attachments/11.json") return Response.json({attachment:{id:11,file_name:"file",content_url:tenantUrl,content_type:options.mime??"text/plain",size:5,malware_scan_result:options.scan??"malware_not_found"}});
    if (url.pathname==="/attachments/token/file/") return new Response(options.content??Buffer.from("Hello"),{headers:{"content-type":options.mime??"text/plain"}});
    throw new Error("Unexpected URL");
  };
  const logger=new SafeLogger({level:"silent"});
  const manager=new ZendeskOAuthManager({config,logger,fetchFn});
  try {await run(new ZendeskApiClient({config,logger,oauthManager:manager,fetchFn}),config,calls);}
  finally {await fs.rm(dir,{recursive:true,force:true});}
}

it("verifies ticket membership before accessing an attachment", async () => {
  await attachmentEnv(async(client,_,calls)=>{
    await assert.rejects(client.readTicketAttachment(123,11),/not present/);
    assert.deepEqual(calls,["/api/v2/tickets/123/comments.json"]);
  },{belongs:false});
});

for (const scan of ["malware_found","failed_to_scan","not_scanned"]) it(`refuses downloading attachments with scan result ${scan}`,async()=> {
  await attachmentEnv(async(client,_,calls)=>{
    await assert.rejects(client.readTicketAttachment(123,11),/malware scan/);
    assert.equal(calls.length,2);
  },{scan});
});

for (const kind of ["text","image","pdf"] as const) it(`returns ${kind} attachment contents through MCP`, async () => {
  const options=kind==="image"?{content:Buffer.from([137,80,78,71,13,10,26,10]),mime:"image/png"}:kind==="pdf"?{content:Buffer.from("%PDF-1.7\nfixture"),mime:"application/pdf"}:{};
  await attachmentEnv(async(api,config,calls)=> {
    const server=createZendeskMcpServer({config,client:api,logger:new SafeLogger({level:"silent"})});
    const client=new Client({name:"attachments-test",version:"1"});
    const [ct,st]=InMemoryTransport.createLinkedPair();await server.connect(st);await client.connect(ct);
    try {
      const metadata=await client.callTool({name:"zendesk_get_attachment",arguments:{ticket_id:123,attachment_id:11}});
      assert.ok(!metadata.isError);assert.equal(calls.length,2);
      const result=await client.callTool({name:"zendesk_get_attachment",arguments:{ticket_id:123,attachment_id:11,include_content:true}});
      assert.ok(!result.isError);
      const content=result.content as Array<{type:string;text?:string}>;
      assert.equal(content[1].type,kind==="text"?"text":kind==="image"?"image":"resource");
      if (kind==="text") assert.equal(JSON.parse(content[1].text!).untrusted_attachment_text,"Hello");
    } finally {await client.close();await server.close();}
  },options);
});
