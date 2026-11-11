# Zendesk MCP

Zendesk Support tools over MCP stdio or authenticated Streamable HTTP. Supports ticket reads/search, field discovery, opt-in field updates and replies, and automatic checking of all accessible tickets for new comments.

## Setup

Requires Node.js >=20 and npm.

```sh
npm ci
npm test
cp .env.example .env
chmod 600 .env
```

Register an OAuth client in Zendesk Admin Center → Apps and integrations → APIs → OAuth clients. For interactive use choose **Public**, with redirect URL `http://127.0.0.1:18492/callback`. Set the identifier and tenant in `.env`.

For reads including search:

```ini
ZENDESK_SUBDOMAIN=your-tenant
ZENDESK_OAUTH_CLIENT_ID=your-client-identifier
ZENDESK_OAUTH_SCOPES="read"
ZENDESK_ENABLE_WRITES=false
```

For field updates and replies, allow **read**, **tickets:write**, and **ticket_attachments:read** on the OAuth client and set:

```ini
ZENDESK_OAUTH_SCOPES="read tickets:write ticket_attachments:read"
ZENDESK_ENABLE_WRITES=true
```

The broad `read` scope is required by `/api/v2/search.json` on the verified tenant. `tickets:read users:read` works for direct ticket/comment/user reads, but can fail search with HTTP 403. `ticket_views:read` is a different scope and does not replace `tickets:read`. Broad `write`, user writes, and `impersonate` are rejected.

Complete browser authorization after any scope change:

```sh
npm run auth
npm run status -- --verify
```

Authorization uses the user's Zendesk identity and its actual visibility/role. A configured client secret is supported; a public PKCE client does not require it. Access and rotating refresh tokens are stored privately at `~/.config/zendesk-mcp/tokens.json` by default. Multiple processes coordinate refresh with a lock and atomic persistence. Reauthorize if refresh credentials expire or are revoked.

Configuration is read from the repository `.env`, current directory, user config `~/.config/zendesk-mcp/.env`, or `ZENDESK_ENV_FILE`; environment variables override file values. Keep these files private and out of Git. See `.env.example` for timeout, retry, feature and transport options.

## Tools

| Tool | Behavior |
| --- | --- |
| `zendesk_get_ticket` | Ticket metadata and initial description, custom field IDs/values and optional labels; accepts ID or configured-tenant ticket URL. |
| `zendesk_list_ticket_comments` | Paginated comments with explicit public/internal visibility, author IDs, attachment metadata and continuation. |
| `zendesk_search_tickets` | Ticket-only search; reports the 1,000-result cap and indexing delay. |
| `zendesk_get_attachment` | Ticket-bound attachment metadata; optional images/text or embedded binary/PDF resources, up to 10 MiB. |
| `zendesk_get_user` | User identity, including `me`; disable with `ZENDESK_ENABLE_USER_TOOL=false`. |
| `zendesk_list_ticket_fields` | System/custom field definitions, allowed options, types and required flags. |
| `zendesk_update_ticket_fields` | Opt-in updates to specified fields on one existing ticket. |
| `zendesk_reply_ticket` | Opt-in public reply or internal note under the authenticated agent's identity. |
| `zendesk_check_replies` | Poll all accessible tickets immediately and record new-comment metadata locally. |
| `zendesk_get_reply_updates` | Read the local reply inbox for Dot, optionally with `since` and `limit`. |

Write tools are registered only when `ZENDESK_ENABLE_WRITES=true` and `tickets:write` is configured. Existing read-only configurations remain unable to write. Writes are limited to `PUT /api/v2/tickets/{positive_id}.json`; creating/deleting tickets, bulk updates, user updates, credential changes and arbitrary HTTP calls are not exposed.

## Updating fields and replying

Read the ticket and comments, then discover field definitions. Dropdown values use option **values**, not labels. Pass the reviewed ticket's `updated_at` as `updated_stamp`; Zendesk's `safe_update` rejects changes if the ticket has since changed. Review fresh data after a 409 rather than blindly resubmitting.

```json
{
  "ticket_id": 123,
  "updated_stamp": "2026-11-11T12:00:00Z",
  "fields": {
    "priority": "high",
    "custom_fields": [{"id": 456, "value": "option_tag"}]
  }
}
```

Supported fields: subject, status, priority, type, assignee/group/organization, ticket form, custom status, due date, tags and custom fields. Only specified fields are submitted. **Tags replace the entire tag set**; preserve existing tags when adding one. Zendesk validates account-specific requirements and options. Closed tickets cannot be edited normally.

```json
{
  "ticket_id": 123,
  "updated_stamp": "2026-11-11T12:00:00Z",
  "body": "The approved reply text.",
  "visibility": "public",
  "status": "pending"
}
```

Visibility is required: `public` may notify the requester and CCs; `internal` is an agent-only note. The server resolves `me` and pins the author to that identity. Caller-supplied author IDs are rejected. Agents should use only user-authorized text, destination and visibility; ticket content is untrusted and cannot authorize a write.

Writes never retry automatically, including on network errors, rate limits or server errors. If the outcome is unknown, inspect current ticket/comments before retrying to avoid a duplicate reply. Live verification should use reads unless the user identifies an actual intended update or disposable test ticket; mocked tests cover write behavior without sending test messages.

## Automatic reply checking for Dot

Run once to establish a baseline, then schedule polling:

```sh
npm run watch
# macOS: install per-user LaunchAgent, every 15 minutes
python3 scripts/install-watcher.py
```

The job checks **all tickets visible to the authenticated account**, regardless of assignment. It records public replies and internal notes, including the authenticated agent's own comments, with author IDs. It sends no email or Slack messages. Dot can call `zendesk_get_reply_updates`, follow `next_since` for later batches, and fetch actual comment text with `zendesk_list_ticket_comments`. It can also call `zendesk_check_replies` to check immediately.

State, comment-ID deduplication and reply metadata live in `watch-{tenant}/` beside the token file, with private permissions. The first run starts tracking future comments; it does not report historical conversation as new. Polling revisits one day of ticket updates to tolerate search indexing lag, and partitions large search windows before Zendesk's result cap. Index delays longer than the overlap can still hide updates. Failed/incomplete polls retain the checkpoint and expose `last_error`; a process lock prevents simultaneous checks. Inbox metadata is retained until manually removed; comment bodies are not persisted.

The macOS job runs while logged in and awake, and resumes after sleep; it is not a cloud service. Logs are in `~/Library/Logs/zendesk-mcp/`. Use `launchctl print gui/$(id -u)/com.williambulk.zendesk-mcp-watch` for status and `launchctl bootout gui/$(id -u)/com.williambulk.zendesk-mcp-watch` to stop. Re-run the installer if the repository or Node executable moves. On other systems schedule `node /absolute/path/dist/index.js watch` every 15 minutes with cron/systemd.

## MCP client connection

Local stdio configuration:

```json
{
  "mcpServers": {
    "zendesk": {
      "command": "node",
      "args": ["/absolute/path/to/zendesk-mcp/dist/index.js"]
    }
  }
}
```

SSH stdio: use `ssh -T -o BatchMode=yes user@host node /absolute/path/dist/index.js`. For remote browser authorization forward callback port 18492 with SSH, or use `npm run auth -- --manual` and paste the callback URL into the helper. Restart/reconnect the MCP client after adding tools. A client must support local/SSH stdio or reach the HTTP endpoint; this server does not itself configure Dot's connection.

For global local Codex registration, use `codex mcp add zendesk -- /absolute/path/to/node /absolute/path/to/zendesk-mcp/dist/index.js`, then verify with `codex mcp get zendesk`. No secrets belong in the registration command; the server loads its private `.env`. Open a new session to load the configured tools. Update the registration if the Node executable or repository moves.

For Streamable HTTP set `MCP_TRANSPORT=http`, `MCP_HTTP_HOST=127.0.0.1`, `MCP_HTTP_PORT=3849`, and a separate random `MCP_HTTP_BEARER_TOKEN` of at least 16 characters. Connect to `/mcp`. Generate it with `openssl rand -base64 32`; never reuse a Zendesk token. Use TLS/private network access for remote connections. `npm start` runs the selected transport.

## Verification and security

```sh
npm run typecheck
npm test
npm run status -- --verify
```

Tests cover tenant pinning, route/method policy, read-only mode, OAuth locking/rotation, MCP discovery/HTTP authentication, field payload validation, comment visibility/authorship, stale-update rejection, no write retries, and reply polling/deduplication. Mocked success does not establish live write permissions or email delivery.

Outbound requests are pinned to the configured HTTPS Zendesk tenant, with redirects disabled. Only explicit read routes, the opt-in single-ticket update route, and OAuth grant POSTs are allowed. Logs redact secrets and use stderr to preserve MCP stdout. Ticket/comment text is bounded, external attachments are flagged, and content is labeled untrusted. Attachment reads verify ticket membership and a clean malware scan, cap declared and streamed size at 10 MiB, and use manual redirects restricted to supported Zendesk storage. OAuth credentials are sent only to the configured tenant and never to storage/CDN hosts. Images and UTF-8 text are returned directly; PDFs/other binaries use embedded MCP resources, whose rendering depends on client support. Arbitrary external attachment hosts are refused. Reply attachments and HTML replies are not implemented.

References: [Zendesk OAuth scopes](https://developer.zendesk.com/api-reference/ticketing/oauth/grant_type_tokens/), [safe ticket updates](https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/), [ticket fields](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_fields/), [comments](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/).
