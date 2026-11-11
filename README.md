# Zendesk MCP (`zendesk-mcp`)

A small, hardened, strictly **read-only** Model Context Protocol (MCP) server for the Zendesk Support REST API, built with the official `@modelcontextprotocol/sdk` and OAuth 2.0 + PKCE.

Designed to be cloned onto a homelab or workstation and connected to any MCP-compatible LLM/AI client (either locally over `stdio`, remotely over `ssh -T` using `stdio`, or via authenticated Streamable HTTP).

---

## Features & Security Controls

1. **Read-Only by Design & Enforcement**:
   - Exposes only four read-only tools (`zendesk_get_ticket`, `zendesk_list_ticket_comments`, `zendesk_search_tickets`, `zendesk_get_user`), all annotated with `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`.
   - Enforces a strict outbound HTTP allowlist (`GET` only for `/api/v2/*` routes; narrow `POST` exception solely for `/oauth/tokens`). Blocks the deprecated `/api/v2/oauth/tokens` endpoint.
   - Pins all requests to `https://{ZENDESK_SUBDOMAIN}.zendesk.com` and disables automatic redirect following (`redirect: "manual"`) so OAuth tokens are never leaked to external hosts.
2. **OAuth 2.0 + PKCE with Atomic Rotation & Cross-Process Locking**:
   - Uses Zendesk's current OAuth grant endpoint (`POST https://{subdomain}.zendesk.com/oauth/tokens`) rather than deprecated API tokens.
   - Rejects broad or write OAuth scopes (`write`, `tickets:write`, etc.); defaults to `tickets:read users:read`.
   - Persists rotated access and refresh tokens atomically in a `0600` file inside a `0700` directory (`~/.config/zendesk-mcp/tokens.json` by default).
   - Coordinates token refreshes across concurrent MCP `stdio` processes using an exclusive lockfile (`tokens.json.lock`) and disk re-read so rotated single-use refresh tokens never race.
3. **Complete Conversation & Pagination Fidelity**:
   - Separates initial ticket metadata (`zendesk_get_ticket`) from the paginated conversation thread (`zendesk_list_ticket_comments`).
   - Preserves custom field IDs and values and optionally resolves human-readable field titles via `/api/v2/ticket_fields.json`.
   - Clearly labels comment visibility (`PUBLIC` vs `INTERNAL_PRIVATE_NOTE`) and explicitly reports `has_more` and `next_cursor` so agents never assume a multi-page thread was read in full.
   - Enforces `type:ticket` on all searches, reports Zendesk's 1,000-result search cap, and notes search-indexing lag.
4. **Untrusted Content & Secret Redaction**:
   - Returns plain text (`plain_body` or stripped HTML fallback), flags external attachment URLs (`is_external_url: true`), sanitizes filenames, and wraps responses with prompt-injection data boundaries.
   - Logs exclusively to `stderr` with automatic redaction of tokens, secrets, authorization codes, and PKCE verifiers.

---

## MCP Tools

| Tool | Zendesk Endpoint | Description |
| :--- | :--- | :--- |
| `zendesk_get_ticket` | `GET /api/v2/tickets/{id}.json` | Retrieve ticket metadata, status, tags, custom fields (IDs, values, and resolved labels), and initial description. Accepts a positive ticket ID (`12345`), `#12345`, or an exact `https://{subdomain}.zendesk.com/agent/tickets/{id}` URL. |
| `zendesk_list_ticket_comments` | `GET /api/v2/tickets/{id}/comments.json` | Retrieve paginated ticket comments (`page[size]`, `page[after]`, `include_inline_images=true`), author IDs, raw timestamps, `PUBLIC` vs `INTERNAL_PRIVATE_NOTE` visibility, plain text, and attachment metadata. |
| `zendesk_search_tickets` | `GET /api/v2/search.json` | Search tickets using Zendesk search syntax with `type:ticket` automatically enforced. Reports total count, pagination, 1,000-result cap status, and indexing lag notice. |
| `zendesk_get_user` | `GET /api/v2/users/{id\|me}.json` | Resolve user identity/name/role by positive user ID or `"me"` (authenticated agent). Can be disabled via `ZENDESK_ENABLE_USER_TOOL=false` if only `tickets:read` scope is granted. |

---

## Setup & Installation (On Target Computer / Homelab)

### Prerequisites
- **Node.js 20.0.0+** (`node -v`) and `npm`

### 1. Clone, Install, Build, and Test

```bash
git clone <repo-url> zendesk-mcp
cd zendesk-mcp
npm ci
npm run build
npm test
```

### 2. Register an OAuth Client in Zendesk Admin Center

Ask a Zendesk administrator for the target tenant (e.g. `acme`) to register an OAuth client in **Zendesk Admin Center -> Apps and integrations -> APIs -> OAuth Clients**:

- **Client Name**: `Zendesk Read-Only MCP`
- **Unique Identifier (`client_id`)**: e.g. `zendesk_readonly_mcp`
- **Client Kind**: **Public** (recommended for PKCE operator flow) or **Confidential** (if a client secret is also stored on the homelab)
- **Redirect URLs**: `http://127.0.0.1:18492/callback`
- **Allowed Scopes** (if configurable on the client): `tickets:read`, `users:read`

### 3. Configure `.env`

Create a private `.env` file in the repository root or at `~/.config/zendesk-mcp/.env`:

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set your tenant and OAuth Client ID:

```ini
ZENDESK_SUBDOMAIN=acme
ZENDESK_OAUTH_CLIENT_ID=your_oauth_client_unique_identifier
ZENDESK_OAUTH_SCOPES="tickets:read users:read"
ZENDESK_OAUTH_REDIRECT_URI=http://127.0.0.1:18492/callback
ZENDESK_TOKEN_FILE=~/.config/zendesk-mcp/tokens.json
```

> **Note**: If your OAuth client only grants `tickets:read` (without `users:read`), set `ZENDESK_OAUTH_SCOPES="tickets:read"` and `ZENDESK_ENABLE_USER_TOOL=false`.

### 4. Authorize with Zendesk OAuth 2.0 + PKCE

Run the interactive OAuth helper on the machine hosting `zendesk-mcp`:

```bash
npm run auth
```

**If running on a remote homelab over SSH**, you have two convenient options:
1. **Option A — SSH Port Forwarding**: Connect from your workstation with `-L 18492:127.0.0.1:18492`:
   ```bash
   ssh -L 18492:127.0.0.1:18492 user@homelab
   cd /path/to/zendesk-mcp && npm run auth
   ```
   When your local browser redirects to `http://127.0.0.1:18492/callback`, the homelab listener receives the code automatically.
2. **Option B — Copy-Paste Callback URL (No SSH Tunnel Needed)**:
   Run `npm run auth` (or `npm run auth -- --manual`), open the printed `https://acme.zendesk.com/oauth/authorizations/new?...` URL in your browser, click **Allow**, and even if your browser shows "Unable to connect" on `127.0.0.1:18492`, copy the full `http://127.0.0.1:18492/callback?code=...&state=...` URL from your browser's address bar and paste it into the terminal prompt.

### 5. Verify Token Status & Live Read Access

```bash
# Check local token file permissions and expiration metadata (never prints secret values)
npm run status

# Also verify live read connectivity against GET /api/v2/users/me.json
npm run status -- --verify
```

---

## Connecting to Any LLM / AI Client

Because `zendesk-mcp` automatically loads `.env` from its own repo directory or `~/.config/zendesk-mcp/.env`, it works reliably even in non-interactive SSH sessions where `.bashrc`/`.zshrc` are not sourced.

### Path A: Local Clone (`stdio`)

When the AI client runs on the same machine where `zendesk-mcp` is cloned:

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

### Path B: Remote Homelab over SSH (`stdio`, Recommended for Homelab)

Keep your OAuth tokens exclusively on the homelab and have your local AI client spawn the MCP server over an SSH pipe without a pseudo-terminal (`-T`):

```json
{
  "mcpServers": {
    "zendesk": {
      "command": "ssh",
      "args": [
        "-T",
        "-o",
        "BatchMode=yes",
        "user@homelab.local",
        "node",
        "/absolute/path/to/zendesk-mcp/dist/index.js"
      ]
    }
  }
}
```

### Path C: Persistent Streamable HTTP Service (`--transport=http`)

Only use this path if an HTTP-only client requires a persistent network endpoint.
**Important Security Boundary**: Never expose the HTTP server anonymously, and never reuse your Zendesk OAuth token as the MCP HTTP token. Generate a separate high-entropy `MCP_HTTP_BEARER_TOKEN` and place the service behind TLS / private VPN (e.g. Tailscale/WireGuard):

```bash
# Generate a dedicated MCP HTTP bearer token (distinct from Zendesk OAuth)
openssl rand -base64 32
```

Set in `.env`:
```ini
MCP_TRANSPORT=http
MCP_HTTP_HOST=127.0.0.1
MCP_HTTP_PORT=3849
MCP_HTTP_BEARER_TOKEN=your_generated_32_byte_mcp_bearer_token
```

Start the server:
```bash
npm start
# Or explicitly:
node dist/index.js serve --transport=http
```

---

## Operations: Startup, Restart, Rotation & Reauthorization

- **Normal Token Rotation**: Access tokens default to a 30-minute lifetime and are automatically refreshed using the stored refresh token (`POST /oauth/tokens`). Rotated tokens are persisted atomically to `tokens.json` (`0600`) and survive process restarts and system reboots without manual intervention.
- **Reauthorization (After 30–90 Day Refresh Expiry or Revocation)**: If a refresh token expires or is revoked by an admin, tool calls return a clear `ReauthorizationRequiredError`. Run `npm run auth` on the host machine to complete a fresh OAuth consent flow.
- **Upgrading / Restarting**:
  ```bash
  git pull
  npm ci
  npm run build
  npm test
  ```
  For `stdio` clients, the next session automatically spawns the updated binary. For persistent HTTP deployments, restart the service (`systemctl restart zendesk-mcp`).
