# MCPoke

A Burp Repeater-style exploration and security testing tool for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Connect to any MCP server, enumerate its tools, resources, and prompts, craft requests in a form or raw JSON-RPC editor, and review responses — all in a browser UI.

Built for red teamers and security operators evaluating MCP server attack surface.

![MCPoke screenshot](assets/screenshot.png)

---

## Features

### Enumeration and passive analysis
- **Multi-server support** — connect to multiple MCP servers simultaneously, switch between them in a sidebar
- **Auto transport detection** — tries HTTP then SSE automatically; works with both stateless HTTP and persistent SSE transports
- **Full enumeration** — calls `tools/list`, `resources/list`, and `prompts/list` on connect; surfaces results in tabbed panels with live item counts
- **Attack surface dashboard** — Overview tab shows a live risk summary after connect: findings by severity, dangerous tool breakdown by category, capability risk annotations, and transport/TLS status
- **Dangerous tool flagging** — auto-scans tool names and descriptions for high-impact keywords (filesystem, code exec, network, database, secrets) and shows a ⚠ badge on flagged tools
- **Capability analysis** — surfaces the `initialize` response capabilities with risk annotations: `sampling` (server can invoke AI models — critical), `roots` (filesystem access declared), `experimental` (undocumented features)
- **Prompt injection / tool poisoning scanner** — passive scan on connect of all tool names, descriptions, parameter descriptions, resource names/URIs, and prompt content; flags instruction overrides, template injection, hidden Unicode, CRLF injection, exfiltration indicators, and LLM-specific delimiters; shows ⚑ badge per item
- **Cross-server tool shadowing detection** — flags duplicate tool names across connected servers; a malicious server registering the same name as a legitimate one can intercept calls
- **Transport security info** — TLS/plaintext indicator per server; fetches cert details (CN, expiry, self-signed flag) on hover
- **SSE notification capture** — live feed of server-pushed `notifications/` events that most clients silently discard
- **Server fingerprinting** — identifies server implementation from name, version, and protocol patterns

### Request crafting
- **Form + Raw editor** — build requests via generated form fields or edit the full JSON-RPC payload directly; sync between modes in either direction
- **Payload library per parameter** — dropdown next to every string input injects a chosen test payload from preset categories: path traversal, SSRF, command injection, prompt injection, template injection, SQLi, CRLF, XXE, LDAP, and more
- **Schema-aware type confusion payloads** — payload picker adds a "Type confusion" category based on each parameter's declared JSON schema type (e.g. integer fields get `"1"`, `null`, `[]`, `{}`, `true`)
- **Protocol edge case presets** — dropdown in the raw editor injects MCP-specific malformed payloads (wrong `protocolVersion`, missing `jsonrpc`, `id: null`, batch requests, unknown methods) plus underexplored MCP methods (`ping`, `completion/complete`, `resources/subscribe`, `logging/setLevel`)
- **OOB callback URL** — set a Burp Collaborator or interactsh URL once in the header; payloads with placeholder domains are auto-substituted before sending

### Active testing
- **Fuzzer** — mark a value in the raw editor with `§§`, open the Fuzzer, select payloads from presets / paste / file upload, fire sequentially with configurable delay; size anomaly detection flags responses deviating ≥20% from baseline
  - **Resizable detail pane** — click any result row to open a split request/response pane at the bottom of the results table; drag the divider to resize
  - **Double-click full view** — double-click a row for a full-screen popup showing the exact request payload sent and the complete response side by side
- **Auth variation tester** — fires the same request with six auth variations automatically (current token, no auth, invalid token, empty bearer, `Authorization: null`, alg:none JWT); compares response bodies against the authenticated baseline and flags identical responses as confirmed bypass regardless of HTTP status
  - **JWT claims tamper** — when the current token is a JWT, adds six additional mutations: `role=admin`, `role=superuser`, `sub=admin`, `sub=0` (IDOR), expired (`exp=1`), far-future expiry
  - **Custom header probing** — when custom headers are configured (e.g. `X-API-Key`), adds variations that strip or invalidate each key; prevents false positives on servers that use custom headers instead of Bearer tokens for authentication
- **Race condition tester** — fires N concurrent requests (5–50) via the **Race** button; results table flags outliers whose HTTP status or response size deviates from the majority
- **Intruder-lite** — open from any history entry via the **Intruder** button; select a parameter leaf as the fuzz target, choose preset categories or paste a wordlist, fire sequentially via `/raw`, view results with size anomaly detection; export as CSV
- **Response diff viewer** — check any two history entries and click **Diff** to see a line-level diff; also auto-shown in the auth tester when a bypass is detected

### Findings and reporting
- **Findings panel** — aggregates all passive and active findings across all connected servers; double-click the panel header to expand full-screen
- **Findings triage** — each finding has a status badge (open / confirmed / false positive / accepted risk) that cycles on click; status persists in localStorage across sessions
- **Remediation guidance** — all auto-generated findings include actionable remediation text in a dedicated column
- **Response sensitive data detection** — scans every response for AWS/GCP/Azure credential formats, JWTs, private key headers, internal file paths, RFC 1918 IPs, stack traces, Slack/GitHub tokens
- **Notes per tool** — inline text field per tool for operator annotations during a session; included in JSON export
- **Session save / load** — export the full session (servers, schemas, history, findings, notes) to JSON and reload it later
- **Request history** — every call is logged with method, args, status, and elapsed time; replay any entry, export as JSON or Markdown
- **Custom request headers** — set arbitrary headers per server (e.g. `X-API-Key`, `X-Tenant-ID`) sent on every request alongside the Bearer token; shown as a green **hdrs** badge in the sidebar
- **HTTP/SOCKS proxy support** — route traffic per-server through Burp Suite or any HTTP/SOCKS proxy

### UI
- **Resizable panes** — all four column panels and the history row are drag-resizable; layout persists in localStorage
- **Full-screen panel expansion** — double-click any panel header to expand it full-screen; press Escape or click Close to restore; works for Servers, Tools, Request, Response, History, Findings, and Notifications panels

---

## Installation

**Requirements:** Python 3.10+, pip

```bash
git clone <repo-url>
cd mcpoke
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 mcpoke.py
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

### Options

```
python3 mcpoke.py [--port PORT] [--host HOST]

  -p, --port PORT   Port to listen on (default: 8000)
      --host HOST   Host to bind to (default: 127.0.0.1)
```

Examples:

```bash
python3 mcpoke.py -p 9090                     # custom port
python3 mcpoke.py --host 0.0.0.0 --port 8080  # listen on all interfaces
```

### Optional: SOCKS proxy support

```bash
pip install aiohttp-socks
```

---

## Usage

### Connecting to a server

1. Enter the MCP server URL in the bottom of the **Servers** panel (e.g. `http://localhost:9000/mcp`)
2. Optionally fill in a Bearer token and proxy URL
3. Click **+ Connect** — MCPoke auto-detects HTTP vs SSE transport

If the server was previously connected, it appears in the sidebar as a cached entry. Click it to pre-fill the form for quick reconnect.

### Attack Surface Dashboard (Overview tab)

After connecting, click the **Overview** tab in the enum panel for a 30-second risk summary:

- **Findings by severity** — count of critical/high/medium/info findings for this server, broken down by category
- **Dangerous tools** — how many tools are flagged and which risk categories they hit
- **Capabilities** — same capability badges as the server info panel, with risk notes
- **Transport** — TLS/plaintext status, cert CN and expiry if available

### Exploring tools, resources, and prompts

Switch between **Overview**, **Tools**, **Resources**, and **Prompts** tabs in the second panel. Counts are shown on each tab. Tools flagged as high-impact show a ⚠ badge; items with injection findings show a ⚑ badge.

- Click a **tool** → opens the form/raw editor pre-filled with its schema
- Click a **resource** → seeds the raw editor with a `resources/read` payload
- Click a **prompt** → seeds the raw editor with a `prompts/get` payload with argument stubs

### Sending requests

**Form mode:** fill in fields generated from the tool's input schema, click **Send**.

Each string input has a payload picker button (▾) with preset injection categories. Fields with a declared JSON schema type also get a **Type confusion** category offering type-mismatch values.

**Raw mode:** edit the full JSON-RPC payload directly. Change `method`, `id`, or any field freely — the payload is sent verbatim. Useful for:
- Testing malformed payloads and type confusion
- Calling methods not in the schema (`resources/list`, `prompts/list`, etc.)
- Missing required fields, oversized values, injection payloads

Switch between modes with the **Form / Raw** toggle. Use **← Sync to form** to pull raw edits back into the form fields.

`Ctrl+Enter` sends the current request.

### Fuzzer

1. In raw mode, select a value you want to fuzz and click **§ Mark** to wrap it with `§§` markers
2. Click **⚡ Fuzz** (or the Fuzzer button) to open the full-screen fuzzer
3. Choose payloads from **Presets**, **Paste** (one per line), or **File** (.txt upload)
4. Set an optional inter-request **Delay** (ms) and click **▶ Start**

Results table shows HTTP status, RPC status, elapsed time, response size, and a preview. Rows with a size anomaly (≥20% from baseline) are highlighted.

**Viewing request/response detail:**
- **Single-click** a result row → opens a split pane at the bottom of the results area showing the exact request sent on the left and the full response on the right; drag the horizontal divider to resize
- **Double-click** a result row → opens a full-screen popup inside the fuzzer with the same request/response view filling the entire space

### Auth variation tester

Click **⚡ Auth** in the raw editor action bar to fire six auth variations against the current request simultaneously:

| # | Variation |
|---|---|
| 1 | Current token (baseline) |
| 2 | No Authorization header |
| 3 | `Bearer invalid` |
| 4 | `Bearer ` (empty) |
| 5 | `Authorization: null` |
| 6 | alg:none unsigned JWT |

If the current token is a JWT, six additional claim-mutation rows are added: `role=admin`, `role=superuser`, `sub=admin`, `sub=0` (IDOR probe), `exp=1` (expired), `exp=9999999999` (far future).

If the server has **custom headers** configured (e.g. `X-API-Key`), additional rows are added for each key (up to 3): all custom headers removed, the specific key removed, and the key set to `invalid`. This covers servers that use a custom header instead of (or in addition to) Bearer tokens for authentication — preventing false positives when the Bearer token column is empty.

Responses are compared body-to-body against the authenticated baseline. A `≡ match` badge on any unauthenticated row is a confirmed auth bypass.

### Race condition tester

Click **△ Race** in the raw editor action bar to fire multiple concurrent requests:

1. Choose a concurrency count (5, 10, 20, or 50)
2. Click **▶ Run** — all requests fire simultaneously via `asyncio.gather`
3. Results table shows HTTP status, RPC status, and elapsed time per request; rows whose status+size deviates from the majority are highlighted as outliers

Useful for TOCTOU bugs, double-spend vulnerabilities, and state-corruption issues.

### Intruder-lite

Click **⚡ Intruder** on any history entry row to open the Intruder:

1. **Left panel** — flattened parameter tree from the original request; click a leaf value to mark it as the fuzz target (highlighted in amber)
2. **Right panel** — choose payload source: **Presets** (same categories as the payload picker) or **Paste** (one per line)
3. Click **▶ Run** — fires requests sequentially via `/raw`, substituting each payload for the marked value
4. Results table shows payload, HTTP/RPC status, elapsed time, and a response preview; size anomalies (≥20% from baseline) are flagged
5. Click **Export CSV** to download results

### Response diff viewer

In the history panel, check the checkboxes on exactly two entries and click the **⋮ Diff (2)** button that appears. A full-screen diff view shows added/removed/unchanged lines between the two responses.

The auth tester also auto-shows a diff between the baseline and any confirmed bypass response.

### Findings triage

The Findings panel (bottom tabs, or double-click to expand full-screen) aggregates all passive and active findings. Each finding has a **status badge** in the Status column:

| Status | Meaning |
|---|---|
| open | Unreviewed (default) |
| confirmed | Verified true positive |
| false pos. | Dismissed as false positive |
| accepted | Accepted risk |

Click the badge to cycle through states. Status persists in `localStorage` across browser sessions and page reloads.

### Custom request headers

Some MCP servers require auth or routing headers beyond a Bearer token (e.g. `X-API-Key`, `X-Tenant-ID`, `X-Forwarded-For`). Click **▸ Custom headers** in the connect form to reveal a textarea and enter headers one per line:

```
X-API-Key: abc123
X-Tenant: myorg
```

Headers are sent on every request to that server — connect, send, fuzz, auth test, race, and intruder. If you also set a Bearer token, the `Authorization` header always takes priority. A green **hdrs** badge appears in the sidebar when headers are configured; hovering shows the header names. Custom headers are restored into the form when you click a cached server entry to reconnect.

### Proxy (Burp Suite)

Set the proxy field per-server to `http://127.0.0.1:8080` to route all traffic for that server through Burp. The proxy badge appears in the sidebar.

### History

Every request is logged in the history panel at the bottom. Click **Replay** to restore a previous call. **Export JSON** and **Export MD** download the full history — useful for evidence and reports.

Double-click the **History** panel header to expand it full-screen for easier review.

---

## Dangerous tool categories

MCPoke scans tool names and descriptions against five categories:

| Category | Example keywords |
|---|---|
| filesystem | `file`, `path`, `read`, `write`, `delete`, `download`, `mkdir` |
| code exec | `exec`, `execute`, `shell`, `eval`, `run`, `bash`, `script` |
| network | `fetch`, `http`, `url`, `curl`, `webhook`, `socket`, `browse` |
| database | `query`, `sql`, `insert`, `drop`, `select`, `database` |
| secrets | `secret`, `credential`, `password`, `apikey`, `token`, `env` |

Flagged tools show ⚠ in the tool list and a category summary in the request panel.

---

## Architecture

Single-file application (`mcpoke.py`):

- **Backend** — FastAPI + aiohttp; handles MCP transport negotiation, probing, and proxying
- **Frontend** — vanilla JS, no build step; inline HTML/CSS/JS served from the Python file
- **Endpoints** — `POST /connect`, `POST /call`, `POST /raw`, `POST /race`, `GET|DELETE /cache`, `GET /cache/entry`, `GET /cert`

### MCP transport support

| Transport | How it works |
|---|---|
| HTTP | Stateless POST to a single endpoint; tries `tools/list` cold before `initialize` |
| SSE | GET → `endpoint` event → POST to session URL; ephemeral session per call |

---

## Backlog

See [BACKLOG.md](BACKLOG.md) for the prioritised feature list.
