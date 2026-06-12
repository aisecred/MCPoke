# MCPoke

A Burp Repeater-style exploration and security testing tool for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Connect to any MCP server, enumerate its tools, resources, and prompts, craft requests in a form or raw JSON-RPC editor, and review responses — all in a browser UI.

Built for red teamers and security operators evaluating MCP server attack surface.

![MCPoke screenshot](assets/screenshot.png)

---

## Features

- **Multi-server support** — connect to multiple MCP servers simultaneously, switch between them in a sidebar
- **Auto transport detection** — tries HTTP then SSE automatically; works with both stateless HTTP and persistent SSE transports
- **Full enumeration** — calls `tools/list`, `resources/list`, and `prompts/list` on connect; surfaces results in tabbed panels with live item counts
- **Dangerous tool flagging** — auto-scans tool names and descriptions for high-impact keywords (filesystem, code exec, network, database, secrets) and shows a ⚠ badge on flagged tools
- **Form + Raw editor** — build requests via generated form fields or edit the full JSON-RPC payload directly; sync between modes in either direction
- **Local schema cache** — enumerated tools, resources, and prompts are cached at `~/.mcpoke/cache.json`; cached servers appear in the sidebar on restart for quick reconnect
- **Request history** — every call is logged with method, args, status, and elapsed time; replay any entry or export the full history as JSON
- **HTTP/SOCKS proxy support** — route traffic per-server through Burp Suite or any HTTP/SOCKS proxy
- **Resizable panes** — all four column panels and the history row are drag-resizable; layout persists in localStorage

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

### Exploring tools, resources, and prompts

Switch between the **Tools**, **Resources**, and **Prompts** tabs in the second panel. Counts are shown on each tab. Tools flagged as high-impact show a ⚠ badge.

- Click a **tool** → opens the form/raw editor pre-filled with its schema
- Click a **resource** → seeds the raw editor with a `resources/read` payload
- Click a **prompt** → seeds the raw editor with a `prompts/get` payload with argument stubs

### Sending requests

**Form mode:** fill in fields generated from the tool's input schema, click **Send**.

**Raw mode:** edit the full JSON-RPC payload directly. Change `method`, `id`, or any field freely — the payload is sent verbatim. Useful for:
- Testing malformed payloads and type confusion
- Calling methods not in the schema (`resources/list`, `prompts/list`, etc.)
- Missing required fields, oversized values, injection payloads

Switch between modes with the **Form / Raw** toggle. Use **← Sync to form** to pull raw edits back into the form fields.

`Ctrl+Enter` sends the current request.

### Proxy (Burp Suite)

Set the proxy field per-server to `http://127.0.0.1:8080` to route all traffic for that server through Burp. The proxy badge appears in the sidebar.

### History

Every request is logged in the history panel at the bottom. Click **Replay** to restore a previous call. **Export JSON** downloads the full history as a structured JSON file — useful for evidence and reports.

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
- **Endpoints** — `POST /connect`, `POST /call`, `POST /raw`, `GET|DELETE /cache`, `GET /cache/entry`

### MCP transport support

| Transport | How it works |
|---|---|
| HTTP | Stateless POST to a single endpoint; tries `tools/list` cold before `initialize` |
| SSE | GET → `endpoint` event → POST to session URL; ephemeral session per call |

---

## Backlog

See [BACKLOG.md](BACKLOG.md) for the prioritised feature list.
