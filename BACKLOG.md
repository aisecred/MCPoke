# MCPoke Backlog

Priority order within each section. Tick items off as they land.

---

## High priority

- [ ] **Full HTTP request/response as the Response panel default**
  The 2026-07-28 spec moved substantial protocol semantics into HTTP headers (`x-mcp-header` → `Mcp-Param-*`, `Mcp-Session-Id`, `Mcp-Protocol-Version`, `Mcp-Method`/SEP-2243) — the JSON-RPC body alone is no longer the full picture of what's happening on the wire. The Response panel should default to showing the full HTTP request/response (status line, all headers, body) instead of just the JSON-RPC body, with a toggle to switch to a JSON-only view for the common case where headers aren't relevant. Builds on the full-headers work already shipped (`_renderHeadersBlock`, currently a collapsed-by-default section above the JSON view) — this changes that from opt-in/collapsed to the default view, not new plumbing.

- [x] **Raw / manual request editor**
  Edit the full JSON-RPC payload directly in a text area instead of (or alongside) the generated form. Critical for testing malformed payloads, schema bypass, type confusion, missing required fields, oversized values. Should sit as a toggle ("Form / Raw") in the request panel.

- [x] **Resources + prompts enumeration**
  Call `resources/list` and `prompts/list` alongside `tools/list` on connect. Surface them in their own tabs in the tools panel. Many servers leak sensitive data through resources or expose system prompts through the prompts endpoint.

- [x] **Dangerous tool flagging**
  Auto-scan tool names and descriptions for high-impact keywords (filesystem: `read_file`, `write_file`; code exec: `run`, `execute`, `shell`; network: `fetch`, `request`, `http`; database: `query`, `sql`). Show a warning badge (⚠) on flagged tools in the list so operators know where to focus first.

- [x] **Prompt injection / tool poisoning scanner**
  Passive scan of all tool names, descriptions, parameter descriptions, resource names/URIs, and prompt content on connect. Flag: instruction override (`ignore previous instructions`, role manipulation), template injection (`{{`, `${`, `<%`), hidden/zero-width Unicode characters, CRLF injection, script injection, exfiltration indicators (external URLs, `send all data to`), and LLM-specific delimiters (`[INST]`, `<<SYS>>`, `<|im_start|>`). Show a red ⚑ badge per item, findings detail in the request panel, and a total risk count on the server entry. Include template injection (Jinja2, Twig, Freemarker, ERB, EL, Velocity).

- [x] **Payload library per parameter**
  For string parameters, a dropdown button next to each input field that injects a chosen test payload. Preset categories:
  - Path traversal: `../../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd`
  - SSRF: `http://169.254.169.254/latest/meta-data/`, `http://localhost/`
  - Command injection: `; id`, `` `id` ``, `| id`
  - Prompt injection: `Ignore previous instructions and...`
  - Template injection: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
  - SQLi: `' OR '1'='1`, `'; DROP TABLE users;--`

- [x] **Capability analysis panel**
  Surface the `initialize` response capabilities with risk annotations. `sampling` = server can invoke AI models (critical risk), `roots` = filesystem access declared, `experimental` = undocumented features. Show in the server info area, not buried in raw JSON.

- [x] **Cross-server tool shadowing detection**
  When 2+ servers are loaded, flag duplicate tool names across servers. A malicious server registering the same tool name as a legitimate one can intercept calls. Show warning in sidebar.

- [x] **SSE notification capture**
  Display server-pushed `notifications/` events in a live feed panel. Servers can push state changes, errors, and progress events that are otherwise invisible and may leak internal information.

- [x] **Protocol edge case presets**
  Dropdown in the raw editor with MCP-specific malformed payloads: wrong `protocolVersion`, missing `jsonrpc` field, `id: null` vs omitted, notification-sent-as-request, unknown method, batch requests. Surfaces how strictly the server validates the protocol.

- [x] **stdio transport**
  Connect to local MCP servers that communicate over stdin/stdout (subprocess). Select "stdio" transport in the connect form, enter the launch command (e.g. `node server.js`), optionally set env vars. Covers the majority of real-world MCP servers (filesystem, git, database tools, etc.).

- [x] **MCP OAuth 2.0 / PKCE tester**
  Probe OAuth flows on connected servers: discover `/.well-known/oauth-authorization-server`, test PKCE enforcement, open redirect validation, token endpoint client auth, bogus client_credentials, and privileged scope acceptance. Findings roll into the Findings panel.

---

## Medium priority

- [x] **Response sensitive data detection**
  After each tool call, scan the response body for patterns: AWS/GCP/Azure key formats, JWTs (`eyJ`…), private key headers, file paths (`/etc/`, `C:\`), internal IPs (RFC 1918), stack traces. Highlight matches in the response panel and add a `findings` field to the JSON export.

- [x] **Auth variation tester**
  One-click panel to fire the same tool call with auth variations: no token, invalid token (`Bearer invalid`), empty bearer (`Bearer `), `Authorization: null`, and optionally a forged `alg:none` JWT. Results shown side-by-side. Surfaces auth bypass and improper validation quickly.

- [x] **Notes per tool**
  Inline text field per tool for operator annotations during a session (e.g. "confirmed path traversal via `path` param", "returns internal DB error on empty input"). Notes included in the JSON export under each history entry.

- [x] **Copy request as cURL / Python**
  One-click export of the current raw editor payload as a `curl` command or Python `requests` snippet, including auth headers and custom headers. Copies to clipboard.

---

## Low priority / nice to have

- [x] **SOCKS proxy support**
  Currently HTTP proxies work. SOCKS4/5 requires `pip install aiohttp-socks` — the code path exists but the package isn't in `requirements.txt`. Add it as an optional dep with a note, or add a setup check that surfaces a clear install instruction in the UI when a socks:// proxy is entered and the package is missing.

- [x] **Session save / load**
  Export the full session (server list + history + notes) to a JSON file and reload it later. Lets operators resume a test across restarts without re-enumerating tools.

- [x] **Repeat with modifications (Fuzzer from history)**
  Take a history entry, mark one parameter as the fuzz target, supply a wordlist or value range, fire N sequential calls. Results shown in a mini table. Useful for iterating on injection payloads without manual re-send.

- [x] **Transport security info**
  Show TLS/plaintext indicator per server (already knowable from the URL scheme). Optionally surface the server's TLS cert details (CN, expiry, self-signed flag) in the server panel on hover.

- [x] **Timing anomaly detection in fuzzer**
  Flag fuzzer results where the response time is statistically slower than the baseline (e.g. ≥2× median). Surfaces blind time-based injection without operator intervention — SQL `SLEEP()`, shell `sleep`, etc.

- [x] **Project file model / autosave**
  Implemented as server-side `.mcpoke` project files (not localStorage). On first launch without `--project`, a picker prompts to create a new project, open an existing one (with a filesystem browser), use a dated default, or continue without saving. Project files auto-save every 60 s, on every tool call, connect, finding status change, note edit, and tab close (via `sendBeacon`). `--project PATH` CLI flag opens a project directly. "Export Session" / "Import Session" remain for portable copies. Project name and last-saved time shown in the toolbar. Paths restricted to user home directory with `.mcpoke`/`.json` extension enforcement.

---

## GhostSplice / instruction-splitting detection coverage

A malicious server can smuggle a split instruction through *any* channel that carries server-controlled text back to the client, not just a tool call's success result. Tracking every such channel here as each is closed off. See [MALICIOUS_SERVER_ATTACKS.md](MALICIOUS_SERVER_ATTACKS.md) §4 for the underlying technique and the README's "GhostSplice / instruction-splitting detection" section for how the checks work.

- [x] **Tool call result content** (`content[].text`)
  Every tool call result is injection-scanned, not just static `tools/list` metadata — closes the original gap the technique exploits.
- [x] **Opaque tool parameter naming**
  Static check at connect time flags tools with ≥2 generic, undescribed parameters (`alpha`/`beta`/`param1`/...) — the setup half of the pattern.
- [x] **Error responses** (JSON-RPC protocol errors and tool-execution `isError:true` results)
  Neither was scanned before — a server can smuggle the mapping fragment into error text exactly as easily as a success response, and operators scrutinize errors less closely by habit.
- [x] **`resources/read` content**
  Resource *content* is now scanned, not just its `resources/list`-time name/title/uri/description metadata.
- [x] **`prompts/get` rendered messages**
  A prompt's list-time metadata was already scanned; the actual messages a prompt renders when invoked now are too (`_runPromptGetChecks`).
- [x] **`structuredContent`**
  Now scanned for injection language (stringified as a whole, since it can be any JSON value per 2026-07-28), in addition to the existing `outputSchema` shape check.
- [x] **`serverInfo.instructions`** (returned at `initialize`)
  Now scanned at connect time (`_runServerInstructionsChecks`), across all three connect paths (HTTP, SSE, stdio).
- [x] **`resource_link.name` / `.description`** (inside tool results)
  The `uri` was already checked for SSRF; the accompanying display text is now scanned for injection too.
- [x] **Notification `params`** (e.g. `notifications/message`'s log text)
  Now scanned (`_runNotificationChecks`) alongside the existing capability/spoofing checks. `ghostsplice_server.py` can't exercise this itself (plain stateless HTTP, no stream to push a notification over) — live coverage added to `spec_probes_server.py`'s `/sse` instead (`data_ingest` + `spam_notification_with_mapping`).

All seven locations closed as of 2026-08-19, all with live fixture coverage: six in `mcp_test_servers/ghostsplice_server.py`, notification params in `mcp_test_servers/spec_probes_server.py`.
