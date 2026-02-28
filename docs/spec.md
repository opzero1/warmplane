# Warmplane API Spec

## HTTP Facade API (`/v1`)

Base:

- Daemon binds to `127.0.0.1:<port>`.
- Default port: `9090`.

Endpoints:

- `GET /v1/capabilities`
- `GET /v1/capabilities/:id`
- `POST /v1/tools/call`
- `GET /v1/resources`
- `POST /v1/resources/read`
- `GET /v1/prompts`
- `POST /v1/prompts/get`

Response semantics:

- list endpoints return `{ "version": "v1", ... }` payloads
- execution/read/get endpoints return normalized envelope:
  - `ok`, `request_id`, `trace_id`, `data`, `error`

Error codes:

- `TOOL_NOT_FOUND`
- `RESOURCE_NOT_FOUND`
- `PROMPT_NOT_FOUND`
- `SERVER_UNREACHABLE`
- `INVALID_ARGS`
- `UPSTREAM_TIMEOUT`
- `UPSTREAM_ERROR`
- `INTERNAL_ERROR`

## MCP Server Facade (stdio)

Run:

```bash
warmplane mcp-server --config mcp_servers.json
```

Exposed MCP tools (lightweight schemas):

- `capabilities_list`
- `capability_describe`
- `capability_call`
- `resources_list`
- `resource_read`
- `prompts_list`
- `prompt_get`

These tools return the same lightweight JSON payloads used by CLI/HTTP facade semantics.

Also exposed natively via MCP methods:

- resources: `resources/list`, `resources/read`
- prompts: `prompts/list`, `prompts/get`

## Policy + Aliases

Configured in `mcp_servers.json`:

- `capabilityAliases`: `<server>.<tool>` -> capability ID
- `resourceAliases`: `<server>.<resource-uri>` -> resource ID
- `promptAliases`: `<server>.<prompt-name>` -> prompt ID
- `policy.allow` / `policy.deny`: ID pattern gates across tools/resources/prompts
- `policy.redactKeys`: redaction keys for logged payloads

## Upstream Transport Config

`mcpServers.<id>` must define exactly one transport selector:

- `command`: stdio transport
- `url`: streamable HTTP transport (JSON + SSE)

If both or neither are present, startup fails with config validation errors.

### stdio fields

- `command` (required for stdio)
- `args` (optional)
- `env` (optional)

### HTTP/SSE fields

- `url` (required for HTTP/SSE)
- `protocolVersion` (optional, default `2025-11-25`)
- `allowStateless` (optional; defaults to rmcp transport behavior)
- `headers` (optional map of static request headers)
- `auth` (optional):
  - bearer: `{ "type": "bearer", "token" | "tokenEnv" }`
  - basic: `{ "type": "basic", "username", "password" | "passwordEnv" }`

For bearer/basic auth, exactly one secret source must be set.
