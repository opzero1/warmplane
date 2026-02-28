# Warmplane

`Warmplane` is the local control plane that keeps MCP sessions warm.

It runs multiple upstream MCP servers behind one local process, keeps those sessions persistent, and exposes a compact interaction surface for tools/resources/prompts. The goal is concrete and measurable: reduce startup latency, reduce payload size, and keep behavior deterministic.

## Why This Exists

Most agent stacks overpay in tokens and latency by eagerly surfacing large tool catalogs and detailed schemas that are never used.

`Warmplane` shifts that model to lazy, compact interaction:

- Discover compact indexes first.
- Fetch detail only when needed.
- Execute through normalized envelopes.

This improves:

- token efficiency
- time-to-first-useful-tool-call
- cross-client consistency
- observability and policy control

## What It Provides

One runtime, three access modes:

1. HTTP facade (`/v1/...`)
2. CLI facade commands
3. MCP facade server mode (`mcp-server`) for MCP-native clients

All three modes share the same backend state, aliases, policy checks, and timeout behavior.

## Core Facade Surface

### Capabilities
- list: compact capability index
- describe: on-demand detail for one capability
- call: normalized execution envelope

### Resources
- list: compact resource index
- read: normalized read envelope

### Prompts
- list: compact prompt index
- get: normalized prompt rendering envelope

## Build

```bash
cargo build --release
```

## Validate Config

Validate and lint configuration before startup:

```bash
warmplane validate-config --config mcp_servers.json
```

Example success output:

```json
{"ok":true,"config":"mcp_servers.json","servers":3}
```

## Configuration

Create `mcp_servers.json`:

```json
{
  "port": 9090,
  "toolTimeoutMs": 15000,
  "capabilityAliases": {
    "sqlite.read_query": "db.query"
  },
  "resourceAliases": {
    "filesystem.file:///tmp/readme.txt": "fs.readme"
  },
  "promptAliases": {
    "github.code_review": "prompt.code-review"
  },
  "policy": {
    "allow": ["db.*", "fs.*", "prompt.*"],
    "deny": ["fs.secret"],
    "redactKeys": ["token", "api_key", "password"]
  },
  "mcpServers": {
    "sqlite": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite", "./test.db"]
    },
    "remote_docs": {
      "url": "https://mcp.example.com/mcp",
      "protocolVersion": "2025-11-25",
      "allowStateless": false,
      "headers": {
        "X-Tenant": "acme"
      },
      "auth": {
        "type": "bearer",
        "tokenEnv": "REMOTE_DOCS_MCP_TOKEN"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

Per `mcpServers.<id>`, transport selection is strict and inferred:

- stdio upstream: set `command` (plus optional `args`, `env`)
- HTTP/SSE upstream: set `url` (plus optional `protocolVersion`, `allowStateless`, `headers`, `auth`)
- exactly one of `command` or `url` must be set

No legacy config fallback is supported.

### HTTP Auth

`auth.type = "bearer"`:

```json
{
  "type": "bearer",
  "tokenEnv": "MCP_TOKEN"
}
```

`auth.type = "basic"`:

```json
{
  "type": "basic",
  "username": "svc-user",
  "passwordEnv": "MCP_PASSWORD"
}
```

For bearer/basic, exactly one direct secret (`token`/`password`) or env-backed secret (`tokenEnv`/`passwordEnv`) is required.

## Run Modes

### 1) HTTP Daemon

```bash
cargo run --release -- daemon --config mcp_servers.json
```

Endpoints:

- `GET /v1/capabilities`
- `GET /v1/capabilities/:id`
- `POST /v1/tools/call`
- `GET /v1/resources`
- `POST /v1/resources/read`
- `GET /v1/prompts`
- `POST /v1/prompts/get`

### 2) MCP Server (stdio)

```bash
cargo run --release -- mcp-server --config mcp_servers.json
```

MCP clients can point directly to this process.

Synthetic lightweight tools exposed:

- `capabilities_list`
- `capability_describe`
- `capability_call`
- `resources_list`
- `resource_read`
- `prompts_list`
- `prompt_get`

Native MCP methods also supported:

- resources: `resources/list`, `resources/read`
- prompts: `prompts/list`, `prompts/get`

### 3) CLI Facade

```bash
# capabilities
cargo run --release -- list-capabilities
cargo run --release -- describe-capability db.query
cargo run --release -- call-capability db.query --params '{"query":"SELECT 1"}'

# resources
cargo run --release -- list-resources
cargo run --release -- read-resource fs.readme

# prompts
cargo run --release -- list-prompts
cargo run --release -- get-prompt prompt.code-review --arguments '{"code":"fn main() {}"}'
```

## MCP Client Example

```json
{
  "mcpServers": {
    "fast-facade": {
      "command": "warmplane",
      "args": ["mcp-server", "--config", "mcp_servers.json"]
    }
  }
}
```

## Smoke Test

Run an end-to-end stdio MCP smoke test:

```bash
./scripts/smoke_mcp_server.sh
```

It validates:

- MCP `initialize`
- `tools/list` includes all synthetic lightweight facade tools
- `resources/list` and `prompts/list` return valid responses

## Design Notes

- Upstream MCP compatibility remains intact.
- Client-facing schemas are intentionally small and stable.
- Policy and aliasing are enforced consistently across modes.
- Timeout and error envelopes are normalized for deterministic orchestration.
- Runtime logs are structured JSON for auditability.
- OpenTelemetry trace export is supported via OTLP.

## Observability

Warmplane emits structured JSON logs by default (`tracing` + `tracing-subscriber`).

Example controls:

- `RUST_LOG=info,warmplane=debug` set verbosity
- `WARMPLANE_OTEL_ENABLED=true` enable OpenTelemetry export
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317` set OTLP collector endpoint
- `WARMPLANE_OTEL_ENDPOINT=http://127.0.0.1:4317` fallback OTLP endpoint if `OTEL_EXPORTER_OTLP_ENDPOINT` is unset
- `WARMPLANE_SERVICE_NAME=warmplane-prod` override service name

Operational notes:

- Logs include structured request/capability/resource/prompt fields for audit trails.
- `trace_id` in execution envelopes can be correlated with logs and distributed traces.
- When OTEL is enabled, traces are exported via OTLP gRPC and local structured logs remain active.

For detailed request/response contracts, see [docs/spec.md](/Users/origo/src/mcp-fast-cli/docs/spec.md).

Additional references:

- OpenAPI: [openapi.yaml](/Users/origo/src/mcp-fast-cli/docs/openapi.yaml)
- Config schema: [config.schema.json](/Users/origo/src/mcp-fast-cli/docs/config.schema.json)
- Install/distribution: [INSTALL.md](/Users/origo/src/mcp-fast-cli/docs/INSTALL.md)
- Deployment runbook: [DEPLOYMENT.md](/Users/origo/src/mcp-fast-cli/docs/DEPLOYMENT.md)
- Observability: [OBSERVABILITY.md](/Users/origo/src/mcp-fast-cli/docs/OBSERVABILITY.md)
