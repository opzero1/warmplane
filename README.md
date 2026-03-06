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

## Install

```bash
cargo install --path .
```

`cargo install warmplane` is not available yet because the crate has not been published to crates.io.

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
  "authStorePath": "/Users/you/.local/share/opencode/mcp-auth.json",
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
    "figma": {
      "url": "https://mcp.figma.com/mcp",
      "auth": {
        "type": "oauth",
        "scope": "file_content:read",
        "tokenStoreKey": "figma"
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

`authStorePath` is optional. When omitted, Warmplane reads and writes the shared MCP auth store at the existing OpenCode locations, preferring `~/.local/share/opencode/mcp-auth.json` and falling back to `~/.config/opencode/mcp-auth.json`.

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

`auth.type = "oauth"`:

```json
{
  "type": "oauth",
  "clientId": "optional-pre-registered-client-id",
  "clientName": "warmplane",
  "clientSecretEnv": "MCP_CLIENT_SECRET",
  "redirectUri": "http://127.0.0.1:8788/callback",
  "scope": "files:read files:write",
  "tokenStoreKey": "figma",
  "authorizationEndpoint": "https://linear.app/oauth/authorize",
  "tokenEndpoint": "https://api.linear.app/oauth/token",
  "codeChallengeMethodsSupported": ["S256"]
}
```

Warmplane currently uses the shared `mcp-auth.json` store for OAuth-backed upstream bearer injection. Manage those entries with the auth commands below.

OAuth contract notes:

- `clientId` is optional when the upstream authorization server supports dynamic client registration; `auth start` / `auth login` can register a client first and persist the returned `clientInfo` in the shared auth store.
- `clientName` is optional and defaults to `warmplane` during dynamic registration.
- `redirectUri` is optional and defaults to `http://127.0.0.1:8788/callback` for loopback callback handling.
- `clientSecret` and `clientSecretEnv` remain mutually exclusive.
- `tokenStoreKey` controls which shared auth-store entry Warmplane reads and writes.
- Discovery metadata (`resourceMetadataUrl`, authorization server metadata, registration/token endpoints, PKCE support) is persisted in the shared auth store after `auth discover`.
- For providers that do not expose RFC 9728 / RFC 8414 discovery metadata, you can preconfigure `authorizationEndpoint`, `tokenEndpoint`, optional `registrationEndpoint`, and `codeChallengeMethodsSupported` as explicit fallback metadata.

## Auth Commands

Discover upstream OAuth metadata before importing tokens:

```bash
warmplane auth discover --config mcp_servers.json --server figma
```

This resolves protected-resource and authorization-server metadata, then persists the normalized discovery record in the shared auth store so later status checks can show whether discovery has already succeeded.

Build a PKCE authorization URL and persist `state`/`codeVerifier` in the shared auth store:

```bash
warmplane auth start --config mcp_servers.json --server figma
```

Run the integrated login flow with best-effort browser launch plus loopback callback capture:

```bash
warmplane auth login --config mcp_servers.json --server figma
```

Exchange the callback `code` and `state` using the stored PKCE verifier:

```bash
warmplane auth exchange --config mcp_servers.json --server figma --code <CODE> --state <STATE>
```

Inspect upstream OAuth readiness:

```bash
warmplane auth status --config mcp_servers.json
```

Import tokens into the shared auth store without editing JSON by hand:

```bash
warmplane auth import --config mcp_servers.json --server figma --access-token-env FIGMA_ACCESS_TOKEN --refresh-token-env FIGMA_REFRESH_TOKEN
```

Refresh stored OAuth credentials using the discovered token endpoint and refresh token:

```bash
warmplane auth refresh --config mcp_servers.json --server figma
```

Remove stored credentials for one upstream:

```bash
warmplane auth logout --config mcp_servers.json --server figma
```

## OAuth Operator Workflow

Recommended bootstrap flow for a new OAuth-capable upstream:

1. `warmplane auth discover --config mcp_servers.json --server <server>`
2. `warmplane auth login --config mcp_servers.json --server <server>`
3. `warmplane auth status --config mcp_servers.json --server <server>`

Fallback/manual flow when browser automation or callback capture is not convenient:

1. `warmplane auth discover --config mcp_servers.json --server <server>`
2. `warmplane auth start --config mcp_servers.json --server <server>`
3. Complete the browser flow yourself and capture the callback `code` + `state`
4. `warmplane auth exchange --config mcp_servers.json --server <server> --code <CODE> --state <STATE>`
5. `warmplane auth status --config mcp_servers.json --server <server>`

Recovery and cleanup:

- `warmplane auth refresh --config mcp_servers.json --server <server>` to rotate expired credentials manually
- `warmplane auth logout --config mcp_servers.json --server <server>` to remove stored state and tokens
- `warmplane validate-config --config mcp_servers.json` before retrying if auth bootstrap behaves unexpectedly

Troubleshooting and rollback diagnostics:

- `warmplane auth status --config mcp_servers.json --server <server>` to inspect discovery readiness, client readiness, refresh-token availability, and auth status
- `warmplane auth logout --config mcp_servers.json --server <server>` followed by `warmplane auth login --config mcp_servers.json --server <server>` to recover from bad or stale local auth state
- Remove or restore the shared `mcp-auth.json` entry for the affected `tokenStoreKey` if you need to roll back to a clean pre-auth state

## Provider Compatibility Notes

- Figma is the standards-first target: discovery, dynamic client registration, PKCE `S256`, token exchange, and refresh all align with Warmplane's native flow.
- Linear is supported natively with explicit fallback metadata in config because its OAuth endpoints are documented but not published through the well-known discovery chain.
- Notion remains a compatibility exception until live validation confirms PKCE and loopback redirect support for its MCP path. Treat it as an explicit shim case instead of silently assuming standards parity.
- If an upstream does not advertise PKCE `S256`, does not expose the expected discovery metadata, or requires non-standard redirect handling, treat that as an explicit compatibility gap rather than silently falling back to wrapper behavior.

## Run Modes

### 1) HTTP Daemon

```bash
warmplane daemon --config mcp_servers.json
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
warmplane mcp-server --config mcp_servers.json
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
warmplane list-capabilities
warmplane describe-capability db.query
warmplane call-capability db.query --params '{"query":"SELECT 1"}'

# resources
warmplane list-resources
warmplane read-resource fs.readme

# prompts
warmplane list-prompts
warmplane get-prompt prompt.code-review --arguments '{"code":"fn main() {}"}'
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

For detailed request/response contracts, see [docs/spec.md](docs/spec.md).

Additional references:

- OpenAPI: `docs/openapi.yaml`
- Config schema: `docs/config.schema.json`
- Install/distribution: `docs/INSTALL.md`
- Deployment runbook: `docs/DEPLOYMENT.md`
- Observability: `docs/OBSERVABILITY.md`
- Rollout follow-ups: `docs/MCP0_FOLLOW_UPS.md`
