# Token Efficiency Evaluation Harness

This harness measures token footprint for:

1. Raw upstream MCP surfaces (`tools/list`, `resources/list`, `prompts/list`)
2. `Warmplane` compact facade surfaces (`/v1/capabilities`, `/v1/resources`, `/v1/prompts`, optional capability describe)

It is designed to run even when some servers require auth; those servers are marked `skipped` with explicit reasons.

## Quick Start

```bash
cargo run --manifest-path eval/token-efficiency/Cargo.toml -- \
  --suite-dir eval/token-efficiency/suites \
  --out-dir eval/token-efficiency/output
```

Outputs:

- `summary.json`
- `report.md`
- Research narrative (manual synthesis): `docs/research/TOKEN_EFFICIENCY_RESEARCH_REPORT.md`

## Environment Variables

Some suites rely on env-backed secrets:

- `GITHUB_MCP_PAT` for GitHub Copilot MCP (optional)

If unset, related servers/suites are still evaluated where possible and marked skipped for auth-limited paths.

## Template Expansion

Config values support:

- `${env:VAR_NAME}`: resolved from environment
- `${input:secret_name}`: intentionally unsupported in non-interactive harness; server is skipped with reason
