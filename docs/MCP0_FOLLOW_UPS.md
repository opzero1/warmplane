# MCP0 Follow-Ups

This file tracks follow-up work that is intentionally separate from the shipped `mcp0`-only rollout.

The core rollout now covers:

- strict `mcp0` installer scaffolding
- native Warmplane OAuth discovery, login, exchange, refresh, and logout
- provider validation for Figma, Linear, and Notion on a live `mcp0` config
- runtime readiness reporting and operator troubleshooting guidance

Remaining follow-ups:

1. Expand the current macOS-first prebuilt binary path to additional platforms once the release asset workflow is stable.
2. Decide whether existing local OpenCode configs should be auto-migrated to `mcp0` outside the installer path, or whether migration should remain installer-driven.
3. Monitor the runtime OAuth refresh path for streamable/stateless HTTP upstreams and expand cross-provider regression coverage for mid-session credential rotation.
4. Consider whether Warmplane should eventually offer a managed long-running service mode that can reuse auth/session state beyond the current on-demand `mcp-server` entrypoint.
5. Add broader regression/perf automation so the direct-vs-`mcp0` startup improvement is tracked continuously instead of only through manual smoke checks.
