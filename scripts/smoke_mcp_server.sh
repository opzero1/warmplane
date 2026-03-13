#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

cargo build --quiet

CONFIG_FILE="$(mktemp)"
cleanup() {
  rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

cat > "$CONFIG_FILE" <<'JSON'
{
  "mcpServers": {}
}
JSON

MCP_FAST_BIN="$REPO_ROOT/target/debug/warmplane" MCP_FAST_CONFIG="$CONFIG_FILE" python3 - <<'PY'
import json
import os
import subprocess
import sys

BIN = os.environ["MCP_FAST_BIN"]
CONFIG = os.environ["MCP_FAST_CONFIG"]

proc = subprocess.Popen(
    [BIN, "mcp-server", "--config", CONFIG],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

try:
    def send(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def recv_until_id(expected_id):
        while True:
            line = proc.stdout.readline()
            if line == "":
                err = proc.stderr.read()
                raise RuntimeError(f"mcp-server exited early while waiting for id={expected_id}. stderr:\n{err}")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == expected_id:
                return msg

    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "0.1.0"}
        }
    })
    init_resp = recv_until_id(1)
    if "result" not in init_resp:
        raise RuntimeError(f"initialize failed: {init_resp}")

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_resp = recv_until_id(2)
    tools = tools_resp.get("result", {}).get("tools", [])
    names = sorted(t.get("name") for t in tools)

    expected = sorted([
        "capabilities_list",
        "capability_find",
        "capability_describe",
        "capability_call",
        "resources_list",
        "resource_read",
        "prompts_list",
        "prompt_get",
    ])
    if names != expected:
        raise RuntimeError(f"unexpected tools list\nexpected={expected}\nactual={names}")

    send({"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}})
    resources_resp = recv_until_id(3)
    if "resources" not in resources_resp.get("result", {}):
        raise RuntimeError(f"resources/list missing resources key: {resources_resp}")

    send({"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}})
    prompts_resp = recv_until_id(4)
    if "prompts" not in prompts_resp.get("result", {}):
        raise RuntimeError(f"prompts/list missing prompts key: {prompts_resp}")

    print("smoke test passed: mcp-server tools/resources/prompts surface is healthy")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
PY
