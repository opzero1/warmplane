# Observability Guide

Warmplane emits structured JSON logs by default and can export distributed traces via OpenTelemetry (OTLP).

This guide covers practical setup and operations.

## 1) Logging Defaults

Warmplane uses `tracing` + JSON output by default.

Key properties:

- machine-parseable log lines (JSON)
- stable event names for startup and operation flow
- contextual fields for audit (server IDs, capability/resource/prompt IDs)
- response `trace_id` correlation with runtime events

Set verbosity:

```bash
export RUST_LOG=info,warmplane=debug
```

## 2) OpenTelemetry Export

OTEL export is optional and controlled by env vars.

Enable OTEL:

```bash
export WARMPLANE_OTEL_ENABLED=true
```

Set collector endpoint (preferred):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
```

Fallback endpoint (if `OTEL_EXPORTER_OTLP_ENDPOINT` is unset):

```bash
export WARMPLANE_OTEL_ENDPOINT=http://127.0.0.1:4317
```

Set service name:

```bash
export WARMPLANE_SERVICE_NAME=warmplane-prod
```

Run:

```bash
warmplane daemon --config mcp_servers.json
```

## 3) Recommended Production Baseline

- Use structured log ingestion into SIEM/ELK/Loki.
- Export OTLP traces to a central collector.
- Standardize `WARMPLANE_SERVICE_NAME` by environment:
  - `warmplane-dev`
  - `warmplane-staging`
  - `warmplane-prod`
- Include deployment metadata at orchestrator layer (k8s labels, host, region) for filtering.

## 4) Collector Patterns

## 4.1 Local OpenTelemetry Collector

`otel-collector-config.yaml` example:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:

exporters:
  logging:
    verbosity: normal

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
```

Run collector and point Warmplane to `http://127.0.0.1:4317`.

## 4.2 Grafana/Tempo-style pipeline

- Warmplane -> OTLP collector -> Tempo
- Logs -> Loki (or equivalent)
- Correlate by `trace_id` and request metadata fields

## 4.3 Datadog/Honeycomb/New Relic style pipeline

- Warmplane -> OTLP collector (or vendor OTLP endpoint)
- Map `service.name` from `WARMPLANE_SERVICE_NAME`
- Keep log + trace retention policies aligned for investigation windows

## 5) Correlation Workflow

When an HTTP call returns a `trace_id`:

1. Find that `trace_id` in trace backend.
2. Pull related structured log lines.
3. Inspect upstream server events and error envelope outcome.

This is the fastest path for incident triage and postmortem reconstruction.

## 6) Security and Compliance Notes

- Prefer env-backed secrets for upstream auth (`tokenEnv`, `passwordEnv`).
- Keep daemon on localhost unless fronted by a trusted boundary.
- Use policy deny rules for destructive operations by default.
- Retain logs/traces according to regulatory requirements.

## 7) Known Limits (Current)

- Metrics export (counters/histograms) is not implemented yet.
- Trace sampling is controlled by downstream collector strategy, not warmplane config.
- Per-tenant telemetry partitioning is currently deployment-layer concern.

## 8) Suggested Next Enhancements

1. Add Prometheus/OTEL metrics (`request_count`, `latency_ms`, `timeouts`, `upstream_errors`).
2. Add explicit span attributes for capability IDs and upstream server IDs.
3. Add configurable log redaction policy for additional compliance regimes.
