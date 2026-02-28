use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::Utc;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use rmcp::{
    model::PaginatedRequestParams,
    transport::{streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport, TokioChildProcess},
    ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tiktoken_rs::CoreBPE;
use tokio::{process::Command, time::sleep};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";
const FACADE_PORT_BASE: u16 = 9910;

#[derive(Debug, Deserialize)]
struct Suite {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "mcpServers")]
    mcp_servers: HashMap<String, ServerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct ServerConfig {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "protocolVersion")]
    protocol_version: Option<String>,
    #[serde(default, rename = "allowStateless")]
    allow_stateless: Option<bool>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    auth: Option<AuthConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuthConfig {
    Bearer {
        #[serde(default)]
        token: Option<String>,
        #[serde(default, rename = "tokenEnv")]
        token_env: Option<String>,
    },
    Basic {
        username: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default, rename = "passwordEnv")]
        password_env: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum TransportKind {
    Stdio {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        protocol_version: String,
        allow_stateless: bool,
        headers: HashMap<String, String>,
        auth: Option<AuthConfig>,
    },
}

#[derive(Debug, Serialize)]
struct PayloadMetrics {
    bytes: usize,
    chars: usize,
    tokens_cl100k: usize,
}

#[derive(Debug, Serialize, Default)]
struct RawSurfaceMetrics {
    tools: Option<PayloadMetrics>,
    resources: Option<PayloadMetrics>,
    prompts: Option<PayloadMetrics>,
}

#[derive(Debug, Serialize)]
struct ServerEval {
    server_id: String,
    transport: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<RawSurfaceMetrics>,
}

#[derive(Debug, Serialize, Default)]
struct FacadeEval {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    capabilities_list: Option<PayloadMetrics>,
    resources_list: Option<PayloadMetrics>,
    prompts_list: Option<PayloadMetrics>,
    capability_describe_first: Option<PayloadMetrics>,
}

#[derive(Debug, Serialize)]
struct Scenario {
    name: String,
    raw_tokens: usize,
    facade_tokens: usize,
    savings_tokens: isize,
    savings_pct: f64,
}

#[derive(Debug, Serialize)]
struct SuiteResult {
    suite: String,
    description: Option<String>,
    timestamp_utc: String,
    active_servers: usize,
    skipped_servers: usize,
    servers: Vec<ServerEval>,
    facade: FacadeEval,
    scenarios: Vec<Scenario>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (suite_dir, out_dir, repo_root) = parse_args()?;
    fs::create_dir_all(&out_dir)?;

    let bpe = tiktoken_rs::cl100k_base().context("failed to load cl100k tokenizer")?;

    let mut suite_paths = list_suite_paths(&suite_dir)?;
    suite_paths.sort();

    let mut results = Vec::new();

    for (idx, suite_path) in suite_paths.iter().enumerate() {
        let suite = load_suite(suite_path)?;
        let port = FACADE_PORT_BASE + idx as u16;
        let result = evaluate_suite(&suite, port, &repo_root, &out_dir, &bpe).await?;
        results.push(result);
    }

    let summary_path = out_dir.join("summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&results)?)?;

    let report = render_report(&results);
    let report_path = out_dir.join("report.md");
    fs::write(&report_path, report.as_bytes())?;

    println!("Wrote {}", summary_path.display());
    println!("Wrote {}", report_path.display());

    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let mut suite_dir = PathBuf::from("eval/token-efficiency/suites");
    let mut out_dir = PathBuf::from("eval/token-efficiency/output");
    let mut repo_root = std::env::current_dir()?;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--suite-dir" => suite_dir = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing value for --suite-dir"))?),
            "--out-dir" => out_dir = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing value for --out-dir"))?),
            "--repo-root" => repo_root = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing value for --repo-root"))?),
            other => return Err(anyhow!("unknown arg: {}", other)),
        }
    }

    Ok((suite_dir, out_dir, repo_root))
}

fn list_suite_paths(suite_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(suite_dir).with_context(|| format!("read_dir {}", suite_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("no suite json files found in {}", suite_dir.display()));
    }
    Ok(out)
}

fn load_suite(path: &Path) -> Result<Suite> {
    let text = fs::read_to_string(path)?;
    let suite: Suite = serde_json::from_str(&text)
        .with_context(|| format!("invalid suite file {}", path.display()))?;
    Ok(suite)
}

async fn evaluate_suite(
    suite: &Suite,
    port: u16,
    repo_root: &Path,
    out_dir: &Path,
    bpe: &CoreBPE,
) -> Result<SuiteResult> {
    let mut servers = Vec::new();
    let mut active_servers = HashMap::<String, TransportKind>::new();

    for (server_id, cfg) in &suite.mcp_servers {
        match resolve_transport(server_id, cfg) {
            Ok(transport) => {
                let transport_label = match &transport {
                    TransportKind::Stdio { .. } => "stdio",
                    TransportKind::Http { .. } => "streamable_http",
                }
                .to_string();

                match evaluate_raw_server(server_id, &transport, bpe).await {
                    Ok(raw) => {
                        servers.push(ServerEval {
                            server_id: server_id.clone(),
                            transport: transport_label,
                            status: "ok".to_string(),
                            error: None,
                            raw: Some(raw),
                        });
                        active_servers.insert(server_id.clone(), transport);
                    }
                    Err(err) => {
                        servers.push(ServerEval {
                            server_id: server_id.clone(),
                            transport: transport_label,
                            status: "error".to_string(),
                            error: Some(err.to_string()),
                            raw: None,
                        });
                    }
                }
            }
            Err(reason) => {
                servers.push(ServerEval {
                    server_id: server_id.clone(),
                    transport: "unknown".to_string(),
                    status: "skipped".to_string(),
                    error: Some(reason),
                    raw: None,
                });
            }
        }
    }

    let facade = evaluate_facade(suite, &active_servers, port, repo_root, out_dir, bpe).await;

    let scenarios = compute_scenarios(&servers, &facade);

    Ok(SuiteResult {
        suite: suite.name.clone(),
        description: suite.description.clone(),
        timestamp_utc: Utc::now().to_rfc3339(),
        active_servers: active_servers.len(),
        skipped_servers: servers.iter().filter(|s| s.status != "ok").count(),
        servers,
        facade,
        scenarios,
    })
}

fn resolve_transport(server_id: &str, cfg: &ServerConfig) -> std::result::Result<TransportKind, String> {
    let has_command = cfg.command.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    let has_url = cfg.url.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);

    if has_command == has_url {
        return Err(format!(
            "server '{}' must set exactly one of command or url",
            server_id
        ));
    }

    if has_command {
        let command = expand_templates(cfg.command.as_deref().unwrap_or_default())?;
        let mut args = Vec::new();
        for arg in &cfg.args {
            args.push(expand_templates(arg)?);
        }
        let mut env = HashMap::new();
        for (k, v) in &cfg.env {
            env.insert(k.clone(), expand_templates(v)?);
        }
        return Ok(TransportKind::Stdio { command, args, env });
    }

    let mut headers = HashMap::new();
    for (k, v) in &cfg.headers {
        headers.insert(k.clone(), expand_templates(v)?);
    }

    Ok(TransportKind::Http {
        url: expand_templates(cfg.url.as_deref().unwrap_or_default())?,
        protocol_version: cfg
            .protocol_version
            .clone()
            .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string()),
        allow_stateless: cfg.allow_stateless.unwrap_or(true),
        headers,
        auth: cfg.auth.clone(),
    })
}

fn expand_templates(input: &str) -> std::result::Result<String, String> {
    let mut out = String::new();
    let mut rest = input;

    loop {
        let Some(start) = rest.find("${") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(format!("unterminated template in '{}'", input));
        };
        let token = &after[..end];
        let replacement = if let Some(var) = token.strip_prefix("env:") {
            std::env::var(var).map_err(|_| format!("missing env var '{}'", var))?
        } else if let Some(name) = token.strip_prefix("input:") {
            return Err(format!(
                "unsupported input template '${{input:{}}}' in non-interactive harness",
                name
            ));
        } else {
            return Err(format!("unsupported template token '{}'", token));
        };
        out.push_str(&replacement);
        rest = &after[end + 1..];
    }

    Ok(out)
}

fn resolve_auth_header(server_id: &str, auth: &Option<AuthConfig>) -> Result<Option<String>> {
    let Some(auth) = auth else {
        return Ok(None);
    };

    match auth {
        AuthConfig::Bearer { token, token_env } => {
            let val = match (token.as_ref(), token_env.as_ref()) {
                (Some(v), None) => v.clone(),
                (None, Some(env)) => std::env::var(env)
                    .with_context(|| format!("server '{}' missing env var '{}'", server_id, env))?,
                _ => {
                    return Err(anyhow!(
                        "server '{}' bearer auth requires exactly one of token/tokenEnv",
                        server_id
                    ))
                }
            };
            Ok(Some(format!("Bearer {}", val)))
        }
        AuthConfig::Basic {
            username,
            password,
            password_env,
        } => {
            let pass = match (password.as_ref(), password_env.as_ref()) {
                (Some(v), None) => v.clone(),
                (None, Some(env)) => std::env::var(env)
                    .with_context(|| format!("server '{}' missing env var '{}'", server_id, env))?,
                _ => {
                    return Err(anyhow!(
                        "server '{}' basic auth requires exactly one of password/passwordEnv",
                        server_id
                    ))
                }
            };
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", username, pass));
            Ok(Some(format!("Basic {}", encoded)))
        }
    }
}

fn build_http_headers(
    server_id: &str,
    protocol_version: &str,
    headers: &HashMap<String, String>,
    auth: &Option<AuthConfig>,
) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();

    out.insert(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_str(protocol_version)
            .with_context(|| format!("invalid protocolVersion for server '{}'", server_id))?,
    );

    for (name, value) in headers {
        let hname = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid header '{}' for server '{}'", name, server_id))?;
        let hval = HeaderValue::from_str(value)
            .with_context(|| format!("invalid value for header '{}'", name))?;
        out.insert(hname, hval);
    }

    if let Some(auth_header) = resolve_auth_header(server_id, auth)? {
        let mut value = HeaderValue::from_str(&auth_header)?;
        value.set_sensitive(true);
        out.insert(AUTHORIZATION, value);
    }

    Ok(out)
}

async fn evaluate_raw_server(server_id: &str, transport: &TransportKind, bpe: &CoreBPE) -> Result<RawSurfaceMetrics> {
    match transport {
        TransportKind::Stdio { command, args, env } => {
            let mut cmd = Command::new(command);
            cmd.args(args);
            cmd.envs(env);
            let child = TokioChildProcess::new(cmd)
                .with_context(|| format!("failed to spawn stdio server '{}'", server_id))?;
            let client = ().serve(child).await?;
            collect_raw_metrics(client, bpe).await
        }
        TransportKind::Http {
            url,
            protocol_version,
            allow_stateless,
            headers,
            auth,
        } => {
            let header_map = build_http_headers(server_id, protocol_version, headers, auth)?;
            let client = reqwest::Client::builder().default_headers(header_map).build()?;
            let mut cfg = StreamableHttpClientTransportConfig::with_uri(url.clone());
            cfg.allow_stateless = *allow_stateless;
            let transport = StreamableHttpClientTransport::with_client(client, cfg);
            let mcp = ().serve(transport).await?;
            collect_raw_metrics(mcp, bpe).await
        }
    }
}

async fn collect_raw_metrics(
    mcp: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    bpe: &CoreBPE,
) -> Result<RawSurfaceMetrics> {
    let tools = tokio::time::timeout(
        Duration::from_secs(25),
        mcp.list_tools(Some(PaginatedRequestParams::default())),
    )
    .await;
    let resources = tokio::time::timeout(
        Duration::from_secs(25),
        mcp.list_resources(Some(PaginatedRequestParams::default())),
    )
    .await;
    let prompts = tokio::time::timeout(Duration::from_secs(25), mcp.list_all_prompts()).await;

    let mut out = RawSurfaceMetrics::default();

    if let Ok(Ok(value)) = tools {
        let json = serde_json::to_value(value)?;
        out.tools = Some(payload_metrics(&json, bpe));
    }
    if let Ok(Ok(value)) = resources {
        let json = serde_json::to_value(value)?;
        out.resources = Some(payload_metrics(&json, bpe));
    }
    if let Ok(Ok(value)) = prompts {
        let json = serde_json::to_value(value)?;
        out.prompts = Some(payload_metrics(&json, bpe));
    }

    Ok(out)
}

async fn evaluate_facade(
    suite: &Suite,
    active_servers: &HashMap<String, TransportKind>,
    port: u16,
    repo_root: &Path,
    out_dir: &Path,
    bpe: &CoreBPE,
) -> FacadeEval {
    if active_servers.is_empty() {
        return FacadeEval {
            status: "skipped".to_string(),
            error: Some("no active servers in suite".to_string()),
            ..Default::default()
        };
    }

    let suite_out_dir = out_dir.join(&suite.name);
    if let Err(err) = fs::create_dir_all(&suite_out_dir) {
        return FacadeEval {
            status: "error".to_string(),
            error: Some(format!("failed creating suite out dir: {}", err)),
            ..Default::default()
        };
    }

    let config_json = build_facade_config(active_servers);
    let config_path = suite_out_dir.join("facade_config.json");
    if let Err(err) = fs::write(&config_path, serde_json::to_vec_pretty(&config_json).unwrap_or_default()) {
        return FacadeEval {
            status: "error".to_string(),
            error: Some(format!("failed writing facade config: {}", err)),
            ..Default::default()
        };
    }

    let mut daemon = match Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--")
        .arg("daemon")
        .arg("--config")
        .arg(config_path.to_string_lossy().to_string())
        .arg("--port")
        .arg(port.to_string())
        .current_dir(repo_root)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return FacadeEval {
                status: "error".to_string(),
                error: Some(format!("failed to spawn daemon: {}", err)),
                ..Default::default()
            }
        }
    };

    let ready = wait_for_facade_ready(port, Duration::from_secs(45)).await;
    if let Err(err) = ready {
        let _ = daemon.kill().await;
        return FacadeEval {
            status: "error".to_string(),
            error: Some(format!("daemon did not become ready: {}", err)),
            ..Default::default()
        };
    }

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", port);

    let mut out = FacadeEval {
        status: "ok".to_string(),
        error: None,
        ..Default::default()
    };

    let caps = fetch_json(&client, &format!("{}/v1/capabilities", base)).await;
    let resources = fetch_json(&client, &format!("{}/v1/resources", base)).await;
    let prompts = fetch_json(&client, &format!("{}/v1/prompts", base)).await;

    if let Ok(v) = &caps {
        out.capabilities_list = Some(payload_metrics(v, bpe));
        if let Some(first_id) = v
            .get("capabilities")
            .and_then(|x| x.as_array())
            .and_then(|arr| arr.first())
            .and_then(|it| it.get("id"))
            .and_then(|x| x.as_str())
        {
            let encoded_id = first_id.replace("/", "%2F");
            if let Ok(desc) = fetch_json(&client, &format!("{}/v1/capabilities/{}", base, encoded_id)).await {
                out.capability_describe_first = Some(payload_metrics(&desc, bpe));
            }
        }
    }
    if let Ok(v) = &resources {
        out.resources_list = Some(payload_metrics(v, bpe));
    }
    if let Ok(v) = &prompts {
        out.prompts_list = Some(payload_metrics(v, bpe));
    }

    if caps.is_err() || resources.is_err() || prompts.is_err() {
        out.status = "partial".to_string();
        out.error = Some(format!(
            "caps={} resources={} prompts={}",
            caps.as_ref().err().map(|e| e.to_string()).unwrap_or_else(|| "ok".to_string()),
            resources
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ok".to_string()),
            prompts
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ok".to_string())
        ));
    }

    let _ = daemon.kill().await;
    out
}

fn build_facade_config(active_servers: &HashMap<String, TransportKind>) -> Value {
    let mut servers = serde_json::Map::new();

    for (id, transport) in active_servers {
        let cfg = match transport {
            TransportKind::Stdio { command, args, env } => json!({
                "command": command,
                "args": args,
                "env": env,
            }),
            TransportKind::Http {
                url,
                protocol_version,
                allow_stateless,
                headers,
                auth,
            } => {
                let auth_json = match auth {
                    Some(AuthConfig::Bearer { token, token_env }) => {
                        json!({ "type": "bearer", "token": token, "tokenEnv": token_env })
                    }
                    Some(AuthConfig::Basic {
                        username,
                        password,
                        password_env,
                    }) => json!({
                        "type": "basic",
                        "username": username,
                        "password": password,
                        "passwordEnv": password_env
                    }),
                    None => Value::Null,
                };

                json!({
                    "url": url,
                    "protocolVersion": protocol_version,
                    "allowStateless": allow_stateless,
                    "headers": headers,
                    "auth": auth_json,
                })
            }
        };

        servers.insert(id.clone(), cfg);
    }

    json!({
        "port": 9090,
        "toolTimeoutMs": 20000,
        "capabilityAliases": {},
        "resourceAliases": {},
        "promptAliases": {},
        "mcpServers": Value::Object(servers),
    })
}

async fn wait_for_facade_ready(port: u16, timeout: Duration) -> Result<()> {
    let start = tokio::time::Instant::now();
    let client = reqwest::Client::new();

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("timeout waiting for http://127.0.0.1:{}/v1/capabilities", port));
        }

        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{}/v1/capabilities", port))
            .send()
            .await
        {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(350)).await;
    }
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value> {
    let res = client.get(url).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(anyhow!("{} -> HTTP {}: {}", url, status.as_u16(), text));
    }
    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("invalid json from {}", url))?;
    Ok(value)
}

fn payload_metrics(value: &Value, bpe: &CoreBPE) -> PayloadMetrics {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    let chars = json.chars().count();
    let bytes = json.len();
    let tokens_cl100k = bpe.encode_with_special_tokens(&json).len();
    PayloadMetrics {
        bytes,
        chars,
        tokens_cl100k,
    }
}

fn compute_scenarios(servers: &[ServerEval], facade: &FacadeEval) -> Vec<Scenario> {
    let raw_tools = servers
        .iter()
        .filter_map(|s| s.raw.as_ref())
        .filter_map(|r| r.tools.as_ref())
        .map(|m| m.tokens_cl100k)
        .sum::<usize>();
    let raw_resources = servers
        .iter()
        .filter_map(|s| s.raw.as_ref())
        .filter_map(|r| r.resources.as_ref())
        .map(|m| m.tokens_cl100k)
        .sum::<usize>();
    let raw_prompts = servers
        .iter()
        .filter_map(|s| s.raw.as_ref())
        .filter_map(|r| r.prompts.as_ref())
        .map(|m| m.tokens_cl100k)
        .sum::<usize>();

    let cap_list = facade.capabilities_list.as_ref().map(|m| m.tokens_cl100k).unwrap_or(0);
    let res_list = facade.resources_list.as_ref().map(|m| m.tokens_cl100k).unwrap_or(0);
    let prm_list = facade.prompts_list.as_ref().map(|m| m.tokens_cl100k).unwrap_or(0);
    let desc_one = facade
        .capability_describe_first
        .as_ref()
        .map(|m| m.tokens_cl100k)
        .unwrap_or(0);

    vec![
        scenario(
            "Discovery: one full index pull",
            raw_tools + raw_resources + raw_prompts,
            cap_list + res_list + prm_list,
        ),
        scenario(
            "5-turn tool loop: schema repeated each turn vs lazy describe once",
            5 * raw_tools,
            (5 * cap_list) + desc_one,
        ),
        scenario(
            "10-turn mixed loop: tools every turn, resources every 2, prompts every 3",
            10 * (raw_tools + raw_resources + raw_prompts),
            (10 * cap_list) + (5 * res_list) + (4 * prm_list) + desc_one,
        ),
    ]
}

fn scenario(name: &str, raw_tokens: usize, facade_tokens: usize) -> Scenario {
    let savings_tokens = raw_tokens as isize - facade_tokens as isize;
    let savings_pct = if raw_tokens == 0 {
        0.0
    } else {
        (savings_tokens as f64 / raw_tokens as f64) * 100.0
    };

    Scenario {
        name: name.to_string(),
        raw_tokens,
        facade_tokens,
        savings_tokens,
        savings_pct,
    }
}

fn render_report(results: &[SuiteResult]) -> String {
    let mut out = String::new();
    out.push_str("# Token Efficiency Evaluation\n\n");
    out.push_str("Generated by `eval/token-efficiency` harness.\n\n");
    out.push_str("## Method\n");
    out.push_str("- Raw baseline: direct MCP `tools/list`, `resources/list`, `prompts/list` per upstream server.\n");
    out.push_str("- Facade baseline: `Warmplane` `/v1/capabilities`, `/v1/resources`, `/v1/prompts`, plus one `capability describe`.\n");
    out.push_str("- Tokenization model: `cl100k_base` via `tiktoken-rs`.\n\n");

    for suite in results {
        out.push_str(&format!("## Suite: {}\n\n", suite.suite));
        if let Some(desc) = &suite.description {
            out.push_str(&format!("{}\n\n", desc));
        }
        out.push_str(&format!(
            "- Active servers: {}\n- Skipped/error servers: {}\n- Facade status: {}\n\n",
            suite.active_servers, suite.skipped_servers, suite.facade.status
        ));

        out.push_str("### Server Status\n\n");
        out.push_str("| Server | Transport | Status | Notes |\n");
        out.push_str("|---|---|---|---|\n");
        for s in &suite.servers {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                s.server_id,
                s.transport,
                s.status,
                s.error.clone().unwrap_or_else(|| "-".to_string()).replace('|', "\\|")
            ));
        }
        out.push('\n');

        out.push_str("### Scenario Results (tokens)\n\n");
        out.push_str("| Scenario | Raw | Facade | Savings | Savings % |\n");
        out.push_str("|---|---:|---:|---:|---:|\n");
        for sc in &suite.scenarios {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {:.1}% |\n",
                sc.name, sc.raw_tokens, sc.facade_tokens, sc.savings_tokens, sc.savings_pct
            ));
        }
        out.push('\n');
    }

    out
}
