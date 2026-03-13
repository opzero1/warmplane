use anyhow::{anyhow, Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use base64::Engine as _;
use futures::future::join_all;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use rmcp::{
    model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams},
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
        TokioChildProcess,
    },
    ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    process::Command,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tracing::{info, warn};

use crate::{
    auth_store::{derive_auth_status, load_store, save_store, OAuthAuthStatus, OAuthEntry},
    config::{AuthConfig, McpConfig, PolicyConfig, ServerConfig, DEFAULT_TOOL_TIMEOUT_MS},
    http_v1,
    oauth_client::{refresh_oauth_tokens, OAuthRefreshRequest},
};

const DEFAULT_MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const OAUTH_REFRESH_SKEW_SECS: u64 = 300;
static STATELESS_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub enum ServerMsg {
    CallTool {
        name: String,
        params: Value,
        reply: oneshot::Sender<Result<Value, UpstreamCallError>>,
    },
    ReadResource {
        uri: String,
        reply: oneshot::Sender<Result<Value, UpstreamCallError>>,
    },
    GetPrompt {
        name: String,
        arguments: Option<serde_json::Map<String, Value>>,
        reply: oneshot::Sender<Result<Value, UpstreamCallError>>,
    },
}

#[derive(Debug, Clone)]
pub enum UpstreamCallError {
    Upstream(String),
    Timeout,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerReadiness {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

fn readiness(code: &str, message: impl Into<String>, retryable: bool) -> ServerReadiness {
    ServerReadiness {
        code: code.to_string(),
        message: message.into(),
        retryable,
    }
}

#[derive(Clone)]
pub struct CapabilityMeta {
    pub server: String,
    pub tool: String,
    pub summary: String,
    pub description: String,
    pub input_schema: Value,
    pub tags: Vec<String>,
    pub examples: Vec<Value>,
}

#[derive(Clone)]
pub struct ResourceMeta {
    pub server: String,
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone)]
pub struct PromptMeta {
    pub server: String,
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub arguments: Vec<Value>,
    pub tags: Vec<String>,
}

#[derive(Clone, Default)]
pub struct Policy {
    allow: Vec<String>,
    deny: Vec<String>,
    pub redact_keys: Vec<String>,
}

impl Policy {
    pub fn from_config(config: Option<PolicyConfig>) -> Self {
        let Some(config) = config else {
            return Self::default();
        };
        Self {
            allow: config.allow,
            deny: config.deny,
            redact_keys: config
                .redact_keys
                .into_iter()
                .map(|k| k.to_lowercase())
                .collect(),
        }
    }

    pub fn allows(&self, id: &str) -> bool {
        if self.deny.iter().any(|pattern| wildcard_match(pattern, id)) {
            return false;
        }

        if self.allow.is_empty() {
            return true;
        }

        self.allow.iter().any(|pattern| wildcard_match(pattern, id))
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

fn resolve_secret(
    direct_value: &Option<String>,
    env_name: &Option<String>,
    server_id: &str,
    field_name: &str,
) -> Result<String> {
    if let Some(value) = direct_value {
        return Ok(value.clone());
    }
    let env_var = env_name
        .as_ref()
        .ok_or_else(|| anyhow!("Server '{}' missing {}", server_id, field_name))?;
    std::env::var(env_var).with_context(|| {
        format!(
            "Server '{}' could not read env var '{}' for {}",
            server_id, env_var, field_name
        )
    })
}

fn resolve_template_string(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = input;

    loop {
        let brace = rest.find("{env:");
        let dollar = rest.find("${env:");
        let next = match (brace, dollar) {
            (Some(left), Some(right)) => Some(if left <= right { (left, 5) } else { (right, 6) }),
            (Some(index), None) => Some((index, 5)),
            (None, Some(index)) => Some((index, 6)),
            (None, None) => None,
        };

        let Some((index, prefix_len)) = next else {
            out.push_str(rest);
            break;
        };

        out.push_str(&rest[..index]);
        let after = &rest[index + prefix_len..];
        let Some(end) = after.find('}') else {
            anyhow::bail!("Unterminated env template in '{}'", input);
        };
        let var = &after[..end];
        if var.trim().is_empty() {
            anyhow::bail!("Empty env template in '{}'", input);
        }
        let value = std::env::var(var)
            .with_context(|| format!("Missing env var '{}' referenced in '{}'", var, input))?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }

    Ok(out)
}

fn resolve_template_map(values: &HashMap<String, String>) -> Result<HashMap<String, String>> {
    values
        .iter()
        .map(|(key, value)| Ok((key.clone(), resolve_template_string(value)?)))
        .collect()
}

async fn build_http_headers(
    server_id: &str,
    srv_cfg: &ServerConfig,
    auth_store_path: Option<&str>,
    resolved_url: Option<&str>,
    oauth_locks: Option<RuntimeOAuthLocks>,
) -> std::result::Result<HeaderMap, ServerReadiness> {
    let mut headers = HeaderMap::new();
    let protocol_version = srv_cfg
        .protocol_version
        .as_deref()
        .unwrap_or(DEFAULT_MCP_PROTOCOL_VERSION);

    headers.insert(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_str(protocol_version).map_err(|_| {
            readiness(
                "config_invalid",
                format!(
                    "Server '{}' has invalid protocolVersion '{}'",
                    server_id, protocol_version
                ),
                false,
            )
        })?,
    );

    for (raw_name, raw_value) in &srv_cfg.headers {
        let resolved_value = resolve_template_string(raw_value).map_err(|error| {
            readiness(
                "config_invalid",
                format!(
                    "Server '{}' has invalid HTTP header template for '{}': {}",
                    server_id, raw_name, error
                ),
                false,
            )
        })?;
        let name = HeaderName::from_bytes(raw_name.as_bytes()).map_err(|_| {
            readiness(
                "config_invalid",
                format!(
                    "Server '{}' has invalid HTTP header name '{}'",
                    server_id, raw_name
                ),
                false,
            )
        })?;
        let value = HeaderValue::from_str(&resolved_value).map_err(|_| {
            readiness(
                "config_invalid",
                format!(
                    "Server '{}' has invalid HTTP header value for '{}'",
                    server_id, raw_name
                ),
                false,
            )
        })?;
        headers.insert(name, value);
    }

    if let Some(auth) = &srv_cfg.auth {
        match auth {
            AuthConfig::Bearer { token, token_env } => {
                let token = resolve_secret(token, token_env, server_id, "bearer token")
                    .map_err(|error| readiness("auth_missing", error.to_string(), false))?;
                let mut auth_value =
                    HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|_| {
                        readiness(
                            "config_invalid",
                            format!(
                                "Server '{}' has invalid bearer token (header encoding failed)",
                                server_id
                            ),
                            false,
                        )
                    })?;
                auth_value.set_sensitive(true);
                headers.insert(AUTHORIZATION, auth_value);
            }
            AuthConfig::Basic {
                username,
                password,
                password_env,
            } => {
                let password = resolve_secret(password, password_env, server_id, "basic password")
                    .map_err(|error| readiness("auth_missing", error.to_string(), false))?;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, password));
                let mut auth_value =
                    HeaderValue::from_str(&format!("Basic {}", encoded)).map_err(|_| {
                        readiness(
                            "config_invalid",
                            format!(
                                "Server '{}' has invalid basic auth credentials (header encoding failed)",
                                server_id
                            ),
                            false,
                        )
                    })?;
                auth_value.set_sensitive(true);
                headers.insert(AUTHORIZATION, auth_value);
            }
            AuthConfig::OAuth {
                client_id,
                client_secret,
                client_secret_env,
                scope,
                token_store_key,
                token_endpoint,
                ..
            } => {
                let _guard = if let Some(lock) = oauth_locks.map(|value| value.inner) {
                    Some(lock.lock_owned().await)
                } else {
                    None
                };
                let (_, mut store) = load_store(auth_store_path).map_err(|error| {
                    readiness("auth_store_unavailable", error.to_string(), true)
                })?;
                let key = token_store_key
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(server_id);
                let mut entry = store.get(key).cloned();
                match derive_auth_status(entry.as_ref(), resolved_url) {
                    OAuthAuthStatus::Authenticated => {}
                    OAuthAuthStatus::Expired => {
                        let Some(current_entry) = entry.clone() else {
                            return Err(readiness(
                                "auth_expired",
                                format!(
                                    "Server '{}' oauth credentials are expired and no auth entry was found",
                                    server_id
                                ),
                                false,
                            ));
                        };
                        let refresh_token = current_entry
                            .tokens
                            .as_ref()
                            .and_then(|value| value.refresh_token.clone())
                            .filter(|value| !value.trim().is_empty())
                            .ok_or_else(|| {
                                readiness(
                                    "auth_expired",
                                    format!(
                                        "Server '{}' oauth credentials are expired and no refresh token is available. Re-import credentials with 'warmplane auth import --config <path> {} ...'",
                                        server_id, server_id
                                    ),
                                    false,
                                )
                            })?;
                        let token_endpoint = current_entry
                            .discovery
                            .as_ref()
                            .and_then(|value| value.token_endpoint.clone())
                            .or_else(|| token_endpoint.clone())
                            .filter(|value| !value.trim().is_empty())
                            .ok_or_else(|| {
                                readiness(
                                    "auth_discovery_missing",
                                    format!(
                                        "Server '{}' oauth credentials are expired but discovery metadata is incomplete. Run 'warmplane auth discover --config <path> {}' first",
                                        server_id, server_id
                                    ),
                                    false,
                                )
                            })?;
                        let scope = scope.clone().or_else(|| {
                            current_entry
                                .tokens
                                .as_ref()
                                .and_then(|value| value.scope.clone())
                        });
                        let resolved_client_secret = resolve_secret(
                            client_secret,
                            client_secret_env,
                            server_id,
                            "client secret",
                        )
                        .ok()
                        .or_else(|| {
                            current_entry
                                .client_info
                                .as_ref()
                                .and_then(|value| value.client_secret.clone())
                        });

                        let refreshed_tokens = refresh_oauth_tokens(OAuthRefreshRequest {
                            token_endpoint,
                            refresh_token,
                            client_id: client_id.clone().or_else(|| {
                                current_entry
                                    .client_info
                                    .as_ref()
                                    .map(|value| value.client_id.clone())
                            }),
                            client_secret: resolved_client_secret,
                            scope,
                        })
                        .await
                        .map_err(|error| {
                            readiness(
                                "auth_refresh_failed",
                                format!(
                                    "Server '{}' oauth refresh failed during startup: {}",
                                    server_id, error
                                ),
                                true,
                            )
                        })?;

                        let mut refreshed_entry = current_entry;
                        refreshed_entry.tokens = Some(refreshed_tokens);
                        store.insert(key.to_string(), refreshed_entry.clone());
                        save_store(auth_store_path, &store).map_err(|error| {
                            readiness("auth_store_unavailable", error.to_string(), true)
                        })?;
                        entry = Some(refreshed_entry);
                    }
                    OAuthAuthStatus::NotAuthenticated => {
                        return Err(readiness(
                            "auth_missing",
                            format!(
                                "Server '{}' missing usable oauth credentials. Run 'warmplane auth discover --config <path> {}' to inspect upstream metadata, then import credentials with 'warmplane auth import --config <path> {} --access-token-env <ENV>'",
                                server_id,
                                server_id,
                                server_id
                            ),
                            false,
                        ));
                    }
                }

                let access_token = entry
                    .as_ref()
                    .and_then(|value| value.tokens.as_ref())
                    .map(|value| value.access_token.as_str())
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        readiness(
                            "auth_missing",
                            "OAuth access token missing after auth status check",
                            false,
                        )
                    })?;
                let mut auth_value = HeaderValue::from_str(&format!("Bearer {}", access_token))
                    .map_err(|_| {
                        readiness(
                            "config_invalid",
                            format!(
                                "Server '{}' has invalid oauth access token (header encoding failed)",
                                server_id
                            ),
                            false,
                        )
                    })?;
                auth_value.set_sensitive(true);
                headers.insert(AUTHORIZATION, auth_value);
            }
        }
    }

    Ok(headers)
}

fn now_epoch_seconds() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default())
    .as_secs()
}

fn oauth_header(token: &str) -> Result<HeaderValue> {
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", token))
        .context("OAuth access token could not be encoded into an Authorization header")?;
    auth.set_sensitive(true);
    Ok(auth)
}

fn auth_headers(headers: &HeaderMap, token: &str) -> Result<HeaderMap> {
    let mut out = headers.clone();
    out.remove(AUTHORIZATION);
    out.insert(AUTHORIZATION, oauth_header(token)?);
    Ok(out)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(ToString::to_string)
}

fn token_from_entry(entry: &OAuthEntry) -> Result<String> {
    entry
        .tokens
        .as_ref()
        .map(|value| value.access_token.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("OAuth access token missing from auth store entry"))
}

fn token_expiring(entry: &OAuthEntry) -> bool {
    entry
        .tokens
        .as_ref()
        .and_then(|value| value.expires_at)
        .map(|value| value <= now_epoch_seconds() + OAUTH_REFRESH_SKEW_SECS)
        .unwrap_or(false)
}

fn auth_error(err: &str) -> bool {
    let err = err.to_ascii_lowercase();
    err.contains("auth required")
        || err.contains("unauthorized")
        || err.contains("forbidden")
        || err.contains("http 401")
        || err.contains("http 403")
}

impl RuntimeOAuth {
    async fn access_token(&self, force_refresh: bool) -> Result<String> {
        let (_, store) = load_store(self.auth_store_path.as_deref())?;
        let entry = store.get(&self.key).cloned().ok_or_else(|| {
            anyhow!(
                "Server '{}' missing oauth credentials in auth store for '{}'",
                self.server_id,
                self.key
            )
        })?;
        let status = derive_auth_status(Some(&entry), Some(&self.resolved_url));

        if !force_refresh
            && matches!(status, OAuthAuthStatus::Authenticated)
            && !token_expiring(&entry)
        {
            return token_from_entry(&entry);
        }

        if matches!(status, OAuthAuthStatus::NotAuthenticated) {
            return Err(anyhow!(
                "Server '{}' missing usable oauth credentials. Re-authenticate or re-import credentials for '{}'",
                self.server_id,
                self.key
            ));
        }

        let _guard = self.locks.inner.lock().await;

        let (_, mut store) = load_store(self.auth_store_path.as_deref())?;
        let current = store.get(&self.key).cloned().ok_or_else(|| {
            anyhow!(
                "Server '{}' missing oauth credentials in auth store for '{}'",
                self.server_id,
                self.key
            )
        })?;
        let status = derive_auth_status(Some(&current), Some(&self.resolved_url));

        if !force_refresh
            && matches!(status, OAuthAuthStatus::Authenticated)
            && !token_expiring(&current)
        {
            return token_from_entry(&current);
        }

        if matches!(status, OAuthAuthStatus::NotAuthenticated) {
            return Err(anyhow!(
                "Server '{}' missing usable oauth credentials. Re-authenticate or re-import credentials for '{}'",
                self.server_id,
                self.key
            ));
        }

        let fallback = token_from_entry(&current).ok();
        let hard_expired = matches!(status, OAuthAuthStatus::Expired);
        match self.refresh_entry(current.clone()).await {
            Ok(next) => {
                let token = token_from_entry(&next)?;
                store.insert(self.key.clone(), next);
                save_store(self.auth_store_path.as_deref(), &store)?;
                Ok(token)
            }
            Err(err) if !hard_expired && !force_refresh => {
                if let Some(token) = fallback {
                    warn!(%self.server_id, key = %self.key, error = %err, "oauth refresh failed before expiry; reusing current access token");
                    return Ok(token);
                }
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    async fn refresh_entry(&self, entry: OAuthEntry) -> Result<OAuthEntry> {
        let refresh_token = entry
            .tokens
            .as_ref()
            .and_then(|value| value.refresh_token.clone())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Server '{}' oauth credentials are expired and no refresh token is available for '{}'",
                    self.server_id,
                    self.key
                )
            })?;
        let token_endpoint = entry
            .discovery
            .as_ref()
            .and_then(|value| value.token_endpoint.clone())
            .or_else(|| self.token_endpoint.clone())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Server '{}' oauth credentials are missing token endpoint metadata for '{}'",
                    self.server_id,
                    self.key
                )
            })?;
        let scope = self
            .scope
            .clone()
            .or_else(|| entry.tokens.as_ref().and_then(|value| value.scope.clone()));
        let client_secret = resolve_secret(
            &self.client_secret,
            &self.client_secret_env,
            &self.server_id,
            "client secret",
        )
        .ok()
        .or_else(|| {
            entry
                .client_info
                .as_ref()
                .and_then(|value| value.client_secret.clone())
        });
        let tokens = refresh_oauth_tokens(OAuthRefreshRequest {
            token_endpoint,
            refresh_token,
            client_id: self.client_id.clone().or_else(|| {
                entry
                    .client_info
                    .as_ref()
                    .map(|value| value.client_id.clone())
            }),
            client_secret,
            scope,
        })
        .await?;

        let mut next = entry;
        next.tokens = Some(tokens);
        Ok(next)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub servers: Arc<HashMap<String, mpsc::Sender<ServerMsg>>>,
    pub server_readiness: Arc<HashMap<String, ServerReadiness>>,
    pub capabilities: Arc<HashMap<String, CapabilityMeta>>,
    pub resources: Arc<HashMap<String, ResourceMeta>>,
    pub prompts: Arc<HashMap<String, PromptMeta>>,
    pub tool_timeout_ms: u64,
    pub policy: Policy,
}

enum PreparedServerTransport {
    Invalid(ServerReadiness),
    Stdio {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        allow_stateless: Option<bool>,
        headers: HeaderMap,
        oauth: Option<RuntimeOAuth>,
    },
}

struct PreparedServerStartup {
    server_id: String,
    transport: PreparedServerTransport,
}

struct InitializedServer {
    server_id: String,
    readiness: ServerReadiness,
    sender: Option<mpsc::Sender<ServerMsg>>,
    capabilities: Vec<(String, CapabilityMeta)>,
    resources: Vec<(String, ResourceMeta)>,
    prompts: Vec<(String, PromptMeta)>,
}

struct StatelessHttpRpcResponse {
    payload: Option<Value>,
    session_id: Option<String>,
}

#[derive(Clone, Default)]
struct RuntimeOAuthLocks {
    inner: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
struct RuntimeOAuth {
    server_id: String,
    key: String,
    auth_store_path: Option<String>,
    resolved_url: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_secret_env: Option<String>,
    scope: Option<String>,
    token_endpoint: Option<String>,
    locks: RuntimeOAuthLocks,
}

#[derive(Debug, Deserialize)]
struct StatelessJsonRpcError {
    #[serde(default)]
    code: Option<Value>,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn next_stateless_request_id() -> u64 {
    STATELESS_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn header_protocol_version(headers: &HeaderMap) -> String {
    headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| DEFAULT_MCP_PROTOCOL_VERSION.to_string())
}

fn parse_stateless_http_response(body: &str) -> Result<Option<Value>> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return serde_json::from_str(trimmed)
            .map(Some)
            .context("Failed to parse JSON-RPC response body");
    }

    let mut data_lines = Vec::new();
    for line in trimmed.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.trim_start());
        }
    }

    if data_lines.is_empty() {
        anyhow::bail!("Failed to parse event-stream response body");
    }

    let payload = data_lines.join("\n");
    serde_json::from_str(&payload)
        .map(Some)
        .context("Failed to parse JSON-RPC event-stream payload")
}

fn stateless_json_rpc_error_message(error: StatelessJsonRpcError) -> String {
    let mut message = error.message;
    if let Some(code) = error.code {
        message = format!("{} (code: {})", message, code);
    }
    if let Some(data) = error.data {
        message = format!("{}; data: {}", message, data);
    }
    message
}

async fn stateless_http_rpc(
    client: &reqwest::Client,
    url: &str,
    session_id: Option<&str>,
    authorization: Option<&HeaderValue>,
    payload: &Value,
) -> std::result::Result<StatelessHttpRpcResponse, String> {
    let mut request = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .json(payload);
    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }
    if let Some(session_id) = session_id {
        request = request.header("mcp-session-id", session_id);
    }

    let response = request
        .send()
        .await
        .map_err(|error| format!("HTTP request failed: {}", error))?;

    let status = response.status();
    let response_session_id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let body = response
        .text()
        .await
        .map_err(|error| format!("Failed to read HTTP response body: {}", error))?;

    if !status.is_success() {
        let suffix = if body.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", body.trim())
        };
        return Err(format!("HTTP {}{}", status, suffix));
    }

    let parsed = parse_stateless_http_response(&body).map_err(|error| error.to_string())?;
    if let Some(value) = &parsed {
        if let Some(error_value) = value.get("error") {
            if let Ok(error) = serde_json::from_value::<StatelessJsonRpcError>(error_value.clone())
            {
                return Err(stateless_json_rpc_error_message(error));
            }
            return Err(format!("JSON-RPC error: {}", error_value));
        }
    }

    Ok(StatelessHttpRpcResponse {
        payload: parsed,
        session_id: response_session_id,
    })
}

async fn initialize_stateless_session(
    client: &reqwest::Client,
    url: &str,
    authorization: Option<&HeaderValue>,
    protocol_version: &str,
    tool_timeout_ms: u64,
) -> std::result::Result<Option<String>, String> {
    let startup_timeout = Duration::from_millis(tool_timeout_ms);
    let initialize_payload = json!({
        "jsonrpc": "2.0",
        "id": next_stateless_request_id(),
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {
                "name": "warmplane",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    });

    let initialize_result = timeout(
        startup_timeout,
        stateless_http_rpc(client, url, None, authorization, &initialize_payload),
    )
    .await;
    let initialized_session_id = match initialize_result {
        Ok(Ok(response)) => response.session_id,
        Ok(Err(error)) => {
            return Err(format!(
                "Failed to negotiate stateless HTTP MCP connection: {}",
                error
            ));
        }
        Err(_) => {
            return Err(format!("Initialize timed out after {}ms", tool_timeout_ms));
        }
    };

    let initialized_payload = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    let initialized_result = timeout(
        startup_timeout,
        stateless_http_rpc(
            client,
            url,
            initialized_session_id.as_deref(),
            authorization,
            &initialized_payload,
        ),
    )
    .await;
    match initialized_result {
        Ok(Ok(_)) => Ok(initialized_session_id),
        Ok(Err(error)) => Err(format!(
            "Failed to finalize stateless HTTP MCP initialization: {}",
            error
        )),
        Err(_) => Err(format!(
            "Initialized notification timed out after {}ms",
            tool_timeout_ms
        )),
    }
}

async fn stateless_call_result(
    client: &reqwest::Client,
    url: &str,
    session_id: Option<&str>,
    authorization: Option<&HeaderValue>,
    payload: &Value,
    timeout_duration: Duration,
) -> Result<Value, UpstreamCallError> {
    let result = timeout(
        timeout_duration,
        stateless_http_rpc(client, url, session_id, authorization, payload),
    )
    .await;
    match result {
        Ok(Ok(response)) => Ok(response
            .payload
            .and_then(|value| value.get("result").cloned())
            .unwrap_or(Value::Null)),
        Ok(Err(err)) => Err(UpstreamCallError::Upstream(err)),
        Err(_) => Err(UpstreamCallError::Timeout),
    }
}

async fn initialize_stateless_http_server(
    server_id: String,
    url: String,
    headers: HeaderMap,
    oauth: Option<RuntimeOAuth>,
    capability_aliases: Arc<HashMap<String, String>>,
    resource_aliases: Arc<HashMap<String, String>>,
    prompt_aliases: Arc<HashMap<String, String>>,
    tool_timeout_ms: u64,
) -> InitializedServer {
    let protocol_version = header_protocol_version(&headers);
    let startup_timeout = Duration::from_millis(tool_timeout_ms);
    let mut base_headers = headers.clone();
    base_headers.remove(AUTHORIZATION);
    let initial_auth = match headers.get(AUTHORIZATION).cloned() {
        Some(value) => Some(value),
        None => match &oauth {
            Some(oauth) => match oauth.access_token(false).await {
                Ok(token) => match oauth_header(&token) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        let readiness = readiness(
                            "transport_unavailable",
                            format!("Failed to encode OAuth header for {}: {}", server_id, error),
                            true,
                        );
                        warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                        return InitializedServer {
                            server_id,
                            readiness,
                            sender: None,
                            capabilities: vec![],
                            resources: vec![],
                            prompts: vec![],
                        };
                    }
                },
                Err(error) => {
                    let readiness = readiness(
                        "transport_unavailable",
                        format!("Failed to load OAuth token for {}: {}", server_id, error),
                        true,
                    );
                    warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                    return InitializedServer {
                        server_id,
                        readiness,
                        sender: None,
                        capabilities: vec![],
                        resources: vec![],
                        prompts: vec![],
                    };
                }
            },
            None => None,
        },
    };
    let client = match reqwest::Client::builder()
        .default_headers(base_headers.clone())
        .build()
    {
        Ok(value) => value,
        Err(error) => {
            let readiness = readiness(
                "transport_unavailable",
                format!("Failed to build HTTP client for {}: {}", server_id, error),
                true,
            );
            warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
            return InitializedServer {
                server_id,
                readiness,
                sender: None,
                capabilities: vec![],
                resources: vec![],
                prompts: vec![],
            };
        }
    };

    let initialized_session_id = match initialize_stateless_session(
        &client,
        &url,
        initial_auth.as_ref(),
        &protocol_version,
        tool_timeout_ms,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let readiness = readiness(
                "transport_unavailable",
                format!(
                    "Failed to negotiate stateless HTTP MCP connection for {}: {}",
                    server_id, error
                ),
                true,
            );
            warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
            return InitializedServer {
                server_id,
                readiness,
                sender: None,
                capabilities: vec![],
                resources: vec![],
                prompts: vec![],
            };
        }
    };

    let mut capabilities = vec![];
    let mut resources = vec![];
    let mut prompts = vec![];

    let tools_response = timeout(
        startup_timeout,
        stateless_http_rpc(
            &client,
            &url,
            initialized_session_id.as_deref(),
            initial_auth.as_ref(),
            &json!({
                "jsonrpc": "2.0",
                "id": next_stateless_request_id(),
                "method": "tools/list",
                "params": {}
            }),
        ),
    )
    .await;
    if let Ok(Ok(response)) = tools_response {
        if let Some(tools_value) = response.payload {
            if let Some(tools_array) = tools_value
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
            {
                for tool in tools_array {
                    if let Some(tool_name) = tool.get("name").and_then(|n| n.as_str()) {
                        info!(%server_id, tool_name = %tool_name, "registered upstream tool");
                        let source_id = format!("{}.{}", server_id, tool_name);
                        let capability_id = capability_aliases
                            .get(&source_id)
                            .cloned()
                            .unwrap_or(source_id);
                        let summary = tool
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No summary available")
                            .to_string();
                        let description = summary.clone();
                        let input_schema = tool
                            .get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| json!({}));
                        capabilities.push((
                            capability_id,
                            CapabilityMeta {
                                server: server_id.clone(),
                                tool: tool_name.to_string(),
                                summary,
                                description,
                                input_schema,
                                tags: vec![server_id.clone()],
                                examples: vec![],
                            },
                        ));
                    }
                }
            }
        }
    }

    let resources_response = timeout(
        startup_timeout,
        stateless_http_rpc(
            &client,
            &url,
            initialized_session_id.as_deref(),
            initial_auth.as_ref(),
            &json!({
                "jsonrpc": "2.0",
                "id": next_stateless_request_id(),
                "method": "resources/list",
                "params": {}
            }),
        ),
    )
    .await;
    if let Ok(Ok(response)) = resources_response {
        if let Some(resources_value) = response.payload {
            if let Some(resource_array) = resources_value
                .get("result")
                .and_then(|r| r.get("resources"))
                .and_then(|r| r.as_array())
            {
                for resource in resource_array {
                    let Some(uri) = resource.get("uri").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let name = resource
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(uri)
                        .to_string();
                    let source_id = format!("{}.{}", server_id, uri);
                    let resource_id = resource_aliases
                        .get(&source_id)
                        .cloned()
                        .unwrap_or(source_id);
                    let description = resource
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    let mime_type = resource
                        .get("mimeType")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    info!(%server_id, uri = %uri, "registered upstream resource");
                    resources.push((
                        resource_id,
                        ResourceMeta {
                            server: server_id.clone(),
                            uri: uri.to_string(),
                            name,
                            description,
                            mime_type,
                            tags: vec![server_id.clone()],
                        },
                    ));
                }
            }
        }
    }

    let prompts_response = timeout(
        startup_timeout,
        stateless_http_rpc(
            &client,
            &url,
            initialized_session_id.as_deref(),
            initial_auth.as_ref(),
            &json!({
                "jsonrpc": "2.0",
                "id": next_stateless_request_id(),
                "method": "prompts/list",
                "params": {}
            }),
        ),
    )
    .await;
    if let Ok(Ok(response)) = prompts_response {
        if let Some(prompts_value) = response.payload {
            if let Some(result_value) = prompts_value.get("result") {
                for prompt in prompt_items_from_value(result_value) {
                    let Some(name) = prompt.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let source_id = format!("{}.{}", server_id, name);
                    let prompt_id = prompt_aliases.get(&source_id).cloned().unwrap_or(source_id);
                    let title = prompt
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    let description = prompt
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    let arguments = prompt
                        .get("arguments")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    info!(%server_id, prompt_name = %name, "registered upstream prompt");
                    prompts.push((
                        prompt_id,
                        PromptMeta {
                            server: server_id.clone(),
                            name: name.to_string(),
                            title,
                            description,
                            arguments,
                            tags: vec![server_id.clone()],
                        },
                    ));
                }
            }
        }
    }

    let (tx, mut rx) = mpsc::channel::<ServerMsg>(32);
    let per_server_timeout = Duration::from_millis(tool_timeout_ms);
    let actor_client = client.clone();
    let actor_url = url.clone();
    let actor_oauth = oauth.clone();
    let actor_protocol_version = protocol_version.clone();
    let mut actor_session_id = initialized_session_id.clone();
    let mut actor_auth = initial_auth.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Some(oauth) = actor_oauth.as_ref() {
                let token = match oauth.access_token(false).await {
                    Ok(value) => value,
                    Err(err) => {
                        let err = Err(UpstreamCallError::Upstream(err.to_string()));
                        match msg {
                            ServerMsg::CallTool { reply, .. }
                            | ServerMsg::ReadResource { reply, .. }
                            | ServerMsg::GetPrompt { reply, .. } => {
                                let _ = reply.send(err);
                            }
                        }
                        continue;
                    }
                };
                let token_changed = actor_auth
                    .as_ref()
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value != format!("Bearer {}", token))
                    .unwrap_or(true);
                if token_changed {
                    match oauth_header(&token) {
                        Ok(value) => {
                            actor_auth = Some(value);
                        }
                        Err(err) => {
                            let err = Err(UpstreamCallError::Upstream(err.to_string()));
                            match msg {
                                ServerMsg::CallTool { reply, .. }
                                | ServerMsg::ReadResource { reply, .. }
                                | ServerMsg::GetPrompt { reply, .. } => {
                                    let _ = reply.send(err);
                                }
                            }
                            continue;
                        }
                    }
                    match initialize_stateless_session(
                        &actor_client,
                        &actor_url,
                        actor_auth.as_ref(),
                        &actor_protocol_version,
                        tool_timeout_ms,
                    )
                    .await
                    {
                        Ok(value) => {
                            actor_session_id = value;
                        }
                        Err(err) => {
                            let err = Err(UpstreamCallError::Upstream(err));
                            match msg {
                                ServerMsg::CallTool { reply, .. }
                                | ServerMsg::ReadResource { reply, .. }
                                | ServerMsg::GetPrompt { reply, .. } => {
                                    let _ = reply.send(err);
                                }
                            }
                            continue;
                        }
                    }
                }
            }

            match msg {
                ServerMsg::CallTool {
                    name,
                    params,
                    reply,
                } => {
                    let payload = json!({
                        "jsonrpc": "2.0",
                        "id": next_stateless_request_id(),
                        "method": "tools/call",
                        "params": {
                            "name": name,
                            "arguments": params,
                        }
                    });
                    let mut res = stateless_call_result(
                        &actor_client,
                        &actor_url,
                        actor_session_id.as_deref(),
                        actor_auth.as_ref(),
                        &payload,
                        per_server_timeout,
                    )
                    .await;
                    if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                    {
                        if let Some(oauth) = actor_oauth.as_ref() {
                            if let Ok(token) = oauth.access_token(true).await {
                                if let Ok(value) = oauth_header(&token) {
                                    actor_auth = Some(value);
                                    if let Ok(value) = initialize_stateless_session(
                                        &actor_client,
                                        &actor_url,
                                        actor_auth.as_ref(),
                                        &actor_protocol_version,
                                        tool_timeout_ms,
                                    )
                                    .await
                                    {
                                        actor_session_id = value;
                                        res = stateless_call_result(
                                            &actor_client,
                                            &actor_url,
                                            actor_session_id.as_deref(),
                                            actor_auth.as_ref(),
                                            &payload,
                                            per_server_timeout,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    }
                    let _ = reply.send(res);
                }
                ServerMsg::ReadResource { uri, reply } => {
                    let payload = json!({
                        "jsonrpc": "2.0",
                        "id": next_stateless_request_id(),
                        "method": "resources/read",
                        "params": { "uri": uri }
                    });
                    let mut res = stateless_call_result(
                        &actor_client,
                        &actor_url,
                        actor_session_id.as_deref(),
                        actor_auth.as_ref(),
                        &payload,
                        per_server_timeout,
                    )
                    .await;
                    if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                    {
                        if let Some(oauth) = actor_oauth.as_ref() {
                            if let Ok(token) = oauth.access_token(true).await {
                                if let Ok(value) = oauth_header(&token) {
                                    actor_auth = Some(value);
                                    if let Ok(value) = initialize_stateless_session(
                                        &actor_client,
                                        &actor_url,
                                        actor_auth.as_ref(),
                                        &actor_protocol_version,
                                        tool_timeout_ms,
                                    )
                                    .await
                                    {
                                        actor_session_id = value;
                                        res = stateless_call_result(
                                            &actor_client,
                                            &actor_url,
                                            actor_session_id.as_deref(),
                                            actor_auth.as_ref(),
                                            &payload,
                                            per_server_timeout,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    }
                    let _ = reply.send(res);
                }
                ServerMsg::GetPrompt {
                    name,
                    arguments,
                    reply,
                } => {
                    let payload = json!({
                        "jsonrpc": "2.0",
                        "id": next_stateless_request_id(),
                        "method": "prompts/get",
                        "params": {
                            "name": name,
                            "arguments": arguments,
                        }
                    });
                    let mut res = stateless_call_result(
                        &actor_client,
                        &actor_url,
                        actor_session_id.as_deref(),
                        actor_auth.as_ref(),
                        &payload,
                        per_server_timeout,
                    )
                    .await;
                    if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                    {
                        if let Some(oauth) = actor_oauth.as_ref() {
                            if let Ok(token) = oauth.access_token(true).await {
                                if let Ok(value) = oauth_header(&token) {
                                    actor_auth = Some(value);
                                    if let Ok(value) = initialize_stateless_session(
                                        &actor_client,
                                        &actor_url,
                                        actor_auth.as_ref(),
                                        &actor_protocol_version,
                                        tool_timeout_ms,
                                    )
                                    .await
                                    {
                                        actor_session_id = value;
                                        res = stateless_call_result(
                                            &actor_client,
                                            &actor_url,
                                            actor_session_id.as_deref(),
                                            actor_auth.as_ref(),
                                            &payload,
                                            per_server_timeout,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    }
                    let _ = reply.send(res);
                }
            }
        }
    });

    InitializedServer {
        server_id: server_id.clone(),
        readiness: readiness("ready", format!("Server '{}' is ready", server_id), false),
        sender: Some(tx),
        capabilities,
        resources,
        prompts,
    }
}

fn prompt_items_from_value(value: &Value) -> Vec<Value> {
    if let Some(items) = value.as_array() {
        return items.clone();
    }

    value
        .get("prompts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

async fn prepare_server_startup(
    server_id: String,
    srv_cfg: ServerConfig,
    auth_store_path: Option<String>,
    oauth_locks: RuntimeOAuthLocks,
) -> PreparedServerStartup {
    let transport = if let Some(command) = &srv_cfg.command {
        let resolved_command = match resolve_template_string(command) {
            Ok(value) => value,
            Err(error) => {
                return PreparedServerStartup {
                    server_id,
                    transport: PreparedServerTransport::Invalid(readiness(
                        "config_invalid",
                        error.to_string(),
                        false,
                    )),
                };
            }
        };
        let resolved_args = match srv_cfg
            .args
            .iter()
            .map(|value| resolve_template_string(value))
            .collect::<Result<Vec<_>>>()
        {
            Ok(value) => value,
            Err(error) => {
                return PreparedServerStartup {
                    server_id,
                    transport: PreparedServerTransport::Invalid(readiness(
                        "config_invalid",
                        error.to_string(),
                        false,
                    )),
                };
            }
        };
        let resolved_env = match resolve_template_map(&srv_cfg.env) {
            Ok(value) => value,
            Err(error) => {
                return PreparedServerStartup {
                    server_id,
                    transport: PreparedServerTransport::Invalid(readiness(
                        "config_invalid",
                        error.to_string(),
                        false,
                    )),
                };
            }
        };

        PreparedServerTransport::Stdio {
            command: resolved_command,
            args: resolved_args,
            env: resolved_env,
        }
    } else if let Some(url) = &srv_cfg.url {
        let resolved_url = match resolve_template_string(url) {
            Ok(value) => value,
            Err(error) => {
                return PreparedServerStartup {
                    server_id,
                    transport: PreparedServerTransport::Invalid(readiness(
                        "config_invalid",
                        error.to_string(),
                        false,
                    )),
                };
            }
        };
        let headers = match build_http_headers(
            &server_id,
            &srv_cfg,
            auth_store_path.as_deref(),
            Some(&resolved_url),
            Some(oauth_locks.clone()),
        )
        .await
        {
            Ok(value) => value,
            Err(readiness) => {
                return PreparedServerStartup {
                    server_id,
                    transport: PreparedServerTransport::Invalid(readiness),
                };
            }
        };
        let oauth = match &srv_cfg.auth {
            Some(AuthConfig::OAuth {
                client_id,
                client_secret,
                client_secret_env,
                scope,
                token_store_key,
                token_endpoint,
                ..
            }) => Some(RuntimeOAuth {
                server_id: server_id.clone(),
                key: token_store_key
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(&server_id)
                    .to_string(),
                auth_store_path: auth_store_path.clone(),
                resolved_url: resolved_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                client_secret_env: client_secret_env.clone(),
                scope: scope.clone(),
                token_endpoint: token_endpoint.clone(),
                locks: oauth_locks,
            }),
            _ => None,
        };

        PreparedServerTransport::Http {
            url: resolved_url,
            allow_stateless: srv_cfg.allow_stateless,
            headers,
            oauth,
        }
    } else {
        PreparedServerTransport::Invalid(readiness(
            "config_invalid",
            format!(
                "Server '{}' missing transport selector: set exactly one of 'command' or 'url'",
                server_id
            ),
            false,
        ))
    };

    PreparedServerStartup {
        server_id,
        transport,
    }
}

async fn initialize_prepared_server(
    prepared: PreparedServerStartup,
    capability_aliases: Arc<HashMap<String, String>>,
    resource_aliases: Arc<HashMap<String, String>>,
    prompt_aliases: Arc<HashMap<String, String>>,
    tool_timeout_ms: u64,
) -> InitializedServer {
    let PreparedServerStartup {
        server_id,
        transport,
    } = prepared;
    info!(%server_id, "starting upstream server");

    let mut streamable_actor = None;
    let mcp_client = match transport {
        PreparedServerTransport::Invalid(readiness) => {
            warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
            return InitializedServer {
                server_id,
                readiness,
                sender: None,
                capabilities: vec![],
                resources: vec![],
                prompts: vec![],
            };
        }
        PreparedServerTransport::Stdio { command, args, env } => {
            let mut cmd = Command::new(command);
            cmd.args(&args);
            cmd.envs(&env);

            let transport = match TokioChildProcess::new(cmd) {
                Ok(value) => value,
                Err(error) => {
                    let readiness = readiness(
                        "transport_unavailable",
                        format!("Failed to spawn process for {}: {}", server_id, error),
                        true,
                    );
                    warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                    return InitializedServer {
                        server_id,
                        readiness,
                        sender: None,
                        capabilities: vec![],
                        resources: vec![],
                        prompts: vec![],
                    };
                }
            };

            match ().serve(transport).await {
                Ok(value) => value,
                Err(error) => {
                    let readiness = readiness(
                        "transport_unavailable",
                        format!(
                            "Failed to negotiate stdio MCP connection for {}: {}",
                            server_id, error
                        ),
                        true,
                    );
                    warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                    return InitializedServer {
                        server_id,
                        readiness,
                        sender: None,
                        capabilities: vec![],
                        resources: vec![],
                        prompts: vec![],
                    };
                }
            }
        }
        PreparedServerTransport::Http {
            url,
            allow_stateless,
            headers,
            oauth,
        } => {
            if allow_stateless.unwrap_or(false) {
                return initialize_stateless_http_server(
                    server_id,
                    url,
                    headers,
                    oauth,
                    capability_aliases,
                    resource_aliases,
                    prompt_aliases,
                    tool_timeout_ms,
                )
                .await;
            }

            let http_client = match reqwest::Client::builder()
                .default_headers(headers.clone())
                .build()
            {
                Ok(value) => value,
                Err(error) => {
                    let readiness = readiness(
                        "transport_unavailable",
                        format!("Failed to build HTTP client for {}: {}", server_id, error),
                        true,
                    );
                    warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                    return InitializedServer {
                        server_id,
                        readiness,
                        sender: None,
                        capabilities: vec![],
                        resources: vec![],
                        prompts: vec![],
                    };
                }
            };

            let mut transport_config = StreamableHttpClientTransportConfig::with_uri(url.clone());
            if let Some(allow_stateless) = allow_stateless {
                transport_config.allow_stateless = allow_stateless;
            }
            let transport =
                StreamableHttpClientTransport::with_client(http_client, transport_config);
            streamable_actor = Some((url, allow_stateless, headers, oauth));
            match ().serve(transport).await {
                Ok(value) => value,
                Err(error) => {
                    let readiness = readiness(
                        "transport_unavailable",
                        format!(
                            "Failed to negotiate streamable HTTP MCP connection for {}: {}",
                            server_id, error
                        ),
                        true,
                    );
                    warn!(%server_id, code = %readiness.code, message = %readiness.message, retryable = readiness.retryable, "skipping upstream server during startup");
                    return InitializedServer {
                        server_id,
                        readiness,
                        sender: None,
                        capabilities: vec![],
                        resources: vec![],
                        prompts: vec![],
                    };
                }
            }
        }
    };

    let mut capabilities = vec![];
    let mut resources = vec![];
    let mut prompts = vec![];
    let (tools_result, resources_result, prompts_result) = tokio::join!(
        mcp_client.list_tools(Default::default()),
        mcp_client.list_resources(Default::default()),
        mcp_client.list_prompts(Default::default()),
    );

    if let Ok(tools) = tools_result {
        if let Ok(tools_json) = serde_json::to_value(&tools) {
            if let Some(tools_array) = tools_json.get("tools").and_then(|t| t.as_array()) {
                for tool in tools_array {
                    if let Some(tool_name) = tool.get("name").and_then(|n| n.as_str()) {
                        info!(%server_id, tool_name = %tool_name, "registered upstream tool");

                        let source_id = format!("{}.{}", server_id, tool_name);
                        let capability_id = capability_aliases
                            .get(&source_id)
                            .cloned()
                            .unwrap_or(source_id);
                        let summary = tool
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No summary available")
                            .to_string();
                        let description = summary.clone();
                        let input_schema = tool
                            .get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| json!({}));

                        capabilities.push((
                            capability_id,
                            CapabilityMeta {
                                server: server_id.clone(),
                                tool: tool_name.to_string(),
                                summary,
                                description,
                                input_schema,
                                tags: vec![server_id.clone()],
                                examples: vec![],
                            },
                        ));
                    }
                }
            }
        }
    }

    if let Ok(listed_resources) = resources_result {
        if let Ok(resources_json) = serde_json::to_value(&listed_resources) {
            if let Some(resource_array) = resources_json.get("resources").and_then(|r| r.as_array())
            {
                for resource in resource_array {
                    let Some(uri) = resource.get("uri").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let name = resource
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(uri)
                        .to_string();

                    let source_id = format!("{}.{}", server_id, uri);
                    let resource_id = resource_aliases
                        .get(&source_id)
                        .cloned()
                        .unwrap_or(source_id);
                    let description = resource
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    let mime_type = resource
                        .get("mimeType")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);

                    info!(%server_id, uri = %uri, "registered upstream resource");
                    resources.push((
                        resource_id,
                        ResourceMeta {
                            server: server_id.clone(),
                            uri: uri.to_string(),
                            name,
                            description,
                            mime_type,
                            tags: vec![server_id.clone()],
                        },
                    ));
                }
            }
        }
    }

    if let Ok(listed_prompts) = prompts_result {
        if let Ok(prompts_json) = serde_json::to_value(&listed_prompts) {
            for prompt in prompt_items_from_value(&prompts_json) {
                let Some(name) = prompt.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };

                let source_id = format!("{}.{}", server_id, name);
                let prompt_id = prompt_aliases.get(&source_id).cloned().unwrap_or(source_id);
                let title = prompt
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let description = prompt
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let arguments = prompt
                    .get("arguments")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                info!(%server_id, prompt_name = %name, "registered upstream prompt");
                prompts.push((
                    prompt_id,
                    PromptMeta {
                        server: server_id.clone(),
                        name: name.to_string(),
                        title,
                        description,
                        arguments,
                        tags: vec![server_id.clone()],
                    },
                ));
            }
        }
    }

    let (tx, mut rx) = mpsc::channel::<ServerMsg>(32);
    let per_server_timeout = Duration::from_millis(tool_timeout_ms);
    if let Some((actor_url, actor_allow_stateless, actor_headers, actor_oauth)) = streamable_actor {
        let actor_server_id = server_id.clone();
        tokio::spawn(async move {
            let mut base_headers = actor_headers.clone();
            base_headers.remove(AUTHORIZATION);
            let mut token = bearer_token(&actor_headers);
            let connect = |headers: HeaderMap| {
                let server_id = actor_server_id.clone();
                let url = actor_url.clone();
                async move {
                    let http_client = reqwest::Client::builder()
                        .default_headers(headers)
                        .build()
                        .map_err(|error| {
                            UpstreamCallError::Upstream(format!(
                                "Failed to build HTTP client for {}: {}",
                                server_id, error
                            ))
                        })?;
                    let mut transport_config = StreamableHttpClientTransportConfig::with_uri(url);
                    if let Some(allow_stateless) = actor_allow_stateless {
                        transport_config.allow_stateless = allow_stateless;
                    }
                    let transport =
                        StreamableHttpClientTransport::with_client(http_client, transport_config);
                    ().serve(transport).await.map_err(|error| {
                        UpstreamCallError::Upstream(format!(
                            "Failed to negotiate streamable HTTP MCP connection for {}: {}",
                            server_id, error
                        ))
                    })
                }
            };
            let mut mcp_client = mcp_client;

            while let Some(msg) = rx.recv().await {
                if let Some(oauth) = actor_oauth.as_ref() {
                    let next = match oauth.access_token(false).await {
                        Ok(value) => value,
                        Err(err) => {
                            let err = Err(UpstreamCallError::Upstream(err.to_string()));
                            match msg {
                                ServerMsg::CallTool { reply, .. }
                                | ServerMsg::ReadResource { reply, .. }
                                | ServerMsg::GetPrompt { reply, .. } => {
                                    let _ = reply.send(err);
                                }
                            }
                            continue;
                        }
                    };
                    if token.as_deref() != Some(next.as_str()) {
                        let headers = match auth_headers(&base_headers, &next) {
                            Ok(value) => value,
                            Err(err) => {
                                let err = Err(UpstreamCallError::Upstream(err.to_string()));
                                match msg {
                                    ServerMsg::CallTool { reply, .. }
                                    | ServerMsg::ReadResource { reply, .. }
                                    | ServerMsg::GetPrompt { reply, .. } => {
                                        let _ = reply.send(err);
                                    }
                                }
                                continue;
                            }
                        };
                        mcp_client = match timeout(per_server_timeout, connect(headers)).await {
                            Ok(Ok(value)) => value,
                            Ok(Err(err)) => {
                                match msg {
                                    ServerMsg::CallTool { reply, .. }
                                    | ServerMsg::ReadResource { reply, .. }
                                    | ServerMsg::GetPrompt { reply, .. } => {
                                        let _ = reply.send(Err(err));
                                    }
                                }
                                continue;
                            }
                            Err(_) => {
                                match msg {
                                    ServerMsg::CallTool { reply, .. }
                                    | ServerMsg::ReadResource { reply, .. }
                                    | ServerMsg::GetPrompt { reply, .. } => {
                                        let _ = reply.send(Err(UpstreamCallError::Upstream(
                                            format!(
                                                "Timed out reconnecting streamable HTTP MCP connection for {}",
                                                actor_server_id
                                            ),
                                        )));
                                    }
                                }
                                continue;
                            }
                        };
                        token = Some(next);
                    }
                }

                match msg {
                    ServerMsg::CallTool {
                        name,
                        params,
                        reply,
                    } => {
                        let req = CallToolRequestParams {
                            name: name.clone().into(),
                            arguments: params.as_object().cloned(),
                            meta: None,
                            task: None,
                        };
                        let mut res =
                            match timeout(per_server_timeout, mcp_client.call_tool(req)).await {
                                Ok(Ok(call_res)) => {
                                    Ok(serde_json::to_value(call_res).unwrap_or(Value::Null))
                                }
                                Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                                Err(_) => Err(UpstreamCallError::Timeout),
                            };
                        if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                        {
                            if let Some(oauth) = actor_oauth.as_ref() {
                                if let Ok(next) = oauth.access_token(true).await {
                                    if let Ok(headers) = auth_headers(&base_headers, &next) {
                                        if let Ok(Ok(value)) =
                                            timeout(per_server_timeout, connect(headers)).await
                                        {
                                            mcp_client = value;
                                            token = Some(next);
                                            let req = CallToolRequestParams {
                                                name: name.into(),
                                                arguments: params.as_object().cloned(),
                                                meta: None,
                                                task: None,
                                            };
                                            res = match timeout(
                                                per_server_timeout,
                                                mcp_client.call_tool(req),
                                            )
                                            .await
                                            {
                                                Ok(Ok(call_res)) => {
                                                    Ok(serde_json::to_value(call_res)
                                                        .unwrap_or(Value::Null))
                                                }
                                                Ok(Err(err)) => Err(UpstreamCallError::Upstream(
                                                    err.to_string(),
                                                )),
                                                Err(_) => Err(UpstreamCallError::Timeout),
                                            };
                                        }
                                    }
                                }
                            }
                        }
                        let _ = reply.send(res);
                    }
                    ServerMsg::ReadResource { uri, reply } => {
                        let req = ReadResourceRequestParams {
                            meta: None,
                            uri: uri.clone(),
                        };
                        let mut res = match timeout(
                            per_server_timeout,
                            mcp_client.read_resource(req),
                        )
                        .await
                        {
                            Ok(Ok(read_res)) => {
                                Ok(serde_json::to_value(read_res).unwrap_or(Value::Null))
                            }
                            Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                            Err(_) => Err(UpstreamCallError::Timeout),
                        };
                        if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                        {
                            if let Some(oauth) = actor_oauth.as_ref() {
                                if let Ok(next) = oauth.access_token(true).await {
                                    if let Ok(headers) = auth_headers(&base_headers, &next) {
                                        if let Ok(Ok(value)) =
                                            timeout(per_server_timeout, connect(headers)).await
                                        {
                                            mcp_client = value;
                                            token = Some(next);
                                            let req = ReadResourceRequestParams { meta: None, uri };
                                            res = match timeout(
                                                per_server_timeout,
                                                mcp_client.read_resource(req),
                                            )
                                            .await
                                            {
                                                Ok(Ok(read_res)) => {
                                                    Ok(serde_json::to_value(read_res)
                                                        .unwrap_or(Value::Null))
                                                }
                                                Ok(Err(err)) => Err(UpstreamCallError::Upstream(
                                                    err.to_string(),
                                                )),
                                                Err(_) => Err(UpstreamCallError::Timeout),
                                            };
                                        }
                                    }
                                }
                            }
                        }
                        let _ = reply.send(res);
                    }
                    ServerMsg::GetPrompt {
                        name,
                        arguments,
                        reply,
                    } => {
                        let req = GetPromptRequestParams {
                            meta: None,
                            name: name.clone(),
                            arguments: arguments.clone(),
                        };
                        let mut res =
                            match timeout(per_server_timeout, mcp_client.get_prompt(req)).await {
                                Ok(Ok(prompt_res)) => {
                                    Ok(serde_json::to_value(prompt_res).unwrap_or(Value::Null))
                                }
                                Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                                Err(_) => Err(UpstreamCallError::Timeout),
                            };
                        if matches!(&res, Err(UpstreamCallError::Upstream(err)) if actor_oauth.is_some() && auth_error(err))
                        {
                            if let Some(oauth) = actor_oauth.as_ref() {
                                if let Ok(next) = oauth.access_token(true).await {
                                    if let Ok(headers) = auth_headers(&base_headers, &next) {
                                        if let Ok(Ok(value)) =
                                            timeout(per_server_timeout, connect(headers)).await
                                        {
                                            mcp_client = value;
                                            token = Some(next);
                                            let req = GetPromptRequestParams {
                                                meta: None,
                                                name,
                                                arguments,
                                            };
                                            res = match timeout(
                                                per_server_timeout,
                                                mcp_client.get_prompt(req),
                                            )
                                            .await
                                            {
                                                Ok(Ok(prompt_res)) => {
                                                    Ok(serde_json::to_value(prompt_res)
                                                        .unwrap_or(Value::Null))
                                                }
                                                Ok(Err(err)) => Err(UpstreamCallError::Upstream(
                                                    err.to_string(),
                                                )),
                                                Err(_) => Err(UpstreamCallError::Timeout),
                                            };
                                        }
                                    }
                                }
                            }
                        }
                        let _ = reply.send(res);
                    }
                }
            }
        });
    } else {
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ServerMsg::CallTool {
                        name,
                        params,
                        reply,
                    } => {
                        let req = CallToolRequestParams {
                            name: name.into(),
                            arguments: params.as_object().cloned(),
                            meta: None,
                            task: None,
                        };

                        let result = timeout(per_server_timeout, mcp_client.call_tool(req)).await;
                        let res = match result {
                            Ok(Ok(call_res)) => {
                                Ok(serde_json::to_value(call_res).unwrap_or(Value::Null))
                            }
                            Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                            Err(_) => Err(UpstreamCallError::Timeout),
                        };
                        let _ = reply.send(res);
                    }
                    ServerMsg::ReadResource { uri, reply } => {
                        let req = ReadResourceRequestParams { meta: None, uri };
                        let result =
                            timeout(per_server_timeout, mcp_client.read_resource(req)).await;
                        let res = match result {
                            Ok(Ok(read_res)) => {
                                Ok(serde_json::to_value(read_res).unwrap_or(Value::Null))
                            }
                            Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                            Err(_) => Err(UpstreamCallError::Timeout),
                        };
                        let _ = reply.send(res);
                    }
                    ServerMsg::GetPrompt {
                        name,
                        arguments,
                        reply,
                    } => {
                        let req = GetPromptRequestParams {
                            meta: None,
                            name,
                            arguments,
                        };
                        let result = timeout(per_server_timeout, mcp_client.get_prompt(req)).await;
                        let res = match result {
                            Ok(Ok(prompt_res)) => {
                                Ok(serde_json::to_value(prompt_res).unwrap_or(Value::Null))
                            }
                            Ok(Err(err)) => Err(UpstreamCallError::Upstream(err.to_string())),
                            Err(_) => Err(UpstreamCallError::Timeout),
                        };
                        let _ = reply.send(res);
                    }
                }
            }
        });
    }

    InitializedServer {
        server_id: server_id.clone(),
        readiness: readiness("ready", format!("Server '{}' is ready", server_id), false),
        sender: Some(tx),
        capabilities,
        resources,
        prompts,
    }
}

pub async fn initialize_state(config: McpConfig) -> Result<AppState> {
    let McpConfig {
        port: _,
        tool_timeout_ms,
        auth_store_path,
        capability_aliases,
        resource_aliases,
        prompt_aliases,
        policy: policy_config,
        mcp_servers,
    } = config;
    let mut server_channels = HashMap::new();
    let mut server_readiness = HashMap::new();
    let mut capabilities = HashMap::new();
    let mut resources = HashMap::new();
    let mut prompts = HashMap::new();
    let tool_timeout_ms = tool_timeout_ms.unwrap_or(DEFAULT_TOOL_TIMEOUT_MS);
    let policy = Policy::from_config(policy_config);
    let capability_aliases = Arc::new(capability_aliases);
    let resource_aliases = Arc::new(resource_aliases);
    let prompt_aliases = Arc::new(prompt_aliases);
    let oauth_locks = RuntimeOAuthLocks::default();
    let mut sorted_servers = mcp_servers.into_iter().collect::<Vec<_>>();
    sorted_servers.sort_by(|left, right| left.0.cmp(&right.0));

    info!(
        server_count = sorted_servers.len(),
        "booting upstream MCP servers"
    );

    let prepared = join_all(sorted_servers.into_iter().map(|(server_id, srv_cfg)| {
        prepare_server_startup(
            server_id,
            srv_cfg,
            auth_store_path.clone(),
            oauth_locks.clone(),
        )
    }))
    .await;

    let initialized = join_all(prepared.into_iter().map(|server| {
        initialize_prepared_server(
            server,
            capability_aliases.clone(),
            resource_aliases.clone(),
            prompt_aliases.clone(),
            tool_timeout_ms,
        )
    }))
    .await;

    for server in initialized {
        server_readiness.insert(server.server_id.clone(), server.readiness);
        if let Some(sender) = server.sender {
            server_channels.insert(server.server_id.clone(), sender);
        }
        for (capability_id, meta) in server.capabilities {
            if capabilities.contains_key(&capability_id) {
                return Err(anyhow!(
                    "Duplicate capability id '{}'. Use capabilityAliases to disambiguate",
                    capability_id
                ));
            }
            capabilities.insert(capability_id, meta);
        }
        for (resource_id, meta) in server.resources {
            if resources.contains_key(&resource_id) {
                return Err(anyhow!(
                    "Duplicate resource id '{}'. Use resourceAliases to disambiguate",
                    resource_id
                ));
            }
            resources.insert(resource_id, meta);
        }
        for (prompt_id, meta) in server.prompts {
            if prompts.contains_key(&prompt_id) {
                return Err(anyhow!(
                    "Duplicate prompt id '{}'. Use promptAliases to disambiguate",
                    prompt_id
                ));
            }
            prompts.insert(prompt_id, meta);
        }
    }

    Ok(AppState {
        servers: Arc::new(server_channels),
        server_readiness: Arc::new(server_readiness),
        capabilities: Arc::new(capabilities),
        resources: Arc::new(resources),
        prompts: Arc::new(prompts),
        tool_timeout_ms,
        policy,
    })
}

pub async fn run_daemon(port: u16, config: McpConfig) -> Result<()> {
    let app_state = initialize_state(config).await?;
    let app = Router::new()
        .route("/v1/capabilities", get(http_v1::handle_list_capabilities))
        .route(
            "/v1/capabilities/:id",
            get(http_v1::handle_describe_capability),
        )
        .route("/v1/resources", get(http_v1::handle_list_resources))
        .route("/v1/resources/read", post(http_v1::handle_read_resource))
        .route("/v1/prompts", get(http_v1::handle_list_prompts))
        .route("/v1/prompts/get", post(http_v1::handle_get_prompt))
        .route("/v1/tools/call", post(http_v1::handle_call_capability))
        .with_state(app_state);

    info!(port, "all upstream servers connected; daemon listening");
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_http_headers, initialize_state, now_epoch_seconds, parse_stateless_http_response,
        prompt_items_from_value, resolve_template_string, wildcard_match, Policy, ServerMsg,
    };
    use crate::{
        auth_store::OAuthEntry,
        config::{AuthConfig, McpConfig, ServerConfig},
    };
    use axum::{
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
        routing::post,
        Form, Json, Router,
    };
    use serde::Deserialize;
    use serde_json::json;
    use std::{
        collections::HashMap,
        fs,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{net::TcpListener, sync::oneshot};

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, unique));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    #[derive(Debug, Deserialize)]
    struct RefreshForm {
        grant_type: String,
        refresh_token: String,
    }

    async fn refresh_handler(Form(form): Form<RefreshForm>) -> Json<serde_json::Value> {
        assert_eq!(form.grant_type, "refresh_token");
        assert_eq!(form.refresh_token, "refresh-token");
        Json(json!({
            "access_token": "fresh-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }))
    }

    async fn spawn_refresh_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/oauth/token", post(refresh_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", address)
    }

    #[derive(Clone)]
    struct RuntimeServerState {
        refreshes: Arc<AtomicUsize>,
    }

    async fn runtime_refresh_handler(
        State(state): State<RuntimeServerState>,
        Form(form): Form<RefreshForm>,
    ) -> Json<serde_json::Value> {
        assert_eq!(form.grant_type, "refresh_token");
        assert_eq!(form.refresh_token, "refresh-token");
        state.refreshes.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "access_token": "fresh-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }))
    }

    async fn runtime_mcp_handler(
        State(_state): State<RuntimeServerState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> impl IntoResponse {
        let method = body
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if method == "notifications/initialized" {
            return StatusCode::OK.into_response();
        }

        let auth = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if auth != "Bearer startup-token" && auth != "Bearer fresh-token" {
            return (StatusCode::UNAUTHORIZED, "Auth required").into_response();
        }

        let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);
        if method == "initialize" {
            let mut response_headers = HeaderMap::new();
            response_headers.insert("mcp-session-id", HeaderValue::from_static("session-1"));
            return (
                response_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {}
                        },
                        "serverInfo": {
                            "name": "runtime-test",
                            "version": "1.0.0"
                        }
                    }
                })),
            )
                .into_response();
        }
        if method == "tools/list" {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [{
                        "name": "ping",
                        "description": "Ping",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }]
                }
            }))
            .into_response();
        }
        if method == "resources/list" {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "resources": [] }
            }))
            .into_response();
        }
        if method == "prompts/list" {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "prompts": [] }
            }))
            .into_response();
        }
        if method == "tools/call" {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": auth.trim_start_matches("Bearer ")
                    }]
                }
            }))
            .into_response();
        }

        (
            StatusCode::BAD_REQUEST,
            format!("unsupported method: {}", method),
        )
            .into_response()
    }

    async fn spawn_runtime_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let state = RuntimeServerState {
            refreshes: refreshes.clone(),
        };
        let app = Router::new()
            .route("/mcp", post(runtime_mcp_handler))
            .route("/oauth/token", post(runtime_refresh_handler))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", address), refreshes)
    }

    #[test]
    fn wildcard_prefix_match_works() {
        assert!(wildcard_match("db.*", "db.query"));
        assert!(!wildcard_match("db.*", "fs.read"));
    }

    #[test]
    fn policy_deny_overrides_allow() {
        let policy = Policy {
            allow: vec!["db.*".to_string()],
            deny: vec!["db.delete".to_string()],
            redact_keys: vec![],
        };

        assert!(policy.allows("db.query"));
        assert!(!policy.allows("db.delete"));
    }

    #[test]
    fn policy_allow_list_is_enforced() {
        let policy = Policy {
            allow: vec!["fs.read".to_string()],
            deny: vec![],
            redact_keys: vec![],
        };

        assert!(policy.allows("fs.read"));
        assert!(!policy.allows("fs.write"));
    }

    #[test]
    fn resolve_template_string_expands_env_placeholders() {
        unsafe {
            std::env::set_var("WARMPLANE_TEMPLATE_TEST", "value");
        }
        let resolved = resolve_template_string("Bearer {env:WARMPLANE_TEMPLATE_TEST}")
            .expect("template should resolve");
        assert_eq!(resolved, "Bearer value");
    }

    #[test]
    fn prompt_items_from_value_supports_both_prompt_shapes() {
        let object_shape = json!({
            "prompts": [
                { "name": "one" },
                { "name": "two" }
            ]
        });
        let array_shape = json!([
            { "name": "three" },
            { "name": "four" }
        ]);

        assert_eq!(prompt_items_from_value(&object_shape).len(), 2);
        assert_eq!(prompt_items_from_value(&array_shape).len(), 2);
    }

    #[test]
    fn parse_stateless_http_response_supports_event_stream_payloads() {
        let body = concat!(
            "id:1\n",
            "event:message\n",
            "data:{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"webReader\"}]}}\n",
        );

        let parsed = parse_stateless_http_response(body)
            .expect("event-stream payload should parse")
            .expect("event-stream payload should produce a value");
        assert_eq!(parsed["result"]["tools"][0]["name"], "webReader");
    }

    #[test]
    fn parse_stateless_http_response_supports_empty_notification_responses() {
        let parsed = parse_stateless_http_response("\n\n").expect("empty response should parse");
        assert!(parsed.is_none());
    }

    #[tokio::test]
    async fn build_http_headers_refreshes_expired_oauth_tokens() {
        let base_url = spawn_refresh_server().await;
        let dir = temp_dir("warmplane-daemon-refresh");
        let auth_store_path = dir.join("mcp-auth.json");
        fs::write(
            &auth_store_path,
            serde_json::to_string_pretty(&HashMap::from([(
                "figma".to_string(),
                OAuthEntry {
                    tokens: Some(crate::auth_store::OAuthTokens {
                        access_token: "expired-token".to_string(),
                        refresh_token: Some("refresh-token".to_string()),
                        expires_at: Some(1),
                        scope: Some("files:read".to_string()),
                    }),
                    discovery: Some(crate::oauth_discovery::OAuthDiscoveryMetadata {
                        token_endpoint: Some(format!("{}/oauth/token", base_url)),
                        ..Default::default()
                    }),
                    server_url: Some("https://mcp.figma.com/mcp".to_string()),
                    ..Default::default()
                },
            )]))
            .unwrap(),
        )
        .unwrap();

        let server = ServerConfig {
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some("https://mcp.figma.com/mcp".to_string()),
            protocol_version: None,
            allow_stateless: None,
            headers: HashMap::new(),
            auth: Some(AuthConfig::OAuth {
                client_id: Some("client-id".to_string()),
                client_name: None,
                client_secret: None,
                client_secret_env: None,
                redirect_uri: None,
                scope: Some("files:read".to_string()),
                token_store_key: Some("figma".to_string()),
                authorization_server: None,
                resource_metadata_url: None,
                authorization_endpoint: None,
                token_endpoint: None,
                registration_endpoint: None,
                code_challenge_methods_supported: vec![],
            }),
        };

        let headers = build_http_headers(
            "figma",
            &server,
            Some(auth_store_path.to_str().unwrap()),
            Some("https://mcp.figma.com/mcp"),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer fresh-token")
        );

        let saved_store: HashMap<String, OAuthEntry> =
            serde_json::from_str(&fs::read_to_string(&auth_store_path).unwrap()).unwrap();
        assert_eq!(
            saved_store
                .get("figma")
                .and_then(|entry| entry.tokens.as_ref())
                .map(|tokens| tokens.access_token.as_str()),
            Some("fresh-token")
        );
        assert_eq!(
            saved_store
                .get("figma")
                .and_then(|entry| entry.tokens.as_ref())
                .and_then(|tokens| tokens.refresh_token.as_deref()),
            Some("rotated-refresh-token")
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stateless_http_actor_refreshes_expired_oauth_tokens_after_startup() {
        let (base_url, refreshes) = spawn_runtime_server().await;
        let dir = temp_dir("warmplane-daemon-runtime-refresh");
        let auth_store_path = dir.join("mcp-auth.json");
        let server_url = format!("{}/mcp", base_url);
        let token_endpoint = format!("{}/oauth/token", base_url);
        fs::write(
            &auth_store_path,
            serde_json::to_string_pretty(&HashMap::from([(
                "notion".to_string(),
                OAuthEntry {
                    tokens: Some(crate::auth_store::OAuthTokens {
                        access_token: "startup-token".to_string(),
                        refresh_token: Some("refresh-token".to_string()),
                        expires_at: Some(now_epoch_seconds() + 3_600),
                        scope: None,
                    }),
                    discovery: Some(crate::oauth_discovery::OAuthDiscoveryMetadata {
                        token_endpoint: Some(token_endpoint.clone()),
                        ..Default::default()
                    }),
                    server_url: Some(server_url.clone()),
                    ..Default::default()
                },
            )]))
            .unwrap(),
        )
        .unwrap();

        let state = initialize_state(McpConfig {
            port: None,
            tool_timeout_ms: Some(15_000),
            auth_store_path: Some(auth_store_path.to_str().unwrap().to_string()),
            capability_aliases: HashMap::new(),
            resource_aliases: HashMap::new(),
            prompt_aliases: HashMap::new(),
            policy: None,
            mcp_servers: HashMap::from([(
                "notion".to_string(),
                ServerConfig {
                    command: None,
                    args: vec![],
                    env: HashMap::new(),
                    url: Some(server_url.clone()),
                    protocol_version: None,
                    allow_stateless: Some(true),
                    headers: HashMap::new(),
                    auth: Some(AuthConfig::OAuth {
                        client_id: None,
                        client_name: None,
                        client_secret: None,
                        client_secret_env: None,
                        redirect_uri: None,
                        scope: None,
                        token_store_key: Some("notion".to_string()),
                        authorization_server: None,
                        resource_metadata_url: None,
                        authorization_endpoint: None,
                        token_endpoint: None,
                        registration_endpoint: None,
                        code_challenge_methods_supported: vec![],
                    }),
                },
            )]),
        })
        .await
        .unwrap();

        fs::write(
            &auth_store_path,
            serde_json::to_string_pretty(&HashMap::from([(
                "notion".to_string(),
                OAuthEntry {
                    tokens: Some(crate::auth_store::OAuthTokens {
                        access_token: "expired-token".to_string(),
                        refresh_token: Some("refresh-token".to_string()),
                        expires_at: Some(1),
                        scope: None,
                    }),
                    discovery: Some(crate::oauth_discovery::OAuthDiscoveryMetadata {
                        token_endpoint: Some(token_endpoint),
                        ..Default::default()
                    }),
                    server_url: Some(server_url),
                    ..Default::default()
                },
            )]))
            .unwrap(),
        )
        .unwrap();

        let sender = state.servers.get("notion").cloned().unwrap_or_else(|| {
            panic!(
                "{}",
                state
                    .server_readiness
                    .get("notion")
                    .map(|value| value.message.clone())
                    .unwrap_or_else(|| "missing readiness".to_string())
            )
        });
        let (reply_tx, reply_rx) = oneshot::channel();
        sender
            .send(ServerMsg::CallTool {
                name: "ping".to_string(),
                params: json!({}),
                reply: reply_tx,
            })
            .await
            .unwrap();

        let value = reply_rx.await.unwrap().unwrap();
        assert!(value.to_string().contains("fresh-token"));
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);

        let saved_store: HashMap<String, OAuthEntry> =
            serde_json::from_str(&fs::read_to_string(&auth_store_path).unwrap()).unwrap();
        assert_eq!(
            saved_store
                .get("notion")
                .and_then(|entry| entry.tokens.as_ref())
                .map(|tokens| tokens.access_token.as_str()),
            Some("fresh-token")
        );
        assert_eq!(
            saved_store
                .get("notion")
                .and_then(|entry| entry.tokens.as_ref())
                .and_then(|tokens| tokens.refresh_token.as_deref()),
            Some("rotated-refresh-token")
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
