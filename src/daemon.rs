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
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    process::Command,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tracing::{info, warn};

use crate::{
    auth_store::{derive_auth_status, load_store, save_store, OAuthAuthStatus},
    config::{AuthConfig, McpConfig, PolicyConfig, ServerConfig, DEFAULT_TOOL_TIMEOUT_MS},
    http_v1,
    oauth_client::{refresh_oauth_tokens, OAuthRefreshRequest},
};

const DEFAULT_MCP_PROTOCOL_VERSION: &str = "2025-11-25";

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
                                        "Server '{}' oauth credentials are expired and no refresh token is available. Re-import credentials with 'warmplane auth import --config <path> --server {} ...'",
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
                                        "Server '{}' oauth credentials are expired but discovery metadata is incomplete. Run 'warmplane auth discover --config <path> --server {}' first",
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
                                "Server '{}' missing usable oauth credentials. Run 'warmplane auth discover --config <path> --server {}' to inspect upstream metadata, then import credentials with 'warmplane auth import --config <path> --server {} --access-token-env <ENV>'",
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

        PreparedServerTransport::Http {
            url: resolved_url,
            allow_stateless: srv_cfg.allow_stateless,
            headers,
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
        } => {
            let http_client = match reqwest::Client::builder().default_headers(headers).build() {
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

            let mut transport_config = StreamableHttpClientTransportConfig::with_uri(url);
            if let Some(allow_stateless) = allow_stateless {
                transport_config.allow_stateless = allow_stateless;
            }
            let transport =
                StreamableHttpClientTransport::with_client(http_client, transport_config);
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
                    let result = timeout(per_server_timeout, mcp_client.read_resource(req)).await;
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
    let mut sorted_servers = mcp_servers.into_iter().collect::<Vec<_>>();
    sorted_servers.sort_by(|left, right| left.0.cmp(&right.0));

    info!(
        server_count = sorted_servers.len(),
        "booting upstream MCP servers"
    );

    let prepared = join_all(sorted_servers.into_iter().map(|(server_id, srv_cfg)| {
        prepare_server_startup(server_id, srv_cfg, auth_store_path.clone())
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
        build_http_headers, prompt_items_from_value, resolve_template_string, wildcard_match,
        Policy,
    };
    use crate::{
        auth_store::OAuthEntry,
        config::{AuthConfig, ServerConfig},
    };
    use axum::{routing::post, Form, Json, Router};
    use serde::Deserialize;
    use serde_json::json;
    use std::{
        collections::HashMap,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::net::TcpListener;

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
}
