use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Value};

mod auth_store;
mod config;
mod daemon;
mod http_v1;
mod mcp_server;
mod models;
mod oauth_client;
mod oauth_discovery;
mod oauth_loopback;
mod telemetry;

use auth_store::{
    derive_auth_status, load_store, save_store, OAuthClientInfo, OAuthEntry, OAuthTokens,
};
use config::{load_config, resolve_client_port, AuthConfig, McpConfig, ServerConfig, DEFAULT_PORT};
use models::{AuthCommands, Cli, Commands};
use oauth_client::{
    exchange_authorization_code, refresh_oauth_tokens, register_oauth_client,
    start_oauth_authorization, OAuthClientRegistrationRequest, OAuthCodeExchangeRequest,
    OAuthRefreshRequest, OAuthStartRequest,
};
use oauth_discovery::{discover_oauth_metadata, OAuthDiscoveryMetadata};
use oauth_loopback::{receive_oauth_callback, try_open_browser};

const DEFAULT_OAUTH_CLIENT_NAME: &str = "warmplane";
const DEFAULT_OAUTH_REDIRECT_URI: &str = "http://127.0.0.1:8788/callback";
const DEFAULT_OAUTH_CALLBACK_TIMEOUT_SECS: u64 = 300;

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

fn resolve_server_url(server_config: &ServerConfig) -> Result<Option<String>> {
    server_config
        .url
        .as_deref()
        .map(resolve_template_string)
        .transpose()
}

fn resolve_oauth_server<'a>(
    config: &'a McpConfig,
    server: &str,
) -> Result<(&'a ServerConfig, &'a AuthConfig, String)> {
    let server_config = config
        .mcp_servers
        .get(server)
        .with_context(|| format!("OAuth server '{}' not found in config", server))?;
    let auth = server_config
        .auth
        .as_ref()
        .with_context(|| format!("Server '{}' does not define auth", server))?;
    if !matches!(auth, AuthConfig::OAuth { .. }) {
        anyhow::bail!("Server '{}' is not configured for oauth auth", server);
    }

    let token_store_key = match auth {
        AuthConfig::OAuth {
            token_store_key, ..
        } => token_store_key
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(server)
            .to_string(),
        _ => unreachable!(),
    };

    Ok((server_config, auth, token_store_key))
}

fn resolve_optional_secret(
    direct: &Option<String>,
    env_name: &Option<String>,
    field_name: &str,
) -> Result<Option<String>> {
    let has_direct = direct
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let has_env = env_name
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if has_direct && has_env {
        anyhow::bail!(
            "{} cannot be provided via both direct value and env var",
            field_name
        );
    }

    if has_direct {
        return Ok(direct.clone());
    }

    if let Some(name) = env_name {
        return Ok(Some(std::env::var(name).with_context(|| {
            format!("Failed to read env var '{}' for {}", name, field_name)
        })?));
    }

    Ok(None)
}

fn resolve_oauth_client_id(auth: &AuthConfig, entry: &OAuthEntry) -> Option<String> {
    match auth {
        AuthConfig::OAuth { client_id, .. } => client_id.clone().or_else(|| {
            entry
                .client_info
                .as_ref()
                .map(|value| value.client_id.clone())
        }),
        _ => None,
    }
}

fn resolve_oauth_client_secret(auth: &AuthConfig, entry: &OAuthEntry) -> Result<Option<String>> {
    match auth {
        AuthConfig::OAuth {
            client_secret,
            client_secret_env,
            ..
        } => resolve_optional_secret(client_secret, client_secret_env, "client secret").map(
            |value| {
                value.or_else(|| {
                    entry
                        .client_info
                        .as_ref()
                        .and_then(|info| info.client_secret.clone())
                })
            },
        ),
        _ => Ok(None),
    }
}

fn resolve_oauth_redirect_uri(auth: &AuthConfig) -> String {
    match auth {
        AuthConfig::OAuth { redirect_uri, .. } => redirect_uri
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_OAUTH_REDIRECT_URI.to_string()),
        _ => DEFAULT_OAUTH_REDIRECT_URI.to_string(),
    }
}

fn resolve_oauth_client_name(auth: &AuthConfig) -> String {
    match auth {
        AuthConfig::OAuth { client_name, .. } => client_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_OAUTH_CLIENT_NAME.to_string()),
        _ => DEFAULT_OAUTH_CLIENT_NAME.to_string(),
    }
}

fn discovery_overrides_from_auth(
    auth: &AuthConfig,
    server_url: Option<&str>,
) -> Option<OAuthDiscoveryMetadata> {
    let AuthConfig::OAuth {
        authorization_server,
        resource_metadata_url,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        code_challenge_methods_supported,
        ..
    } = auth
    else {
        return None;
    };

    let has_override = authorization_endpoint.is_some()
        || token_endpoint.is_some()
        || registration_endpoint.is_some()
        || authorization_server.is_some()
        || resource_metadata_url.is_some()
        || !code_challenge_methods_supported.is_empty();
    if !has_override {
        return None;
    }

    Some(OAuthDiscoveryMetadata {
        resource_metadata_url: resource_metadata_url
            .clone()
            .or_else(|| server_url.map(ToString::to_string)),
        authorization_server: authorization_server.clone(),
        authorization_metadata_url: None,
        authorization_endpoint: authorization_endpoint.clone(),
        token_endpoint: token_endpoint.clone(),
        registration_endpoint: registration_endpoint.clone(),
        scopes_supported: vec![],
        code_challenge_methods_supported: code_challenge_methods_supported.clone(),
    })
}

fn resolve_token_endpoint(auth: &AuthConfig, entry: &OAuthEntry) -> Option<String> {
    entry
        .discovery
        .as_ref()
        .and_then(|value| value.token_endpoint.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match auth {
            AuthConfig::OAuth { token_endpoint, .. } => token_endpoint
                .clone()
                .filter(|value| !value.trim().is_empty()),
            _ => None,
        })
}

async fn refresh_oauth_entry(
    server: &str,
    auth: &AuthConfig,
    entry: &OAuthEntry,
) -> Result<OAuthEntry> {
    let refresh_token = entry
        .tokens
        .as_ref()
        .and_then(|value| value.refresh_token.clone())
        .filter(|value| !value.trim().is_empty())
        .with_context(|| {
            format!(
                "Server '{}' is missing a refresh token in the shared auth store",
                server
            )
        })?;
    let token_endpoint = resolve_token_endpoint(auth, entry).with_context(|| {
            format!(
                "Server '{}' is missing discovered token endpoint metadata. Run 'warmplane auth discover --config <path> {}' first",
                server, server
            )
        })?;
    let scope = match auth {
        AuthConfig::OAuth { scope, .. } => scope
            .clone()
            .or_else(|| entry.tokens.as_ref().and_then(|value| value.scope.clone())),
        _ => None,
    };

    let refreshed_tokens = refresh_oauth_tokens(OAuthRefreshRequest {
        token_endpoint,
        refresh_token,
        client_id: resolve_oauth_client_id(auth, entry),
        client_secret: resolve_oauth_client_secret(auth, entry)?,
        scope,
    })
    .await?;

    let mut next = entry.clone();
    next.tokens = Some(refreshed_tokens);
    Ok(next)
}

async fn start_oauth_entry(
    server: &str,
    auth: &AuthConfig,
    entry: &OAuthEntry,
) -> Result<(OAuthEntry, Value)> {
    let discovery = entry.discovery.as_ref().with_context(|| {
        format!(
            "Server '{}' is missing discovered OAuth metadata. Run 'warmplane auth discover --config <path> {}' first",
            server, server
        )
    })?;
    let authorization_endpoint = discovery
        .authorization_endpoint
        .clone()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| {
            format!(
                "Server '{}' is missing discovered authorization endpoint metadata",
                server
            )
        })?;
    if !discovery
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        anyhow::bail!(
            "Server '{}' does not advertise PKCE S256 support in discovery metadata",
            server
        );
    }

    let redirect_uri = resolve_oauth_redirect_uri(auth);
    let mut next_entry = entry.clone();
    if resolve_oauth_client_id(auth, &next_entry).is_none() {
        let registration_endpoint = discovery
            .registration_endpoint
            .clone()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| {
                format!(
                    "Server '{}' is missing a client_id and discovery metadata does not advertise a registration endpoint",
                    server
                )
            })?;
        next_entry.client_info = Some(
            register_oauth_client(OAuthClientRegistrationRequest {
                registration_endpoint,
                client_name: resolve_oauth_client_name(auth),
                redirect_uri: redirect_uri.clone(),
                scope: match auth {
                    AuthConfig::OAuth { scope, .. } => scope.clone(),
                    _ => None,
                },
            })
            .await?,
        );
    }

    let client_id = resolve_oauth_client_id(auth, &next_entry).with_context(|| {
        format!(
            "Server '{}' is missing a client_id even after client registration",
            server
        )
    })?;
    let scope = match auth {
        AuthConfig::OAuth { scope, .. } => scope.clone(),
        _ => None,
    };
    let started = start_oauth_authorization(OAuthStartRequest {
        authorization_endpoint,
        client_id,
        redirect_uri,
        scope,
        resource: next_entry.server_url.clone(),
    })?;
    next_entry.oauth_state = Some(started.state.clone());
    next_entry.code_verifier = Some(started.code_verifier.clone());

    Ok((
        next_entry,
        json!({
            "authorizationUrl": started.authorization_url,
            "redirectUri": started.redirect_uri,
            "state": started.state,
            "codeVerifier": started.code_verifier,
        }),
    ))
}

async fn ensure_discovery_entry(
    server: &str,
    server_config: &ServerConfig,
    auth: &AuthConfig,
    entry: &OAuthEntry,
) -> Result<OAuthEntry> {
    if entry.discovery.is_some() {
        return Ok(entry.clone());
    }

    let resolved_url = resolve_server_url(server_config)?.with_context(|| {
        format!(
            "Server '{}' is missing a URL for OAuth discovery/bootstrap",
            server
        )
    })?;
    let discovery = match discover_oauth_metadata(&resolved_url).await {
        Ok(discovery) => discovery,
        Err(error) => {
            discovery_overrides_from_auth(auth, Some(&resolved_url)).with_context(|| {
                format!("OAuth discovery failed for server '{}': {}", server, error)
            })?
        }
    };
    let mut next = entry.clone();
    next.server_url = Some(resolved_url);
    next.discovery = Some(discovery);
    Ok(next)
}

async fn exchange_oauth_entry(
    server: &str,
    auth: &AuthConfig,
    entry: &OAuthEntry,
    code: &str,
    state: &str,
) -> Result<OAuthEntry> {
    let expected_state = entry.oauth_state.as_deref().with_context(|| {
        format!(
            "Server '{}' does not have a stored OAuth state. Run 'warmplane auth start --config <path> {}' first",
            server, server
        )
    })?;
    if expected_state != state {
        anyhow::bail!(
            "Server '{}' OAuth state mismatch. Restart auth with 'warmplane auth start --config <path> {}'",
            server,
            server
        );
    }

    let discovery = entry.discovery.as_ref().with_context(|| {
        format!(
            "Server '{}' is missing discovered OAuth metadata. Run 'warmplane auth discover --config <path> {}' first",
            server, server
        )
    })?;
    let token_endpoint = discovery
        .token_endpoint
        .clone()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| {
            format!(
                "Server '{}' is missing discovered token endpoint metadata",
                server
            )
        })?;
    let code_verifier = entry
        .code_verifier
        .clone()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| {
            format!(
                "Server '{}' is missing a stored PKCE code verifier. Restart auth with 'warmplane auth start --config <path> {}'",
                server, server
            )
        })?;
    let client_id = resolve_oauth_client_id(auth, entry).with_context(|| {
        format!(
            "Server '{}' is missing a client_id for token exchange",
            server
        )
    })?;
    let redirect_uri = resolve_oauth_redirect_uri(auth);
    let tokens = exchange_authorization_code(OAuthCodeExchangeRequest {
        token_endpoint,
        code: code.to_string(),
        redirect_uri,
        code_verifier,
        client_id,
        client_secret: resolve_oauth_client_secret(auth, entry)?,
    })
    .await?;

    let mut next = entry.clone();
    next.tokens = Some(tokens);
    next.oauth_state = None;
    next.code_verifier = None;
    Ok(next)
}

fn build_auth_status_payload(
    config_path: &str,
    config: &McpConfig,
    server_filter: Option<&str>,
) -> Result<Value> {
    let (auth_store_path, store) = load_store(config.auth_store_path.as_deref())?;
    let mut servers = Vec::new();

    for (server_id, server_config) in &config.mcp_servers {
        if !server_filter
            .map(|value| value == server_id.as_str())
            .unwrap_or(true)
        {
            continue;
        }

        let Some(AuthConfig::OAuth {
            client_id,
            client_secret,
            client_secret_env,
            scope,
            token_store_key,
            ..
        }) = server_config.auth.as_ref()
        else {
            continue;
        };

        let resolved_url = resolve_server_url(server_config)?;
        let key = token_store_key
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(server_id.as_str());
        let entry = store.get(key);
        let has_client_id = client_id
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || entry
                .and_then(|value| value.client_info.as_ref())
                .map(|value| !value.client_id.trim().is_empty())
                .unwrap_or(false);
        let has_client_secret = client_secret
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || client_secret_env
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
            || entry
                .and_then(|value| value.client_info.as_ref())
                .and_then(|value| value.client_secret.as_ref())
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
        let status = derive_auth_status(entry, resolved_url.as_deref());
        let fallback_discovery = discovery_overrides_from_auth(
            server_config
                .auth
                .as_ref()
                .expect("oauth config already matched"),
            resolved_url.as_deref(),
        );
        let discovery = entry
            .and_then(|value| value.discovery.clone())
            .or(fallback_discovery);
        let refresh_token_available = entry
            .and_then(|value| value.tokens.as_ref())
            .and_then(|value| value.refresh_token.as_ref())
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let url_matches = match (resolved_url.as_deref(), entry) {
            (Some(expected), Some(entry)) => entry
                .server_url
                .as_deref()
                .map(|value| value == expected)
                .unwrap_or(true),
            _ => true,
        };

        servers.push(json!({
            "id": server_id,
            "url": resolved_url,
            "tokenStoreKey": key,
            "authStatus": status,
            "discoveryResolved": discovery.is_some(),
            "resourceMetadataUrl": discovery.as_ref().and_then(|value| value.resource_metadata_url.as_deref()),
            "authorizationServer": discovery.as_ref().and_then(|value| value.authorization_server.as_deref()),
            "authorizationEndpoint": discovery.as_ref().and_then(|value| value.authorization_endpoint.as_deref()),
            "tokenEndpoint": discovery.as_ref().and_then(|value| value.token_endpoint.as_deref()),
            "refreshTokenAvailable": refresh_token_available,
            "codeChallengeS256Supported": discovery
                .as_ref()
                .map(|value| value.code_challenge_methods_supported.iter().any(|method| method == "S256"))
                .unwrap_or(false),
            "hasClientId": has_client_id,
            "hasClientSecret": has_client_secret,
            "scope": scope,
            "serverUrlMatches": url_matches,
        }));
    }

    servers.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });

    Ok(json!({
        "ok": true,
        "config": config_path,
        "authStorePath": auth_store_path,
        "servers": servers,
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = telemetry::init()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::ValidateConfig { config } => {
            let cfg = load_config(&config)?;
            let server_count = cfg.mcp_servers.len();
            println!(
                "{{\"ok\":true,\"config\":\"{}\",\"servers\":{}}}",
                config, server_count
            );
        }
        Commands::Daemon { port, config } => {
            let config_data = load_config(&config)?;
            let resolved_port = port.or(config_data.port).unwrap_or(DEFAULT_PORT);
            daemon::run_daemon(resolved_port, config_data).await?;
        }
        Commands::McpServer { config } => {
            let config_data = load_config(&config)?;
            mcp_server::run_mcp_server(config_data).await?;
        }
        Commands::Auth { command } => match command {
            AuthCommands::Discover { config, server } => {
                let config_data = load_config(&config)?;
                let (server_config, auth, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;

                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let entry = ensure_discovery_entry(
                    &server,
                    server_config,
                    auth,
                    &store.remove(&token_store_key).unwrap_or_default(),
                )
                .await?;
                let discovery = entry
                    .discovery
                    .clone()
                    .context("OAuth discovery succeeded but no discovery metadata was persisted")?;
                store.insert(token_store_key.clone(), entry);

                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "discovery": discovery,
                    }))?
                );
            }
            AuthCommands::Start { config, server } => {
                let config_data = load_config(&config)?;
                let (server_config, auth, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;
                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let existing_entry = ensure_discovery_entry(
                    &server,
                    server_config,
                    auth,
                    &store.remove(&token_store_key).unwrap_or_default(),
                )
                .await?;
                let (next_entry, started) =
                    start_oauth_entry(&server, auth, &existing_entry).await?;
                store.insert(token_store_key.clone(), next_entry);

                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "authorizationUrl": started.get("authorizationUrl").cloned(),
                        "redirectUri": started.get("redirectUri").cloned(),
                        "state": started.get("state").cloned(),
                    }))?
                );
            }
            AuthCommands::Login { config, server } => {
                let config_data = load_config(&config)?;
                let (server_config, auth, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;
                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let existing_entry = ensure_discovery_entry(
                    &server,
                    server_config,
                    auth,
                    &store.remove(&token_store_key).unwrap_or_default(),
                )
                .await?;
                let (started_entry, started) =
                    start_oauth_entry(&server, auth, &existing_entry).await?;
                let authorization_url = started
                    .get("authorizationUrl")
                    .and_then(Value::as_str)
                    .context("OAuth login did not produce an authorization URL")?
                    .to_string();
                let redirect_uri = started
                    .get("redirectUri")
                    .and_then(Value::as_str)
                    .context("OAuth login did not produce a redirect URI")?
                    .to_string();
                store.insert(token_store_key.clone(), started_entry.clone());
                save_store(config_data.auth_store_path.as_deref(), &store)?;

                let browser_opened = try_open_browser(&authorization_url);
                if !browser_opened {
                    eprintln!(
                        "Open this URL in your browser to continue OAuth login: {}",
                        authorization_url
                    );
                }

                let callback = receive_oauth_callback(
                    &redirect_uri,
                    std::time::Duration::from_secs(DEFAULT_OAUTH_CALLBACK_TIMEOUT_SECS),
                )
                .await
                .with_context(|| {
                    format!(
                        "OAuth login timed out waiting for callback. Authorization URL: {}",
                        authorization_url
                    )
                })?;
                let exchanged_entry = exchange_oauth_entry(
                    &server,
                    auth,
                    &started_entry,
                    &callback.code,
                    &callback.state,
                )
                .await?;

                store.insert(token_store_key.clone(), exchanged_entry.clone());
                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "browserOpened": browser_opened,
                        "authStatus": derive_auth_status(
                            Some(&exchanged_entry),
                            exchanged_entry.server_url.as_deref(),
                        ),
                    }))?
                );
            }
            AuthCommands::Exchange {
                config,
                server,
                code,
                state,
            } => {
                let config_data = load_config(&config)?;
                let (_, auth, token_store_key) = resolve_oauth_server(&config_data, &server)?;
                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let existing_entry = store.get(&token_store_key).cloned().with_context(|| {
                    format!(
                        "Server '{}' has no stored auth entry. Run discovery/start first",
                        server
                    )
                })?;
                let exchanged_entry =
                    exchange_oauth_entry(&server, auth, &existing_entry, &code, &state).await?;
                store.insert(token_store_key.clone(), exchanged_entry.clone());

                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "authStatus": derive_auth_status(
                            Some(&exchanged_entry),
                            exchanged_entry.server_url.as_deref(),
                        ),
                    }))?
                );
            }
            AuthCommands::Status { config, server } => {
                let config_data = load_config(&config)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&build_auth_status_payload(
                        &config,
                        &config_data,
                        server.as_deref(),
                    )?)?
                );
            }
            AuthCommands::Refresh { config, server } => {
                let config_data = load_config(&config)?;
                let (server_config, auth, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;
                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let entry = store.get(&token_store_key).cloned().with_context(|| {
                    format!(
                        "Server '{}' has no stored auth entry. Run discovery/import first",
                        server
                    )
                })?;
                let mut refreshed_entry = refresh_oauth_entry(&server, auth, &entry).await?;
                if refreshed_entry.server_url.is_none() {
                    refreshed_entry.server_url = resolve_server_url(server_config)?;
                }

                store.insert(token_store_key.clone(), refreshed_entry.clone());
                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "authStatus": derive_auth_status(
                            Some(&refreshed_entry),
                            refreshed_entry.server_url.as_deref(),
                        ),
                        "refreshTokenAvailable": refreshed_entry
                            .tokens
                            .as_ref()
                            .and_then(|value| value.refresh_token.as_ref())
                            .map(|value| !value.trim().is_empty())
                            .unwrap_or(false),
                    }))?
                );
            }
            AuthCommands::Import {
                config,
                server,
                access_token,
                access_token_env,
                refresh_token,
                refresh_token_env,
                expires_at,
                scope,
                client_id,
                client_secret,
                client_secret_env,
            } => {
                let config_data = load_config(&config)?;
                let (server_config, auth, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;
                let AuthConfig::OAuth {
                    client_id: cfg_client_id,
                    client_secret: cfg_client_secret,
                    client_secret_env: cfg_client_secret_env,
                    ..
                } = auth
                else {
                    unreachable!();
                };

                let access_token =
                    resolve_optional_secret(&access_token, &access_token_env, "access token")?
                        .context(
                            "Missing access token. Provide --access-token or --access-token-env",
                        )?;
                let refresh_token =
                    resolve_optional_secret(&refresh_token, &refresh_token_env, "refresh token")?;
                let imported_client_secret =
                    resolve_optional_secret(&client_secret, &client_secret_env, "client secret")?
                        .or_else(|| cfg_client_secret.clone())
                        .or_else(|| {
                            cfg_client_secret_env
                                .as_ref()
                                .and_then(|name| std::env::var(name).ok())
                        });

                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let mut entry = store.remove(&token_store_key).unwrap_or_default();
                let resolved_url = resolve_server_url(server_config)?;
                entry.tokens = Some(OAuthTokens {
                    access_token,
                    refresh_token,
                    expires_at,
                    scope: scope.clone(),
                });
                entry.server_url = resolved_url.clone();

                let resolved_client_id = client_id.or_else(|| cfg_client_id.clone());
                if let Some(client_id) = resolved_client_id {
                    entry.client_info = Some(OAuthClientInfo {
                        client_id,
                        client_secret: imported_client_secret,
                        client_id_issued_at: entry
                            .client_info
                            .as_ref()
                            .and_then(|value| value.client_id_issued_at),
                        client_secret_expires_at: entry
                            .client_info
                            .as_ref()
                            .and_then(|value| value.client_secret_expires_at),
                    });
                }

                store.insert(token_store_key.clone(), entry.clone());
                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "authStatus": derive_auth_status(Some(&entry), resolved_url.as_deref()),
                    }))?
                );
            }
            AuthCommands::Logout { config, server } => {
                let config_data = load_config(&config)?;
                let (server_config, _, token_store_key) =
                    resolve_oauth_server(&config_data, &server)?;
                let (_, mut store) = load_store(config_data.auth_store_path.as_deref())?;
                let removed = store.remove(&token_store_key).is_some();
                let auth_store_path = save_store(config_data.auth_store_path.as_deref(), &store)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "config": config,
                        "authStorePath": auth_store_path,
                        "server": server,
                        "tokenStoreKey": token_store_key,
                        "removed": removed,
                        "authStatus": derive_auth_status(None, server_config.url.as_deref()),
                    }))?
                );
            }
        },
        Commands::ListCapabilities { port, config } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let res = reqwest::get(format!(
                "http://127.0.0.1:{}/v1/capabilities",
                resolved_port
            ))
            .await?;
            println!("{}", res.text().await?);
        }
        Commands::DescribeCapability { port, config, id } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let res = reqwest::get(format!(
                "http://127.0.0.1:{}/v1/capabilities/{}",
                resolved_port, id
            ))
            .await?;
            println!("{}", res.text().await?);
        }
        Commands::CallCapability {
            port,
            config,
            id,
            params,
            request_id,
        } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let parsed_params: Value =
                serde_json::from_str(&params).context("Invalid JSON parameters provided")?;

            let payload = json!({
                "capability_id": id,
                "args": parsed_params,
                "request_id": request_id,
            });

            let client = reqwest::Client::new();
            let res = client
                .post(format!("http://127.0.0.1:{}/v1/tools/call", resolved_port))
                .json(&payload)
                .send()
                .await?;
            println!("{}", res.text().await?);
        }
        Commands::ListResources { port, config } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let res =
                reqwest::get(format!("http://127.0.0.1:{}/v1/resources", resolved_port)).await?;
            println!("{}", res.text().await?);
        }
        Commands::ReadResource {
            port,
            config,
            id,
            request_id,
        } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let payload = json!({
                "resource_id": id,
                "request_id": request_id,
            });

            let client = reqwest::Client::new();
            let res = client
                .post(format!(
                    "http://127.0.0.1:{}/v1/resources/read",
                    resolved_port
                ))
                .json(&payload)
                .send()
                .await?;
            println!("{}", res.text().await?);
        }
        Commands::ListPrompts { port, config } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let res =
                reqwest::get(format!("http://127.0.0.1:{}/v1/prompts", resolved_port)).await?;
            println!("{}", res.text().await?);
        }
        Commands::GetPrompt {
            port,
            config,
            id,
            arguments,
            request_id,
        } => {
            let resolved_port = resolve_client_port(port, &config)?;
            let parsed_arguments: Value =
                serde_json::from_str(&arguments).context("Invalid JSON arguments provided")?;

            let payload = json!({
                "prompt_id": id,
                "arguments": parsed_arguments,
                "request_id": request_id,
            });

            let client = reqwest::Client::new();
            let res = client
                .post(format!("http://127.0.0.1:{}/v1/prompts/get", resolved_port))
                .json(&payload)
                .send()
                .await?;
            println!("{}", res.text().await?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_auth_status_payload, ensure_discovery_entry, exchange_oauth_entry,
        resolve_optional_secret,
    };
    use crate::auth_store::OAuthEntry;
    use crate::config::{AuthConfig, McpConfig, ServerConfig};
    use serde_json::{json, Value};
    use std::{
        collections::HashMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, unique));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    fn oauth_server(url: &str, auth: AuthConfig) -> ServerConfig {
        ServerConfig {
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some(url.to_string()),
            protocol_version: None,
            allow_stateless: None,
            headers: HashMap::new(),
            auth: Some(auth),
        }
    }

    #[test]
    fn build_auth_status_payload_reports_oauth_server_states() {
        let dir = temp_dir("warmplane-auth-status-payload");
        let auth_store_path = dir.join("mcp-auth.json");
        fs::write(
            &auth_store_path,
            serde_json::to_string_pretty(&json!({
                "figma": {
                    "tokens": {
                        "accessToken": "figma-token",
                        "expiresAt": 4102444800_u64
                    },
                    "serverUrl": "https://mcp.figma.com/mcp",
                    "discovery": {
                        "resourceMetadataUrl": "https://mcp.figma.com/.well-known/oauth-protected-resource",
                        "authorizationServer": "https://mcp.figma.com/auth",
                        "authorizationEndpoint": "https://mcp.figma.com/oauth/authorize",
                        "tokenEndpoint": "https://mcp.figma.com/oauth/token",
                        "codeChallengeMethodsSupported": ["S256"]
                    }
                },
                "notion": {
                    "tokens": {
                        "accessToken": "notion-token",
                        "expiresAt": 1_u64
                    },
                    "serverUrl": "https://mcp.notion.com/mcp"
                }
            }))
            .expect("auth store json should serialize"),
        )
        .expect("auth store should be written");

        let mut servers = HashMap::new();
        servers.insert(
            "figma".to_string(),
            oauth_server(
                "https://mcp.figma.com/mcp",
                AuthConfig::OAuth {
                    client_id: Some("figma-client".to_string()),
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
                },
            ),
        );
        servers.insert(
            "notion".to_string(),
            oauth_server(
                "https://mcp.notion.com/mcp",
                AuthConfig::OAuth {
                    client_id: None,
                    client_name: None,
                    client_secret: None,
                    client_secret_env: Some("NOTION_CLIENT_SECRET".to_string()),
                    redirect_uri: None,
                    scope: None,
                    token_store_key: Some("notion".to_string()),
                    authorization_server: None,
                    resource_metadata_url: None,
                    authorization_endpoint: None,
                    token_endpoint: None,
                    registration_endpoint: None,
                    code_challenge_methods_supported: vec![],
                },
            ),
        );
        servers.insert(
            "linear".to_string(),
            oauth_server(
                "https://mcp.linear.app/mcp",
                AuthConfig::OAuth {
                    client_id: None,
                    client_name: None,
                    client_secret: None,
                    client_secret_env: None,
                    redirect_uri: None,
                    scope: None,
                    token_store_key: Some("linear".to_string()),
                    authorization_server: Some("https://api.linear.app".to_string()),
                    resource_metadata_url: None,
                    authorization_endpoint: Some("https://linear.app/oauth/authorize".to_string()),
                    token_endpoint: Some("https://api.linear.app/oauth/token".to_string()),
                    registration_endpoint: None,
                    code_challenge_methods_supported: vec!["S256".to_string()],
                },
            ),
        );

        let config = McpConfig {
            port: None,
            tool_timeout_ms: None,
            auth_store_path: Some(auth_store_path.to_string_lossy().to_string()),
            capability_aliases: HashMap::new(),
            resource_aliases: HashMap::new(),
            prompt_aliases: HashMap::new(),
            policy: None,
            mcp_servers: servers,
        };

        let payload = build_auth_status_payload("test-config.json", &config, None)
            .expect("payload should build");
        let servers = payload
            .get("servers")
            .and_then(Value::as_array)
            .expect("servers array should exist");

        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0]["id"], "figma");
        assert_eq!(servers[0]["authStatus"], "authenticated");
        assert_eq!(servers[0]["discoveryResolved"], true);
        assert_eq!(servers[0]["refreshTokenAvailable"], false);
        assert_eq!(
            servers[0]["authorizationServer"],
            "https://mcp.figma.com/auth"
        );
        assert_eq!(servers[0]["hasClientId"], true);
        assert_eq!(servers[1]["id"], "linear");
        assert_eq!(servers[1]["authStatus"], "not_authenticated");
        assert_eq!(servers[1]["discoveryResolved"], true);
        assert_eq!(
            servers[1]["authorizationEndpoint"],
            "https://linear.app/oauth/authorize"
        );
        assert_eq!(servers[1]["codeChallengeS256Supported"], true);
        assert_eq!(servers[2]["id"], "notion");
        assert_eq!(servers[2]["authStatus"], "expired");
        assert_eq!(servers[2]["hasClientSecret"], true);
        assert_eq!(servers[2]["refreshTokenAvailable"], false);

        fs::remove_dir_all(dir).expect("temp dir cleanup should succeed");
    }

    #[test]
    fn resolve_optional_secret_rejects_dual_sources() {
        let err = resolve_optional_secret(
            &Some("token".to_string()),
            &Some("TOKEN_ENV".to_string()),
            "access token",
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("access token cannot be provided via both direct value and env var"));
    }

    #[tokio::test]
    async fn exchange_oauth_entry_rejects_state_mismatch() {
        let entry = OAuthEntry {
            oauth_state: Some("expected-state".to_string()),
            code_verifier: Some("code-verifier".to_string()),
            discovery: Some(crate::oauth_discovery::OAuthDiscoveryMetadata {
                token_endpoint: Some("https://mcp.example.com/oauth/token".to_string()),
                ..Default::default()
            }),
            client_info: Some(crate::auth_store::OAuthClientInfo {
                client_id: "client-id".to_string(),
                client_secret: None,
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
            server_url: Some("https://mcp.example.com/mcp".to_string()),
            ..Default::default()
        };

        let error = exchange_oauth_entry(
            "example",
            &AuthConfig::OAuth {
                client_id: Some("client-id".to_string()),
                client_name: None,
                client_secret: None,
                client_secret_env: None,
                redirect_uri: None,
                scope: None,
                token_store_key: None,
                authorization_server: None,
                resource_metadata_url: None,
                authorization_endpoint: None,
                token_endpoint: None,
                registration_endpoint: None,
                code_challenge_methods_supported: vec![],
            },
            &entry,
            "auth-code",
            "wrong-state",
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("OAuth state mismatch"));
    }

    #[tokio::test]
    async fn ensure_discovery_entry_uses_auth_overrides_when_standard_discovery_fails() {
        let server_config = oauth_server(
            "http://127.0.0.1:9/mcp",
            AuthConfig::OAuth {
                client_id: None,
                client_name: None,
                client_secret: None,
                client_secret_env: None,
                redirect_uri: None,
                scope: None,
                token_store_key: None,
                authorization_server: Some("https://api.linear.app".to_string()),
                resource_metadata_url: None,
                authorization_endpoint: Some("https://linear.app/oauth/authorize".to_string()),
                token_endpoint: Some("https://api.linear.app/oauth/token".to_string()),
                registration_endpoint: None,
                code_challenge_methods_supported: vec!["S256".to_string()],
            },
        );

        let auth = server_config.auth.as_ref().unwrap();
        let entry = ensure_discovery_entry("linear", &server_config, auth, &OAuthEntry::default())
            .await
            .unwrap();

        assert_eq!(entry.server_url.as_deref(), Some("http://127.0.0.1:9/mcp"));
        assert_eq!(
            entry
                .discovery
                .as_ref()
                .and_then(|value| value.authorization_endpoint.as_deref()),
            Some("https://linear.app/oauth/authorize")
        );
        assert!(entry
            .discovery
            .as_ref()
            .map(|value| value
                .code_challenge_methods_supported
                .iter()
                .any(|method| method == "S256"))
            .unwrap_or(false));
    }
}
