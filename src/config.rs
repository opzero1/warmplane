use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, io::ErrorKind};

pub const DEFAULT_PORT: u16 = 9090;
pub const DEFAULT_CONFIG_PATH: &str = "mcp_servers.json";
pub const DEFAULT_TOOL_TIMEOUT_MS: u64 = 15_000;

#[derive(Deserialize, Clone)]
pub struct McpConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default, rename = "toolTimeoutMs")]
    pub tool_timeout_ms: Option<u64>,
    #[serde(default, rename = "authStorePath")]
    pub auth_store_path: Option<String>,
    #[serde(default, rename = "capabilityAliases")]
    pub capability_aliases: HashMap<String, String>,
    #[serde(default, rename = "resourceAliases")]
    pub resource_aliases: HashMap<String, String>,
    #[serde(default, rename = "promptAliases")]
    pub prompt_aliases: HashMap<String, String>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    #[serde(rename = "mcpServers")]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: Option<String>,
    #[serde(default, rename = "allowStateless")]
    pub allow_stateless: Option<bool>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    #[serde(rename = "bearer")]
    Bearer {
        #[serde(default)]
        token: Option<String>,
        #[serde(default, rename = "tokenEnv")]
        token_env: Option<String>,
    },
    #[serde(rename = "basic")]
    Basic {
        username: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default, rename = "passwordEnv")]
        password_env: Option<String>,
    },
    #[serde(rename = "oauth")]
    OAuth {
        #[serde(default, rename = "clientId")]
        client_id: Option<String>,
        #[serde(default, rename = "clientName")]
        client_name: Option<String>,
        #[serde(default, rename = "clientSecret")]
        client_secret: Option<String>,
        #[serde(default, rename = "clientSecretEnv")]
        client_secret_env: Option<String>,
        #[serde(default, rename = "redirectUri")]
        redirect_uri: Option<String>,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default, rename = "tokenStoreKey")]
        token_store_key: Option<String>,
        #[serde(default, rename = "authorizationServer")]
        authorization_server: Option<String>,
        #[serde(default, rename = "resourceMetadataUrl")]
        resource_metadata_url: Option<String>,
        #[serde(default, rename = "authorizationEndpoint")]
        authorization_endpoint: Option<String>,
        #[serde(default, rename = "tokenEndpoint")]
        token_endpoint: Option<String>,
        #[serde(default, rename = "registrationEndpoint")]
        registration_endpoint: Option<String>,
        #[serde(default, rename = "codeChallengeMethodsSupported")]
        code_challenge_methods_supported: Vec<String>,
    },
}

#[derive(Deserialize, Clone, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default, rename = "redactKeys")]
    pub redact_keys: Vec<String>,
}

pub fn load_config(config_path: &str) -> Result<McpConfig> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;
    let config: McpConfig =
        serde_json::from_str(&config_str).context("Failed to parse config JSON")?;
    validate_config(&config)?;
    Ok(config)
}

pub fn resolve_client_port(port_override: Option<u16>, config_path: &str) -> Result<u16> {
    if let Some(port) = port_override {
        return Ok(port);
    }

    match fs::read_to_string(config_path) {
        Ok(config_str) => {
            let config: McpConfig =
                serde_json::from_str(&config_str).context("Failed to parse config JSON")?;
            validate_config(&config)?;
            Ok(config.port.unwrap_or(DEFAULT_PORT))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(DEFAULT_PORT),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to read config file: {}", config_path))
        }
    }
}

fn validate_config(config: &McpConfig) -> Result<()> {
    for (server_id, server) in &config.mcp_servers {
        let has_command = server
            .command
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_url = server
            .url
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        match (has_command, has_url) {
            (true, true) => {
                anyhow::bail!(
                    "Server '{}' is ambiguous: configure exactly one of 'command' or 'url'",
                    server_id
                );
            }
            (false, false) => {
                anyhow::bail!(
                    "Server '{}' is invalid: configure exactly one of 'command' or 'url'",
                    server_id
                );
            }
            _ => {}
        }

        if has_command {
            if server.auth.is_some() {
                anyhow::bail!(
                    "Server '{}' uses stdio ('command') and cannot define 'auth'",
                    server_id
                );
            }
            if !server.headers.is_empty() {
                anyhow::bail!(
                    "Server '{}' uses stdio ('command') and cannot define HTTP 'headers'",
                    server_id
                );
            }
            if server.protocol_version.is_some() {
                anyhow::bail!(
                    "Server '{}' uses stdio ('command') and cannot define 'protocolVersion'",
                    server_id
                );
            }
            if server.allow_stateless.is_some() {
                anyhow::bail!(
                    "Server '{}' uses stdio ('command') and cannot define 'allowStateless'",
                    server_id
                );
            }
        }

        if let Some(auth) = &server.auth {
            match auth {
                AuthConfig::Bearer { token, token_env } => {
                    let has_token = token.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
                    let has_token_env = token_env
                        .as_ref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    if has_token == has_token_env {
                        anyhow::bail!(
                            "Server '{}' bearer auth requires exactly one of 'token' or 'tokenEnv'",
                            server_id
                        );
                    }
                }
                AuthConfig::Basic {
                    username,
                    password,
                    password_env,
                } => {
                    if username.trim().is_empty() {
                        anyhow::bail!(
                            "Server '{}' basic auth requires non-empty 'username'",
                            server_id
                        );
                    }
                    let has_password = password.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
                    let has_password_env = password_env
                        .as_ref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    if has_password == has_password_env {
                        anyhow::bail!(
                            "Server '{}' basic auth requires exactly one of 'password' or 'passwordEnv'",
                            server_id
                        );
                    }
                }
                AuthConfig::OAuth {
                    client_id,
                    client_name,
                    client_secret,
                    client_secret_env,
                    redirect_uri,
                    scope,
                    token_store_key,
                    authorization_server,
                    resource_metadata_url,
                    authorization_endpoint,
                    token_endpoint,
                    registration_endpoint,
                    code_challenge_methods_supported,
                } => {
                    if client_id
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty 'clientId' when provided",
                            server_id
                        );
                    }

                    if client_name
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty 'clientName' when provided",
                            server_id
                        );
                    }

                    let has_client_secret = client_secret
                        .as_ref()
                        .map(|value| !value.is_empty())
                        .unwrap_or(false);
                    let has_client_secret_env = client_secret_env
                        .as_ref()
                        .map(|value| !value.trim().is_empty())
                        .unwrap_or(false);
                    if has_client_secret && has_client_secret_env {
                        anyhow::bail!(
                            "Server '{}' oauth auth cannot define both 'clientSecret' and 'clientSecretEnv'",
                            server_id
                        );
                    }

                    if redirect_uri
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty 'redirectUri' when provided",
                            server_id
                        );
                    }

                    if scope
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty 'scope' when provided",
                            server_id
                        );
                    }

                    if token_store_key
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty 'tokenStoreKey' when provided",
                            server_id
                        );
                    }

                    for (field_name, value) in [
                        ("authorizationServer", authorization_server.as_ref()),
                        ("resourceMetadataUrl", resource_metadata_url.as_ref()),
                        ("authorizationEndpoint", authorization_endpoint.as_ref()),
                        ("tokenEndpoint", token_endpoint.as_ref()),
                        ("registrationEndpoint", registration_endpoint.as_ref()),
                    ] {
                        if value.map(|value| value.trim().is_empty()).unwrap_or(false) {
                            anyhow::bail!(
                                "Server '{}' oauth auth requires non-empty '{}' when provided",
                                server_id,
                                field_name
                            );
                        }
                    }

                    if code_challenge_methods_supported
                        .iter()
                        .any(|value| value.trim().is_empty())
                    {
                        anyhow::bail!(
                            "Server '{}' oauth auth requires non-empty values in 'codeChallengeMethodsSupported'",
                            server_id
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_config, AuthConfig, McpConfig, ServerConfig};
    use std::collections::HashMap;

    fn empty_server() -> ServerConfig {
        ServerConfig {
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: None,
            protocol_version: None,
            allow_stateless: None,
            headers: HashMap::new(),
            auth: None,
        }
    }

    fn config_with_server(server: ServerConfig) -> McpConfig {
        let mut mcp_servers = HashMap::new();
        mcp_servers.insert("s1".to_string(), server);
        McpConfig {
            port: None,
            tool_timeout_ms: None,
            auth_store_path: None,
            capability_aliases: HashMap::new(),
            resource_aliases: HashMap::new(),
            prompt_aliases: HashMap::new(),
            policy: None,
            mcp_servers,
        }
    }

    #[test]
    fn server_requires_exactly_one_transport_selector() {
        let server = empty_server();
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err
            .to_string()
            .contains("configure exactly one of 'command' or 'url'"));
    }

    #[test]
    fn server_rejects_both_transport_selectors() {
        let mut server = empty_server();
        server.command = Some("node".to_string());
        server.url = Some("https://example.com/mcp".to_string());
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err.to_string().contains("is ambiguous"));
    }

    #[test]
    fn stdio_server_rejects_http_only_fields() {
        let mut server = empty_server();
        server.command = Some("node".to_string());
        server.headers.insert("X-Test".to_string(), "1".to_string());
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err.to_string().contains("cannot define HTTP 'headers'"));
    }

    #[test]
    fn bearer_auth_requires_one_credential_source() {
        let mut server = empty_server();
        server.url = Some("https://example.com/mcp".to_string());
        server.auth = Some(AuthConfig::Bearer {
            token: None,
            token_env: None,
        });
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires exactly one of 'token' or 'tokenEnv'"));
    }

    #[test]
    fn basic_auth_requires_one_password_source() {
        let mut server = empty_server();
        server.url = Some("https://example.com/mcp".to_string());
        server.auth = Some(AuthConfig::Basic {
            username: "alice".to_string(),
            password: Some("pw".to_string()),
            password_env: Some("PW_ENV".to_string()),
        });
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires exactly one of 'password' or 'passwordEnv'"));
    }

    #[test]
    fn valid_http_server_passes_validation() {
        let mut server = empty_server();
        server.url = Some("https://example.com/mcp".to_string());
        server.protocol_version = Some("2025-11-25".to_string());
        server.auth = Some(AuthConfig::Bearer {
            token: None,
            token_env: Some("MCP_TOKEN".to_string()),
        });
        assert!(validate_config(&config_with_server(server)).is_ok());
    }

    #[test]
    fn oauth_server_passes_validation_without_client_id() {
        let mut server = empty_server();
        server.url = Some("https://example.com/mcp".to_string());
        server.auth = Some(AuthConfig::OAuth {
            client_id: None,
            client_name: None,
            client_secret: None,
            client_secret_env: None,
            redirect_uri: None,
            scope: Some("files:read".to_string()),
            token_store_key: None,
            authorization_server: None,
            resource_metadata_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            code_challenge_methods_supported: vec![],
        });
        assert!(validate_config(&config_with_server(server)).is_ok());
    }

    #[test]
    fn oauth_server_rejects_duplicate_client_secret_sources() {
        let mut server = empty_server();
        server.url = Some("https://example.com/mcp".to_string());
        server.auth = Some(AuthConfig::OAuth {
            client_id: Some("client-id".to_string()),
            client_name: None,
            client_secret: Some("secret".to_string()),
            client_secret_env: Some("CLIENT_SECRET".to_string()),
            redirect_uri: None,
            scope: None,
            token_store_key: None,
            authorization_server: None,
            resource_metadata_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            code_challenge_methods_supported: vec![],
        });
        let err = validate_config(&config_with_server(server)).unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot define both 'clientSecret' and 'clientSecretEnv'"));
    }

    #[test]
    fn oauth_json_tag_accepts_oauth_literal() {
        let parsed: AuthConfig = serde_json::from_str(
            r#"{
                "type": "oauth",
                "tokenStoreKey": "figma"
            }"#,
        )
        .expect("oauth auth tag should parse");

        assert!(matches!(
            parsed,
            AuthConfig::OAuth {
                token_store_key: Some(_),
                ..
            }
        ));
    }
}
