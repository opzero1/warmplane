use anyhow::{Context, Result};
use reqwest::header::HeaderMap;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthDiscoveryMetadata {
    #[serde(default, rename = "resourceMetadataUrl")]
    pub resource_metadata_url: Option<String>,
    #[serde(default, rename = "authorizationServer")]
    pub authorization_server: Option<String>,
    #[serde(default, rename = "authorizationMetadataUrl")]
    pub authorization_metadata_url: Option<String>,
    #[serde(default, rename = "authorizationEndpoint")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, rename = "tokenEndpoint")]
    pub token_endpoint: Option<String>,
    #[serde(default, rename = "registrationEndpoint")]
    pub registration_endpoint: Option<String>,
    #[serde(default, rename = "scopesSupported")]
    pub scopes_supported: Vec<String>,
    #[serde(default, rename = "codeChallengeMethodsSupported")]
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ProtectedResourceMetadata {
    #[serde(default, rename = "authorization_servers")]
    authorization_servers: Vec<String>,
    #[serde(default, rename = "scopes_supported")]
    scopes_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationServerMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default, rename = "scopes_supported")]
    scopes_supported: Vec<String>,
    #[serde(default, rename = "code_challenge_methods_supported")]
    code_challenge_methods_supported: Vec<String>,
}

pub async fn discover_oauth_metadata(resource_url: &str) -> Result<OAuthDiscoveryMetadata> {
    let client = Client::builder()
        .build()
        .context("Failed to build discovery HTTP client")?;
    discover_oauth_metadata_with_client(&client, resource_url).await
}

async fn discover_oauth_metadata_with_client(
    client: &Client,
    resource_url: &str,
) -> Result<OAuthDiscoveryMetadata> {
    let resource_url = Url::parse(resource_url)
        .with_context(|| format!("Invalid OAuth resource URL '{}'", resource_url))?;
    let resource_metadata_url =
        match resource_metadata_from_challenge(client, &resource_url).await? {
            Some(url) => url,
            None => default_resource_metadata_url(&resource_url)?,
        };

    let protected_resource =
        fetch_json::<ProtectedResourceMetadata>(client, &resource_metadata_url)
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch protected resource metadata from '{}'",
                    resource_metadata_url
                )
            })?;
    let authorization_server = protected_resource
        .authorization_servers
        .first()
        .cloned()
        .context("Protected resource metadata did not advertise any authorization servers")?;

    let mut last_error: Option<anyhow::Error> = None;
    for candidate in authorization_server_metadata_candidates(&authorization_server)? {
        match fetch_json::<AuthorizationServerMetadata>(client, &candidate).await {
            Ok(metadata) => {
                validate_authorization_server_metadata(&candidate, &metadata)?;
                let scopes_supported = if metadata.scopes_supported.is_empty() {
                    protected_resource.scopes_supported.clone()
                } else {
                    metadata.scopes_supported.clone()
                };

                return Ok(OAuthDiscoveryMetadata {
                    resource_metadata_url: Some(resource_metadata_url),
                    authorization_server: Some(authorization_server),
                    authorization_metadata_url: Some(candidate),
                    authorization_endpoint: Some(metadata.authorization_endpoint),
                    token_endpoint: Some(metadata.token_endpoint),
                    registration_endpoint: metadata.registration_endpoint,
                    scopes_supported,
                    code_challenge_methods_supported: metadata.code_challenge_methods_supported,
                });
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!("OAuth discovery could not resolve authorization server metadata")
    }))
}

async fn resource_metadata_from_challenge(
    client: &Client,
    resource_url: &Url,
) -> Result<Option<String>> {
    let response = client
        .get(resource_url.clone())
        .send()
        .await
        .with_context(|| format!("Failed to probe resource URL '{}'", resource_url))?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(None);
    }

    Ok(resource_metadata_from_headers(response.headers()))
}

fn resource_metadata_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(parse_resource_metadata_from_www_authenticate)
}

fn parse_resource_metadata_from_www_authenticate(header: &str) -> Option<String> {
    let (_, rest) = header.split_once("resource_metadata=")?;
    let rest = rest.trim();
    if let Some(stripped) = rest.strip_prefix('"') {
        let (value, _) = stripped.split_once('"')?;
        return Some(value.to_string());
    }

    let value = rest.split(',').next()?.trim();
    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

fn default_resource_metadata_url(resource_url: &Url) -> Result<String> {
    let mut url = resource_url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("/.well-known/oauth-protected-resource");
    Ok(url.to_string())
}

fn authorization_server_metadata_candidates(authorization_server: &str) -> Result<Vec<String>> {
    let url = Url::parse(authorization_server).with_context(|| {
        format!(
            "Invalid authorization server URL '{}' in protected resource metadata",
            authorization_server
        )
    })?;
    let origin = origin_string(&url)?;
    let path = url.path().trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Ok(vec![
            format!("{}/.well-known/oauth-authorization-server", origin),
            format!("{}/.well-known/openid-configuration", origin),
        ]);
    }

    Ok(vec![
        format!("{}/.well-known/oauth-authorization-server{}", origin, path),
        format!("{}/.well-known/openid-configuration{}", origin, path),
        format!("{}{}/.well-known/openid-configuration", origin, path),
    ])
}

fn origin_string(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .context("Authorization server URL is missing a host")?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

async fn fetch_json<T>(client: &Client, url: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Request to '{}' failed", url))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("Request to '{}' returned status {}", url, status);
    }

    response
        .json::<T>()
        .await
        .with_context(|| format!("Response from '{}' was not valid JSON", url))
}

fn validate_authorization_server_metadata(
    metadata_url: &str,
    metadata: &AuthorizationServerMetadata,
) -> Result<()> {
    if metadata.authorization_endpoint.trim().is_empty() {
        anyhow::bail!(
            "Authorization server metadata '{}' is missing authorization_endpoint",
            metadata_url
        );
    }
    if metadata.token_endpoint.trim().is_empty() {
        anyhow::bail!(
            "Authorization server metadata '{}' is missing token_endpoint",
            metadata_url
        );
    }
    if !metadata
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        anyhow::bail!(
            "Authorization server metadata '{}' does not advertise PKCE S256 support",
            metadata_url
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        authorization_server_metadata_candidates, discover_oauth_metadata,
        parse_resource_metadata_from_www_authenticate,
    };
    use axum::{
        extract::State,
        http::{header::WWW_AUTHENTICATE, StatusCode},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn parses_resource_metadata_from_www_authenticate_header() {
        let parsed = parse_resource_metadata_from_www_authenticate(
            "Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource\"",
        );
        assert_eq!(
            parsed.as_deref(),
            Some("https://example.com/.well-known/oauth-protected-resource")
        );
    }

    #[test]
    fn builds_path_aware_authorization_server_metadata_candidates() {
        let candidates =
            authorization_server_metadata_candidates("https://example.com/tenant1").unwrap();
        assert_eq!(
            candidates,
            vec![
                "https://example.com/.well-known/oauth-authorization-server/tenant1",
                "https://example.com/.well-known/openid-configuration/tenant1",
                "https://example.com/tenant1/.well-known/openid-configuration",
            ]
        );
    }

    #[derive(Clone)]
    struct AppState {
        base_url: Arc<String>,
        challenge_mode: bool,
    }

    async fn handle_probe(State(state): State<AppState>) -> impl IntoResponse {
        if state.challenge_mode {
            let headers = [(
                WWW_AUTHENTICATE,
                format!(
                    "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                    state.base_url
                ),
            )];
            return (StatusCode::UNAUTHORIZED, headers, String::new()).into_response();
        }

        (StatusCode::OK, String::from("ok")).into_response()
    }

    async fn handle_resource_metadata(State(state): State<AppState>) -> impl IntoResponse {
        Json(json!({
            "authorization_servers": [format!("{}/auth", state.base_url)],
            "scopes_supported": ["files:read"]
        }))
    }

    async fn handle_auth_server_metadata(State(state): State<AppState>) -> impl IntoResponse {
        Json(json!({
            "authorization_endpoint": format!("{}/oauth/authorize", state.base_url),
            "token_endpoint": format!("{}/oauth/token", state.base_url),
            "registration_endpoint": format!("{}/oauth/register", state.base_url),
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["files:read"]
        }))
    }

    async fn handle_auth_server_metadata_without_s256(
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        Json(json!({
            "authorization_endpoint": format!("{}/oauth/authorize", state.base_url),
            "token_endpoint": format!("{}/oauth/token", state.base_url),
            "code_challenge_methods_supported": ["plain"],
            "scopes_supported": ["files:read"]
        }))
    }

    async fn spawn_test_server(challenge_mode: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{}", address);
        let state = AppState {
            base_url: Arc::new(base_url.clone()),
            challenge_mode,
        };
        let app = Router::new()
            .route("/mcp", get(handle_probe))
            .route(
                "/.well-known/oauth-protected-resource",
                get(handle_resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server/auth",
                get(handle_auth_server_metadata),
            )
            .with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        base_url
    }

    async fn spawn_non_compliant_test_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{}", address);
        let state = AppState {
            base_url: Arc::new(base_url.clone()),
            challenge_mode: true,
        };
        let app = Router::new()
            .route("/mcp", get(handle_probe))
            .route(
                "/.well-known/oauth-protected-resource",
                get(handle_resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server/auth",
                get(handle_auth_server_metadata_without_s256),
            )
            .with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        base_url
    }

    #[tokio::test]
    async fn discovers_oauth_metadata_from_challenge_chain() {
        let base_url = spawn_test_server(true).await;
        let discovery = discover_oauth_metadata(&format!("{}/mcp", base_url))
            .await
            .unwrap();
        let expected_resource_metadata =
            format!("{}/.well-known/oauth-protected-resource", base_url);
        let expected_authorization_server = format!("{}/auth", base_url);
        let expected_authorization_endpoint = format!("{}/oauth/authorize", base_url);

        assert_eq!(
            discovery.resource_metadata_url.as_deref(),
            Some(expected_resource_metadata.as_str())
        );
        assert_eq!(
            discovery.authorization_server.as_deref(),
            Some(expected_authorization_server.as_str())
        );
        assert_eq!(
            discovery.authorization_endpoint.as_deref(),
            Some(expected_authorization_endpoint.as_str())
        );
        assert!(discovery
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256"));
    }

    #[tokio::test]
    async fn falls_back_to_default_protected_resource_metadata_url() {
        let base_url = spawn_test_server(false).await;
        let discovery = discover_oauth_metadata(&format!("{}/mcp", base_url))
            .await
            .unwrap();
        let expected_resource_metadata =
            format!("{}/.well-known/oauth-protected-resource", base_url);

        assert_eq!(
            discovery.resource_metadata_url.as_deref(),
            Some(expected_resource_metadata.as_str())
        );
    }

    #[tokio::test]
    async fn rejects_authorization_server_metadata_without_s256_support() {
        let base_url = spawn_non_compliant_test_server().await;
        let error = discover_oauth_metadata(&format!("{}/mcp", base_url))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not advertise PKCE S256 support"));
    }
}
