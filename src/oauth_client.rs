use anyhow::{Context, Result};
use base64::Engine as _;
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::auth_store::{OAuthClientInfo, OAuthTokens};

#[derive(Debug, Clone)]
pub struct OAuthRefreshRequest {
    pub token_endpoint: String,
    pub refresh_token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthStartRequest {
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthStartResponse {
    pub authorization_url: String,
    pub code_verifier: String,
    pub state: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct OAuthClientRegistrationRequest {
    pub registration_endpoint: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthCodeExchangeRequest {
    pub token_endpoint: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthRefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthClientRegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    client_id_issued_at: Option<u64>,
    #[serde(default)]
    client_secret_expires_at: Option<u64>,
}

pub async fn refresh_oauth_tokens(input: OAuthRefreshRequest) -> Result<OAuthTokens> {
    let client = Client::builder()
        .build()
        .context("Failed to build OAuth refresh HTTP client")?;
    refresh_oauth_tokens_with_client(&client, input).await
}

pub async fn exchange_authorization_code(input: OAuthCodeExchangeRequest) -> Result<OAuthTokens> {
    let client = Client::builder()
        .build()
        .context("Failed to build OAuth token exchange HTTP client")?;
    exchange_authorization_code_with_client(&client, input).await
}

pub async fn register_oauth_client(
    input: OAuthClientRegistrationRequest,
) -> Result<OAuthClientInfo> {
    let client = Client::builder()
        .build()
        .context("Failed to build OAuth registration HTTP client")?;
    register_oauth_client_with_client(&client, input).await
}

pub fn start_oauth_authorization(input: OAuthStartRequest) -> Result<OAuthStartResponse> {
    if input.client_id.trim().is_empty() {
        anyhow::bail!("OAuth authorization requires a non-empty client_id");
    }

    let code_verifier = random_base64url(32);
    let state = random_base64url(24);
    let code_challenge = code_challenge_s256(&code_verifier);
    let mut authorization_url = Url::parse(&input.authorization_endpoint).with_context(|| {
        format!(
            "Invalid authorization endpoint '{}'",
            input.authorization_endpoint
        )
    })?;

    {
        let mut query = authorization_url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &input.client_id);
        query.append_pair("redirect_uri", &input.redirect_uri);
        query.append_pair("code_challenge", &code_challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("state", &state);
        if let Some(scope) = input.scope.as_ref() {
            if !scope.trim().is_empty() {
                query.append_pair("scope", scope);
            }
        }
        if let Some(resource) = input.resource.as_ref() {
            if !resource.trim().is_empty() {
                query.append_pair("resource", resource);
            }
        }
    }

    Ok(OAuthStartResponse {
        authorization_url: authorization_url.to_string(),
        code_verifier,
        state,
        redirect_uri: input.redirect_uri,
    })
}

async fn refresh_oauth_tokens_with_client(
    client: &Client,
    input: OAuthRefreshRequest,
) -> Result<OAuthTokens> {
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), input.refresh_token.clone()),
    ];
    if let Some(client_id) = input.client_id.clone() {
        form.push(("client_id".to_string(), client_id));
    }
    if let Some(client_secret) = input.client_secret.clone() {
        form.push(("client_secret".to_string(), client_secret));
    }
    if let Some(scope) = input.scope.clone() {
        form.push(("scope".to_string(), scope));
    }

    let response = client
        .post(&input.token_endpoint)
        .form(&form)
        .send()
        .await
        .with_context(|| format!("Refresh request to '{}' failed", input.token_endpoint))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "Refresh request to '{}' returned status {}",
            input.token_endpoint,
            status
        );
    }

    let payload = response
        .json::<OAuthRefreshResponse>()
        .await
        .with_context(|| {
            format!(
                "Refresh response from '{}' was not valid JSON",
                input.token_endpoint
            )
        })?;
    if payload.access_token.trim().is_empty() {
        anyhow::bail!(
            "Refresh response from '{}' did not include a usable access_token",
            input.token_endpoint
        );
    }
    if let Some(token_type) = payload.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            anyhow::bail!(
                "Refresh response from '{}' returned unsupported token_type '{}'",
                input.token_endpoint,
                token_type
            );
        }
    }

    Ok(OAuthTokens {
        access_token: payload.access_token,
        refresh_token: payload.refresh_token.or(Some(input.refresh_token)),
        expires_at: payload.expires_in.map(|value| now_epoch_seconds() + value),
        scope: payload.scope.or(input.scope),
    })
}

async fn register_oauth_client_with_client(
    client: &Client,
    input: OAuthClientRegistrationRequest,
) -> Result<OAuthClientInfo> {
    let response = client
        .post(&input.registration_endpoint)
        .json(&serde_json::json!({
            "client_name": input.client_name,
            "redirect_uris": [input.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": input.scope,
        }))
        .send()
        .await
        .with_context(|| {
            format!(
                "Client registration request to '{}' failed",
                input.registration_endpoint
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "Client registration request to '{}' returned status {}",
            input.registration_endpoint,
            status
        );
    }

    let payload = response
        .json::<OAuthClientRegistrationResponse>()
        .await
        .with_context(|| {
            format!(
                "Client registration response from '{}' was not valid JSON",
                input.registration_endpoint
            )
        })?;
    if payload.client_id.trim().is_empty() {
        anyhow::bail!(
            "Client registration response from '{}' did not include a usable client_id",
            input.registration_endpoint
        );
    }

    Ok(OAuthClientInfo {
        client_id: payload.client_id,
        client_secret: payload.client_secret,
        client_id_issued_at: payload.client_id_issued_at,
        client_secret_expires_at: payload.client_secret_expires_at,
    })
}

async fn exchange_authorization_code_with_client(
    client: &Client,
    input: OAuthCodeExchangeRequest,
) -> Result<OAuthTokens> {
    if input.client_id.trim().is_empty() {
        anyhow::bail!("Authorization code exchange requires a non-empty client_id");
    }
    if input.code_verifier.trim().is_empty() {
        anyhow::bail!("Authorization code exchange requires a non-empty code_verifier");
    }

    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), input.code),
        ("redirect_uri".to_string(), input.redirect_uri),
        ("code_verifier".to_string(), input.code_verifier),
        ("client_id".to_string(), input.client_id),
    ];
    if let Some(client_secret) = input.client_secret {
        form.push(("client_secret".to_string(), client_secret));
    }

    let response = client
        .post(&input.token_endpoint)
        .form(&form)
        .send()
        .await
        .with_context(|| {
            format!(
                "Authorization code exchange request to '{}' failed",
                input.token_endpoint
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "Authorization code exchange request to '{}' returned status {}",
            input.token_endpoint,
            status
        );
    }

    let payload = response
        .json::<OAuthRefreshResponse>()
        .await
        .with_context(|| {
            format!(
                "Authorization code exchange response from '{}' was not valid JSON",
                input.token_endpoint
            )
        })?;
    if payload.access_token.trim().is_empty() {
        anyhow::bail!(
            "Authorization code exchange response from '{}' did not include a usable access_token",
            input.token_endpoint
        );
    }
    if let Some(token_type) = payload.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            anyhow::bail!(
                "Authorization code exchange response from '{}' returned unsupported token_type '{}'",
                input.token_endpoint,
                token_type
            );
        }
    }

    Ok(OAuthTokens {
        access_token: payload.access_token,
        refresh_token: payload.refresh_token,
        expires_at: payload.expires_in.map(|value| now_epoch_seconds() + value),
        scope: payload.scope,
    })
}

fn now_epoch_seconds() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default())
    .as_secs()
}

fn random_base64url(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{
        exchange_authorization_code, refresh_oauth_tokens, register_oauth_client,
        start_oauth_authorization, OAuthClientRegistrationRequest, OAuthCodeExchangeRequest,
        OAuthRefreshRequest, OAuthStartRequest,
    };
    use axum::{routing::post, Form, Json, Router};
    use reqwest::Url;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    #[derive(Debug, Deserialize)]
    struct RefreshForm {
        grant_type: String,
        refresh_token: String,
        client_id: Option<String>,
        client_secret: Option<String>,
        scope: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExchangeForm {
        grant_type: String,
        code: String,
        redirect_uri: String,
        code_verifier: String,
        client_id: String,
        client_secret: Option<String>,
    }

    async fn refresh_handler(Form(form): Form<RefreshForm>) -> Json<serde_json::Value> {
        assert_eq!(form.grant_type, "refresh_token");
        assert_eq!(form.refresh_token, "refresh-token");
        assert_eq!(form.client_id.as_deref(), Some("client-id"));
        assert_eq!(form.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(form.scope.as_deref(), Some("files:read"));

        Json(json!({
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600,
            "scope": "files:read",
            "token_type": "Bearer"
        }))
    }

    async fn registration_handler(
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(payload["client_name"], "warmplane");
        assert_eq!(
            payload["redirect_uris"][0],
            "http://127.0.0.1:8788/callback"
        );
        assert_eq!(payload["grant_types"][0], "authorization_code");
        assert_eq!(payload["grant_types"][1], "refresh_token");

        Json(json!({
            "client_id": "registered-client-id",
            "client_secret": "registered-client-secret",
            "client_id_issued_at": 123,
            "client_secret_expires_at": 456
        }))
    }

    async fn exchange_handler(Form(form): Form<ExchangeForm>) -> Json<serde_json::Value> {
        assert_eq!(form.grant_type, "authorization_code");
        assert_eq!(form.code, "auth-code");
        assert_eq!(form.redirect_uri, "http://127.0.0.1:8788/callback");
        assert_eq!(form.code_verifier, "code-verifier");
        assert_eq!(form.client_id, "client-id");
        assert_eq!(form.client_secret.as_deref(), Some("client-secret"));

        Json(json!({
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 1200,
            "scope": "files:read",
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

    async fn spawn_registration_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/oauth/register", post(registration_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", address)
    }

    async fn spawn_exchange_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/oauth/token", post(exchange_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", address)
    }

    #[tokio::test]
    async fn refresh_oauth_tokens_posts_refresh_grant_and_parses_response() {
        let base_url = spawn_refresh_server().await;
        let tokens = refresh_oauth_tokens(OAuthRefreshRequest {
            token_endpoint: format!("{}/oauth/token", base_url),
            refresh_token: "refresh-token".to_string(),
            client_id: Some("client-id".to_string()),
            client_secret: Some("client-secret".to_string()),
            scope: Some("files:read".to_string()),
        })
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "new-access-token");
        assert_eq!(
            tokens.refresh_token.as_deref(),
            Some("rotated-refresh-token")
        );
        assert_eq!(tokens.scope.as_deref(), Some("files:read"));
        assert!(tokens.expires_at.is_some());
    }

    #[test]
    fn start_oauth_authorization_builds_pkce_url() {
        let started = start_oauth_authorization(OAuthStartRequest {
            authorization_endpoint: "https://mcp.example.com/oauth/authorize".to_string(),
            client_id: "client-id".to_string(),
            redirect_uri: "http://127.0.0.1:8788/callback".to_string(),
            scope: Some("files:read".to_string()),
            resource: Some("https://mcp.example.com/mcp".to_string()),
        })
        .unwrap();

        let url = Url::parse(&started.authorization_url).unwrap();
        let params = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        assert_eq!(params.get("response_type"), Some(&"code".to_string()));
        assert_eq!(params.get("client_id"), Some(&"client-id".to_string()));
        assert_eq!(
            params.get("redirect_uri"),
            Some(&"http://127.0.0.1:8788/callback".to_string())
        );
        assert_eq!(params.get("scope"), Some(&"files:read".to_string()));
        assert_eq!(
            params.get("resource"),
            Some(&"https://mcp.example.com/mcp".to_string())
        );
        assert_eq!(
            params.get("code_challenge_method"),
            Some(&"S256".to_string())
        );
        assert!(!started.code_verifier.is_empty());
        assert!(!started.state.is_empty());
        assert_eq!(started.redirect_uri, "http://127.0.0.1:8788/callback");
        assert!(params.get("code_challenge").is_some());
        assert_eq!(params.get("state"), Some(&started.state));
    }

    #[tokio::test]
    async fn register_oauth_client_posts_registration_request() {
        let base_url = spawn_registration_server().await;
        let client_info = register_oauth_client(OAuthClientRegistrationRequest {
            registration_endpoint: format!("{}/oauth/register", base_url),
            client_name: "warmplane".to_string(),
            redirect_uri: "http://127.0.0.1:8788/callback".to_string(),
            scope: Some("files:read".to_string()),
        })
        .await
        .unwrap();

        assert_eq!(client_info.client_id, "registered-client-id");
        assert_eq!(
            client_info.client_secret.as_deref(),
            Some("registered-client-secret")
        );
        assert_eq!(client_info.client_id_issued_at, Some(123));
        assert_eq!(client_info.client_secret_expires_at, Some(456));
    }

    #[tokio::test]
    async fn exchange_authorization_code_posts_pkce_fields() {
        let base_url = spawn_exchange_server().await;
        let tokens = exchange_authorization_code(OAuthCodeExchangeRequest {
            token_endpoint: format!("{}/oauth/token", base_url),
            code: "auth-code".to_string(),
            redirect_uri: "http://127.0.0.1:8788/callback".to_string(),
            code_verifier: "code-verifier".to_string(),
            client_id: "client-id".to_string(),
            client_secret: Some("client-secret".to_string()),
        })
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "access-token");
        assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-token"));
        assert_eq!(tokens.scope.as_deref(), Some("files:read"));
        assert!(tokens.expires_at.is_some());
    }
}
