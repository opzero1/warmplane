use anyhow::{Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use reqwest::Url;
use std::{collections::HashMap, process::Command, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex, time::timeout};

#[derive(Debug, Clone)]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
}

#[derive(Clone)]
struct CallbackState {
    callback: Arc<Mutex<Option<Result<OAuthCallback, String>>>>,
}

pub async fn receive_oauth_callback(
    redirect_uri: &str,
    timeout_duration: Duration,
) -> Result<OAuthCallback> {
    let parsed = Url::parse(redirect_uri)
        .with_context(|| format!("Invalid redirect URI '{}'", redirect_uri))?;
    if parsed.scheme() != "http" {
        anyhow::bail!(
            "Redirect URI '{}' must use http for loopback handling",
            redirect_uri
        );
    }

    let host = parsed
        .host_str()
        .context("Redirect URI is missing a host")?;
    if host != "127.0.0.1" && host != "localhost" {
        anyhow::bail!(
            "Redirect URI '{}' must use a loopback host (127.0.0.1 or localhost)",
            redirect_uri
        );
    }
    let port = parsed
        .port_or_known_default()
        .context("Redirect URI is missing a port")?;
    let callback_path = parsed.path().to_string();
    let state = CallbackState {
        callback: Arc::new(Mutex::new(None)),
    };

    let app = Router::new()
        .route(&callback_path, get(handle_callback))
        .with_state(state.clone());
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| {
            format!(
                "Failed to bind loopback callback listener on {}",
                redirect_uri
            )
        })?;

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let received = timeout(timeout_duration, async {
        loop {
            if let Some(result) = state.callback.lock().await.take() {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    server_handle.abort();

    match received {
        Ok(Ok(callback)) => Ok(callback),
        Ok(Err(message)) => Err(anyhow::anyhow!(message)),
        Err(_) => Err(anyhow::anyhow!(
            "Timed out waiting for OAuth callback on {}",
            redirect_uri
        )),
    }
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(error) = params.get("error") {
        *state.callback.lock().await =
            Some(Err(format!("OAuth callback returned error '{}'", error)));
        return (
            StatusCode::BAD_REQUEST,
            "OAuth callback failed. Return to the terminal for details.",
        );
    }

    let Some(code) = params.get("code").cloned() else {
        return (
            StatusCode::BAD_REQUEST,
            "OAuth callback missing required 'code' query parameter.",
        );
    };
    let Some(state_value) = params.get("state").cloned() else {
        return (
            StatusCode::BAD_REQUEST,
            "OAuth callback missing required 'state' query parameter.",
        );
    };

    *state.callback.lock().await = Some(Ok(OAuthCallback {
        code,
        state: state_value,
    }));

    (
        StatusCode::OK,
        "OAuth callback captured. You can return to the terminal.",
    )
}

pub fn try_open_browser(url: &str) -> bool {
    let status = if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "start", "", url]).status()
    } else {
        Command::new("xdg-open").arg(url).status()
    };

    status.map(|value| value.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::receive_oauth_callback;
    use std::{net::TcpListener as StdTcpListener, time::Duration};

    fn available_port() -> u16 {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn receive_oauth_callback_captures_code_and_state() {
        let port = available_port();
        let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

        let callback_task = tokio::spawn({
            let redirect_uri = redirect_uri.clone();
            async move { receive_oauth_callback(&redirect_uri, Duration::from_secs(5)).await }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = reqwest::get(format!(
            "http://127.0.0.1:{}/callback?code=auth-code&state=expected-state",
            port
        ))
        .await
        .unwrap();
        assert!(response.status().is_success());

        let callback = callback_task.await.unwrap().unwrap();
        assert_eq!(callback.code, "auth-code");
        assert_eq!(callback.state, "expected-state");
    }

    #[tokio::test]
    async fn receive_oauth_callback_times_out_cleanly() {
        let port = available_port();
        let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

        let error = receive_oauth_callback(&redirect_uri, Duration::from_millis(10))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Timed out waiting for OAuth callback"));
    }
}
