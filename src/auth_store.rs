use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::oauth_discovery::OAuthDiscoveryMetadata;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthAuthStatus {
    Authenticated,
    Expired,
    NotAuthenticated,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthTokens {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(default, rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(
        default,
        rename = "expiresAt",
        deserialize_with = "deserialize_optional_epoch_seconds"
    )]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthClientInfo {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(default, rename = "clientSecret")]
    pub client_secret: Option<String>,
    #[serde(default, rename = "clientIdIssuedAt")]
    pub client_id_issued_at: Option<u64>,
    #[serde(default, rename = "clientSecretExpiresAt")]
    pub client_secret_expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthEntry {
    #[serde(default)]
    pub tokens: Option<OAuthTokens>,
    #[serde(default, rename = "clientInfo")]
    pub client_info: Option<OAuthClientInfo>,
    #[serde(default, rename = "codeVerifier")]
    pub code_verifier: Option<String>,
    #[serde(default, rename = "oauthState")]
    pub oauth_state: Option<String>,
    #[serde(default, rename = "serverUrl")]
    pub server_url: Option<String>,
    #[serde(default)]
    pub discovery: Option<OAuthDiscoveryMetadata>,
}

pub type OAuthAuthStore = HashMap<String, OAuthEntry>;

fn deserialize_optional_epoch_seconds<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                return Ok(Some(value));
            }
            if let Some(value) = number.as_i64() {
                if value < 0 {
                    return Err(serde::de::Error::custom(
                        "expiresAt must be a non-negative epoch value",
                    ));
                }
                return Ok(Some(value as u64));
            }
            if let Some(value) = number.as_f64() {
                if !value.is_finite() || value < 0.0 {
                    return Err(serde::de::Error::custom(
                        "expiresAt must be a finite non-negative epoch value",
                    ));
                }
                return Ok(Some(value.floor() as u64));
            }

            Err(serde::de::Error::custom(
                "expiresAt must be a numeric epoch value",
            ))
        }
        serde_json::Value::Null => Ok(None),
        _ => Err(serde::de::Error::custom(
            "expiresAt must be a numeric epoch value",
        )),
    }
}

fn resolve_home_dir() -> Result<PathBuf> {
    if let Ok(home) = env::var("HOME") {
        if !home.trim().is_empty() {
            return Ok(PathBuf::from(home));
        }
    }

    if let Ok(profile) = env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return Ok(PathBuf::from(profile));
        }
    }

    let drive = env::var("HOMEDRIVE").unwrap_or_default();
    let path = env::var("HOMEPATH").unwrap_or_default();
    if !drive.trim().is_empty() && !path.trim().is_empty() {
        return Ok(PathBuf::from(format!("{}{}", drive, path)));
    }

    anyhow::bail!("Could not resolve home directory for auth store path");
}

fn default_store_paths() -> Result<Vec<PathBuf>> {
    let home = resolve_home_dir()?;
    Ok(vec![
        home.join(".local")
            .join("share")
            .join("opencode")
            .join("mcp-auth.json"),
        home.join(".config").join("opencode").join("mcp-auth.json"),
    ])
}

pub fn resolve_store_path(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(PathBuf::from(path));
    }

    let paths = default_store_paths()?;
    for path in &paths {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    Ok(paths
        .into_iter()
        .next()
        .context("Failed to resolve default auth store path")?)
}

pub fn load_store(explicit: Option<&str>) -> Result<(PathBuf, OAuthAuthStore)> {
    let path = resolve_store_path(explicit)?;
    match fs::read_to_string(&path) {
        Ok(text) => {
            let store = serde_json::from_str::<OAuthAuthStore>(&text)
                .with_context(|| format!("Failed to parse auth store JSON: {}", path.display()))?;
            Ok((path, store))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok((path, HashMap::new())),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to read auth store file: {}", path.display()))
        }
    }
}

pub fn save_store(explicit: Option<&str>, store: &OAuthAuthStore) -> Result<PathBuf> {
    let path = resolve_store_path(explicit)?;
    ensure_parent_dir(&path)?;

    let text = serde_json::to_string_pretty(store).context("Failed to encode auth store JSON")?;
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    fs::write(&tmp_path, format!("{}\n", text)).with_context(|| {
        format!(
            "Failed to write auth store temp file: {}",
            tmp_path.display()
        )
    })?;
    fs::rename(&tmp_path, &path)
        .with_context(|| format!("Failed to finalize auth store write: {}", path.display()))?;
    Ok(path)
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "Failed to create auth store directory: {}",
            parent.display()
        )
    })
}

pub fn derive_auth_status(entry: Option<&OAuthEntry>, server_url: Option<&str>) -> OAuthAuthStatus {
    let Some(entry) = entry else {
        return OAuthAuthStatus::NotAuthenticated;
    };

    if let Some(expected_url) = server_url {
        if let Some(stored_url) = entry.server_url.as_deref() {
            if stored_url != expected_url {
                return OAuthAuthStatus::NotAuthenticated;
            }
        }
    }

    let Some(tokens) = entry.tokens.as_ref() else {
        return OAuthAuthStatus::NotAuthenticated;
    };

    if tokens.access_token.trim().is_empty() {
        return OAuthAuthStatus::NotAuthenticated;
    }

    if let Some(expires_at) = tokens.expires_at {
        if expires_at <= now_epoch_seconds() {
            return OAuthAuthStatus::Expired;
        }
    }

    OAuthAuthStatus::Authenticated
}

fn now_epoch_seconds() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default())
    .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        derive_auth_status, load_store, save_store, OAuthAuthStatus, OAuthEntry, OAuthTokens,
    };
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

    #[test]
    fn derive_auth_status_reports_missing_tokens() {
        assert!(matches!(
            derive_auth_status(Some(&OAuthEntry::default()), None),
            OAuthAuthStatus::NotAuthenticated
        ));
    }

    #[test]
    fn derive_auth_status_reports_expired_tokens() {
        let entry = OAuthEntry {
            tokens: Some(OAuthTokens {
                access_token: "token".to_string(),
                refresh_token: None,
                expires_at: Some(1),
                scope: None,
            }),
            ..OAuthEntry::default()
        };

        assert!(matches!(
            derive_auth_status(Some(&entry), None),
            OAuthAuthStatus::Expired
        ));
    }

    #[test]
    fn derive_auth_status_rejects_server_url_mismatch() {
        let entry = OAuthEntry {
            tokens: Some(OAuthTokens {
                access_token: "token".to_string(),
                refresh_token: None,
                expires_at: None,
                scope: None,
            }),
            server_url: Some("https://wrong.example.com/mcp".to_string()),
            ..OAuthEntry::default()
        };

        assert!(matches!(
            derive_auth_status(Some(&entry), Some("https://right.example.com/mcp")),
            OAuthAuthStatus::NotAuthenticated
        ));
    }

    #[test]
    fn load_store_returns_empty_store_for_missing_explicit_path() {
        let dir = temp_dir("warmplane-auth-store-missing");
        let path = dir.join("mcp-auth.json");

        let (resolved_path, store) =
            load_store(Some(path.to_str().expect("valid path"))).expect("load should succeed");

        assert_eq!(resolved_path, path);
        assert!(store.is_empty());

        fs::remove_dir_all(dir).expect("temp dir cleanup should succeed");
    }

    #[test]
    fn save_store_round_trips_explicit_path() {
        let dir = temp_dir("warmplane-auth-store-roundtrip");
        let path = dir.join("mcp-auth.json");
        let mut store = HashMap::new();
        store.insert(
            "figma".to_string(),
            OAuthEntry {
                tokens: Some(OAuthTokens {
                    access_token: "token".to_string(),
                    refresh_token: Some("refresh".to_string()),
                    expires_at: Some(4_102_444_800),
                    scope: Some("files:read".to_string()),
                }),
                server_url: Some("https://mcp.figma.com/mcp".to_string()),
                ..OAuthEntry::default()
            },
        );

        let saved_path = save_store(Some(path.to_str().expect("valid path")), &store)
            .expect("save should succeed");
        let (loaded_path, loaded_store) =
            load_store(Some(path.to_str().expect("valid path"))).expect("load should succeed");

        assert_eq!(saved_path, path);
        assert_eq!(loaded_path, path);
        assert_eq!(loaded_store.len(), 1);
        assert_eq!(
            loaded_store
                .get("figma")
                .and_then(|entry| entry.tokens.as_ref())
                .map(|tokens| tokens.access_token.as_str()),
            Some("token")
        );
        assert_eq!(
            loaded_store
                .get("figma")
                .and_then(|entry| entry.server_url.as_deref()),
            Some("https://mcp.figma.com/mcp")
        );

        fs::remove_dir_all(dir).expect("temp dir cleanup should succeed");
    }

    #[test]
    fn load_store_accepts_fractional_expires_at_values() {
        let dir = temp_dir("warmplane-auth-store-fractional-expiry");
        let path = dir.join("mcp-auth.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "figma": {
                    "tokens": {
                        "accessToken": "token",
                        "expiresAt": 1776355122.044
                    }
                }
            }))
            .expect("auth store json should serialize"),
        )
        .expect("auth store should be written");

        let (_, store) =
            load_store(Some(path.to_str().expect("valid path"))).expect("load should succeed");

        assert_eq!(
            store
                .get("figma")
                .and_then(|entry| entry.tokens.as_ref())
                .and_then(|tokens| tokens.expires_at),
            Some(1_776_355_122)
        );

        fs::remove_dir_all(dir).expect("temp dir cleanup should succeed");
    }
}
