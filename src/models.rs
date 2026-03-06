use clap::{Parser, Subcommand};

use crate::config::DEFAULT_CONFIG_PATH;

#[derive(Parser)]
#[command(
    name = "warmplane",
    about = "The local control plane that keeps MCP sessions warm"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Validate config file and exit (no daemon startup)
    ValidateConfig {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Boot the background daemon
    Daemon {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Run as an MCP stdio server exposing the lightweight facade
    McpServer {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Manage upstream OAuth auth-store state for Warmplane-managed servers
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// List compact capabilities from the v1 facade API
    ListCapabilities {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Describe one capability with full on-demand schema from the v1 facade API
    DescribeCapability {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        id: String,
    },
    /// Call one capability through the v1 facade API
    CallCapability {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        id: String,
        #[arg(short, long, default_value = "{}")]
        params: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// List compact resources from the v1 facade API
    ListResources {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Read one resource through the v1 facade API
    ReadResource {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// List compact prompts from the v1 facade API
    ListPrompts {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
    },
    /// Get one prompt through the v1 facade API
    GetPrompt {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        id: String,
        #[arg(short, long, default_value = "{}")]
        arguments: String,
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Discover upstream OAuth metadata without importing tokens yet
    Discover {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
    },
    /// Build an OAuth authorization URL and persist PKCE/state for a server
    Start {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
    },
    /// Run the integrated browser + loopback callback login flow for a server
    Login {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
    },
    /// Exchange an authorization code using stored PKCE/state for a server
    Exchange {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        state: String,
    },
    /// Inspect Warmplane-managed upstream auth readiness
    Status {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: Option<String>,
    },
    /// Refresh stored upstream OAuth credentials using the refresh token grant
    Refresh {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
    },
    /// Import upstream OAuth credentials into the shared auth store
    Import {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
        #[arg(long)]
        access_token: Option<String>,
        #[arg(long)]
        access_token_env: Option<String>,
        #[arg(long)]
        refresh_token: Option<String>,
        #[arg(long)]
        refresh_token_env: Option<String>,
        #[arg(long)]
        expires_at: Option<u64>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        client_id: Option<String>,
        #[arg(long)]
        client_secret: Option<String>,
        #[arg(long)]
        client_secret_env: Option<String>,
    },
    /// Remove upstream OAuth credentials from the shared auth store
    Logout {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,
        server: String,
    },
}
