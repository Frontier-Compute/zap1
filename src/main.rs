use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use zap1::{anchor, api, config, db, foreman, keys, node, scanner};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("zap1 v{}", env!("CARGO_PKG_VERSION"));

    let config = Arc::new(config::Config::from_env()?);
    tracing::info!("Network: {:?}", config.network);
    tracing::info!("Zebra RPC: {}", config.zebra_rpc_url);
    tracing::info!("Scan from height: {}", config.scan_from_height);

    let ufvk = Arc::new(keys::parse_ufvk(&config.network, &config.ufvk)?);
    tracing::info!("UFVK loaded successfully");

    let test_addr = keys::address_for_index_encoded(&ufvk, &config.network, 0)?;
    tracing::info!("Test address (index 0): {}", test_addr);

    let db = Arc::new(db::Db::open(&config.db_path)?);
    tracing::info!("Database opened: {}", config.db_path);
    db.create_webhooks_table()?;

    // Initialize Foreman client if configured
    let foreman = match (&config.foreman_api_key, &config.foreman_client_id) {
        (Some(key), Some(id)) => {
            tracing::info!("Foreman connected: client {}", id);
            Some(Arc::new(foreman::ForemanClient::new(key, id)))
        }
        _ => {
            tracing::info!("Foreman not configured (FOREMAN_API_KEY / FOREMAN_CLIENT_ID)");
            None
        }
    };

    // Create node backend (Zaino gRPC if ZAINO_GRPC_URL is set, otherwise Zebra RPC)
    let backend: Arc<dyn node::NodeBackend> = Arc::from(node::create_backend(&config));

    // Spawn scanner
    let scanner_config = config.clone();
    let scanner_db = db.clone();
    let scanner_ufvk = ufvk.clone();
    let scanner_backend = backend.clone();
    tokio::spawn(async move {
        scanner::scan_loop(scanner_config, scanner_db, scanner_ufvk, scanner_backend).await;
    });

    // Spawn anchor automation (replaces auto_anchor.sh cron)
    let anchor_config = config.clone();
    let anchor_db = db.clone();
    tokio::spawn(async move {
        anchor::anchor_loop(anchor_config, anchor_db).await;
    });

    // Start API
    let state = api::AppState {
        db,
        ufvk,
        config: config.clone(),
        foreman,
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("API listening on {}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
