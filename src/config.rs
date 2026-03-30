use anyhow::{Context, Result};
use zcash_protocol::consensus::Network;

#[derive(Debug, Clone)]
pub struct Config {
    pub ufvk: String,
    pub network: Network,
    pub zebra_rpc_url: String,
    pub zaino_grpc_url: Option<String>,
    pub listen_addr: String,
    pub db_path: String,
    pub scan_from_height: u32,
    pub webhook_url: Option<String>,
    pub signal_number: Option<String>,
    pub signal_api_url: Option<String>,
    pub foreman_api_key: Option<String>,
    pub foreman_client_id: Option<String>,
    pub api_key: Option<String>,
    // Anchor automation
    pub anchor_enabled: bool,
    pub anchor_zingo_cli: Option<String>,
    pub anchor_chain: String,
    pub anchor_server: Option<String>,
    pub anchor_data_dir: Option<String>,
    pub anchor_to_address: Option<String>,
    pub anchor_amount_zat: u64,
    pub anchor_threshold: u32,
    pub anchor_interval_hours: u64,
    pub anchor_webhook_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let ufvk = std::env::var("UFVK").context("UFVK env var required")?;

        let network = match std::env::var("NETWORK")
            .unwrap_or_else(|_| "Testnet".to_string())
            .as_str()
        {
            "Mainnet" => Network::MainNetwork,
            _ => Network::TestNetwork,
        };

        let zebra_rpc_url =
            std::env::var("ZEBRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18232".to_string());

        let zaino_grpc_url = std::env::var("ZAINO_GRPC_URL").ok();

        let listen_addr =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3080".to_string());

        let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "/data/zap1.db".to_string());

        let scan_from_height: u32 = std::env::var("SCAN_FROM_HEIGHT")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .unwrap_or(0);

        let webhook_url = std::env::var("WEBHOOK_URL").ok();
        let signal_number = std::env::var("SIGNAL_NUMBER").ok();
        let signal_api_url = std::env::var("SIGNAL_API_URL").ok();
        let foreman_api_key = std::env::var("FOREMAN_API_KEY").ok();
        let foreman_client_id = std::env::var("FOREMAN_CLIENT_ID").ok();
        let api_key = std::env::var("API_KEY").ok();

        // Anchor automation config
        let anchor_zingo_cli = std::env::var("ANCHOR_ZINGO_CLI").ok();
        let anchor_enabled = anchor_zingo_cli.is_some();
        let anchor_chain = std::env::var("ANCHOR_CHAIN").unwrap_or_else(|_| "mainnet".to_string());
        let anchor_server = std::env::var("ANCHOR_SERVER").ok();
        let anchor_data_dir = std::env::var("ANCHOR_DATA_DIR").ok();
        let anchor_to_address = std::env::var("ANCHOR_TO_ADDRESS").ok();
        let anchor_amount_zat: u64 = std::env::var("ANCHOR_AMOUNT_ZAT")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .unwrap_or(1000);
        let anchor_threshold: u32 = std::env::var("ANCHOR_THRESHOLD")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10);
        let anchor_webhook_url = std::env::var("ANCHOR_WEBHOOK_URL").ok();

        let anchor_interval_hours: u64 = std::env::var("ANCHOR_INTERVAL_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .unwrap_or(24);

        Ok(Config {
            ufvk,
            network,
            zebra_rpc_url,
            zaino_grpc_url,
            listen_addr,
            db_path,
            scan_from_height,
            webhook_url,
            signal_number,
            signal_api_url,
            foreman_api_key,
            foreman_client_id,
            api_key,
            anchor_enabled,
            anchor_zingo_cli,
            anchor_chain,
            anchor_server,
            anchor_data_dir,
            anchor_to_address,
            anchor_amount_zat,
            anchor_threshold,
            anchor_interval_hours,
            anchor_webhook_url,
        })
    }
}
