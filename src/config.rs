use anyhow::{Context, Result};
use zcash_protocol::consensus::Network;

#[derive(Clone)]
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
    pub trial_key_issuance_enabled: bool,
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
    pub anchor_seed: Option<String>,
    // Experimental co-located FROST compatibility mode
    pub signing_mode: String,
    pub frost_share_path_2: Option<String>,
    pub frost_share_path_3: Option<String>,
    pub experimental_colocated_frost_enabled: bool,
}

fn parse_strict_bool(name: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => anyhow::bail!("{name} must be exactly true, false, 1, or 0"),
    }
}

fn env_flag_default_false(name: &str) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) => parse_strict_bool(name, &value),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn env_exact_bool_default_false(name: &str) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => anyhow::bail!("{name} must be exactly true or false"),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn env_u32(name: &str, default: u32) -> Result<u32> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .with_context(|| format!("{name} must be an unsigned 32-bit integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be an unsigned 64-bit integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn validate_signing_mode(
    signing_mode: &str,
    experimental_colocated_frost_enabled: bool,
    network_is_testnet: bool,
    anchor_seed_present: bool,
    frost_share_path_2: Option<&str>,
    frost_share_path_3: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(
        matches!(signing_mode, "single_key" | "frost"),
        "SIGNING_MODE must be exactly single_key or frost"
    );

    if signing_mode == "frost" {
        anyhow::ensure!(
            experimental_colocated_frost_enabled,
            "SIGNING_MODE=frost is experimental and co-locates ANCHOR_SEED plus two shares; set EXPERIMENTAL_COLOCATED_FROST_ENABLED=true only for an explicitly authorized non-production experiment"
        );
        anyhow::ensure!(
            network_is_testnet,
            "experimental co-located FROST is non-production and requires NETWORK=Testnet"
        );
        anyhow::ensure!(
            anchor_seed_present,
            "SIGNING_MODE=frost requires ANCHOR_SEED to derive and verify the wallet group key"
        );
        anyhow::ensure!(
            frost_share_path_2.is_some_and(|path| !path.trim().is_empty())
                && frost_share_path_3.is_some_and(|path| !path.trim().is_empty()),
            "SIGNING_MODE=frost requires FROST_SHARE_PATH_2 and FROST_SHARE_PATH_3"
        );
    } else {
        anyhow::ensure!(
            !experimental_colocated_frost_enabled,
            "EXPERIMENTAL_COLOCATED_FROST_ENABLED requires SIGNING_MODE=frost"
        );
        anyhow::ensure!(
            frost_share_path_2.is_none() && frost_share_path_3.is_none(),
            "FROST share paths require SIGNING_MODE=frost"
        );
    }

    Ok(())
}

impl Config {
    pub fn test_defaults() -> Self {
        Self {
            ufvk: String::new(),
            network: Network::MainNetwork,
            zebra_rpc_url: "http://127.0.0.1:8232".to_string(),
            zaino_grpc_url: None,
            listen_addr: "127.0.0.1:0".to_string(),
            db_path: ":memory:".to_string(),
            scan_from_height: 0,
            webhook_url: None,
            signal_number: None,
            signal_api_url: None,
            foreman_api_key: None,
            foreman_client_id: None,
            api_key: Some("test_key".to_string()),
            trial_key_issuance_enabled: false,
            anchor_enabled: false,
            anchor_zingo_cli: None,
            anchor_chain: "mainnet".to_string(),
            anchor_server: None,
            anchor_data_dir: None,
            anchor_to_address: None,
            anchor_amount_zat: 1000,
            anchor_threshold: 10,
            anchor_interval_hours: 24,
            anchor_webhook_url: None,
            anchor_seed: None,
            signing_mode: "single_key".to_string(),
            frost_share_path_2: None,
            frost_share_path_3: None,
            experimental_colocated_frost_enabled: false,
        }
    }

    pub fn from_env() -> Result<Self> {
        let ufvk = std::env::var("UFVK").context("UFVK env var required")?;

        let network_name = std::env::var("NETWORK").unwrap_or_else(|_| "Testnet".to_string());
        let network = match network_name.as_str() {
            "Mainnet" | "mainnet" => Network::MainNetwork,
            "Testnet" | "testnet" => Network::TestNetwork,
            _ => anyhow::bail!("NETWORK must be exactly Mainnet or Testnet"),
        };

        let zebra_rpc_url =
            std::env::var("ZEBRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18232".to_string());

        let zaino_grpc_url = std::env::var("ZAINO_GRPC_URL").ok();

        let listen_addr =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3080".to_string());

        let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "/data/zap1.db".to_string());

        let scan_from_height = env_u32("SCAN_FROM_HEIGHT", 0)?;

        let webhook_url = std::env::var("WEBHOOK_URL").ok();
        let signal_number = std::env::var("SIGNAL_NUMBER").ok();
        let signal_api_url = std::env::var("SIGNAL_API_URL").ok();
        let foreman_api_key = std::env::var("FOREMAN_API_KEY").ok();
        let foreman_client_id = std::env::var("FOREMAN_CLIENT_ID").ok();
        let api_key = std::env::var("API_KEY").ok();
        let trial_key_issuance_enabled = env_flag_default_false("TRIAL_KEY_ISSUANCE_ENABLED")?;

        // Anchor automation config
        let anchor_zingo_cli = std::env::var("ANCHOR_ZINGO_CLI").ok();
        // Signer presence never grants transaction authority. Broadcast is
        // disabled by default and requires this separate, strictly parsed gate.
        let anchor_enabled = env_flag_default_false("ANCHOR_BROADCAST_ENABLED")?;
        anyhow::ensure!(
            !anchor_enabled || anchor_zingo_cli.is_none(),
            "automatic ANCHOR_ZINGO_CLI quicksend is unsupported: use the embedded wallet or the operator-authorized manual QR flow"
        );
        let expected_anchor_chain = match network {
            Network::MainNetwork => "mainnet",
            Network::TestNetwork => "testnet",
        };
        let anchor_chain =
            std::env::var("ANCHOR_CHAIN").unwrap_or_else(|_| expected_anchor_chain.to_string());
        anyhow::ensure!(
            anchor_chain == expected_anchor_chain,
            "ANCHOR_CHAIN must match NETWORK ({expected_anchor_chain})"
        );
        let anchor_server = std::env::var("ANCHOR_SERVER").ok();
        let anchor_data_dir = std::env::var("ANCHOR_DATA_DIR").ok();
        let anchor_to_address = std::env::var("ANCHOR_TO_ADDRESS").ok();
        let anchor_amount_zat = env_u64("ANCHOR_AMOUNT_ZAT", 1000)?;
        anyhow::ensure!(
            (1..=2_100_000_000_000_000).contains(&anchor_amount_zat),
            "ANCHOR_AMOUNT_ZAT must be between 1 and the Zcash maximum supply in zatoshis"
        );
        let anchor_threshold = env_u32("ANCHOR_THRESHOLD", 10)?;
        anyhow::ensure!(
            anchor_threshold > 0,
            "ANCHOR_THRESHOLD must be greater than zero"
        );
        let anchor_webhook_url = std::env::var("ANCHOR_WEBHOOK_URL").ok();
        let anchor_seed = std::env::var("ANCHOR_SEED").ok();

        let anchor_interval_hours = env_u64("ANCHOR_INTERVAL_HOURS", 24)?;
        anyhow::ensure!(
            anchor_interval_hours > 0,
            "ANCHOR_INTERVAL_HOURS must be greater than zero"
        );
        anyhow::ensure!(
            anchor_interval_hours <= 876_000,
            "ANCHOR_INTERVAL_HOURS must not exceed 100 years"
        );

        let signing_mode =
            std::env::var("SIGNING_MODE").unwrap_or_else(|_| "single_key".to_string());
        let frost_share_path_2 = std::env::var("FROST_SHARE_PATH_2").ok();
        let frost_share_path_3 = std::env::var("FROST_SHARE_PATH_3").ok();
        let experimental_colocated_frost_enabled =
            env_exact_bool_default_false("EXPERIMENTAL_COLOCATED_FROST_ENABLED")?;
        validate_signing_mode(
            &signing_mode,
            experimental_colocated_frost_enabled,
            matches!(network, Network::TestNetwork),
            anchor_seed
                .as_deref()
                .is_some_and(|seed| !seed.trim().is_empty()),
            frost_share_path_2.as_deref(),
            frost_share_path_3.as_deref(),
        )?;

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
            trial_key_issuance_enabled,
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
            anchor_seed,
            signing_mode,
            frost_share_path_2,
            frost_share_path_3,
            experimental_colocated_frost_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{env_exact_bool_default_false, parse_strict_bool, validate_signing_mode};

    #[test]
    fn broadcast_flag_is_strict_and_defaults_are_handled_by_the_caller() {
        assert!(parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "true").unwrap());
        assert!(parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "1").unwrap());
        assert!(!parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "false").unwrap());
        assert!(!parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "0").unwrap());
        assert!(parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "yes").is_err());
        assert!(parse_strict_bool("ANCHOR_BROADCAST_ENABLED", "").is_err());
    }

    #[test]
    fn colocated_frost_requires_explicit_experimental_opt_in() {
        let error = validate_signing_mode(
            "frost",
            false,
            true,
            true,
            Some("share-2.json"),
            Some("share-3.json"),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("EXPERIMENTAL_COLOCATED_FROST_ENABLED=true"));
    }

    #[test]
    fn colocated_frost_requires_full_seed_and_both_share_paths() {
        assert!(validate_signing_mode(
            "frost",
            true,
            true,
            false,
            Some("share-2.json"),
            Some("share-3.json")
        )
        .is_err());
        assert!(
            validate_signing_mode("frost", true, true, true, Some("share-2.json"), None).is_err()
        );
        assert!(
            validate_signing_mode("frost", true, true, true, Some(""), Some("share-3.json"))
                .is_err()
        );
    }

    #[test]
    fn colocated_frost_opt_in_accepts_only_literal_booleans() {
        const NAME: &str = "ZAP1_TEST_EXPERIMENTAL_FROST_BOOL";
        std::env::set_var(NAME, "true");
        assert!(env_exact_bool_default_false(NAME).unwrap());
        std::env::set_var(NAME, "false");
        assert!(!env_exact_bool_default_false(NAME).unwrap());
        std::env::set_var(NAME, "1");
        assert!(env_exact_bool_default_false(NAME).is_err());
        std::env::remove_var(NAME);
    }

    #[test]
    fn colocated_frost_configuration_is_accepted_only_with_all_gates() {
        validate_signing_mode(
            "frost",
            true,
            true,
            true,
            Some("share-2.json"),
            Some("share-3.json"),
        )
        .unwrap();
        assert!(validate_signing_mode("single_key", true, true, true, None, None).is_err());
        assert!(validate_signing_mode(
            "single_key",
            false,
            false,
            true,
            Some("share-2.json"),
            None
        )
        .is_err());
    }

    #[test]
    fn colocated_frost_is_rejected_on_mainnet() {
        let error = validate_signing_mode(
            "frost",
            true,
            false,
            true,
            Some("share-2.json"),
            Some("share-3.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("NETWORK=Testnet"));
    }
}
