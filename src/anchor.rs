//! Anchor automation subsystem.
//!
//! Manages the lifecycle of Merkle root anchoring to Zcash mainnet:
//! - Monitors unanchored leaf count and time since last anchor
//! - Builds ZAP1:09 memo with current Merkle root
//! - Broadcasts via zingo-cli (or future embedded tx builder)
//! - Implements exponential backoff on failure (5m, 10m, 20m, 40m, 60m cap)
//! - Sends Signal + webhook notifications on success/failure
//! - Confirms anchor height from Zebra RPC after broadcast

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::db::Db;
use crate::memo::merkle_root_memo;
use crate::merkle::decode_hash;

/// Maximum consecutive failures before capping backoff.
const MAX_BACKOFF_MINUTES: u64 = 60;
/// Base backoff interval in minutes.
const BASE_BACKOFF_MINUTES: u64 = 5;

/// Anchor subsystem state.
struct AnchorState {
    consecutive_failures: AtomicU32,
    backoff_until: tokio::sync::Mutex<Option<Instant>>,
}

impl AnchorState {
    fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            backoff_until: tokio::sync::Mutex::new(None),
        }
    }

    fn record_failure(&self) -> u64 {
        let count = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        let backoff_minutes = BASE_BACKOFF_MINUTES * (1u64 << (count as u64 - 1).min(4));
        backoff_minutes.min(MAX_BACKOFF_MINUTES)
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }

    fn failure_count(&self) -> u32 {
        self.consecutive_failures.load(Ordering::SeqCst)
    }
}

/// Run the anchor automation loop. Call from main alongside the scanner.
pub async fn anchor_loop(config: Arc<Config>, db: Arc<Db>) {
    if !config.anchor_enabled {
        tracing::info!("Anchor automation disabled (ANCHOR_ZINGO_CLI not set)");
        return;
    }

    tracing::info!(
        "Anchor automation starting: threshold={} interval={}h",
        config.anchor_threshold,
        config.anchor_interval_hours
    );

    let state = AnchorState::new();
    let check_interval = Duration::from_secs(60);

    loop {
        sleep(check_interval).await;

        // Check backoff
        {
            let backoff = state.backoff_until.lock().await;
            if let Some(until) = *backoff {
                if Instant::now() < until {
                    continue; // Still in backoff period
                }
            }
        }

        if let Err(e) = maybe_anchor(&config, &db, &state).await {
            tracing::warn!("Anchor check error: {:#}", e);
        }
    }
}

/// Check if anchoring is needed and execute if so.
async fn maybe_anchor(config: &Config, db: &Arc<Db>, state: &AnchorState) -> Result<()> {
    let unanchored = db.unanchored_leaf_count()?;
    if unanchored == 0 {
        return Ok(());
    }

    let root = db.current_merkle_root()?;
    let needs_anchor = match &root {
        Some(r) => {
            if unanchored >= config.anchor_threshold {
                tracing::info!(
                    "Anchor trigger: {} unanchored leaves >= threshold {}",
                    unanchored,
                    config.anchor_threshold
                );
                true
            } else if r.anchor_txid.is_some() {
                let last_root_time = chrono::DateTime::parse_from_rfc3339(&r.created_at).ok();
                if let Some(t) = last_root_time {
                    let hours_since =
                        (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_hours();
                    if hours_since >= config.anchor_interval_hours as i64 {
                        tracing::info!(
                            "Anchor trigger: {}h since last root, interval={}h",
                            hours_since,
                            config.anchor_interval_hours
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                tracing::info!("Anchor trigger: unanchored root exists");
                true
            }
        }
        None => false,
    };

    if !needs_anchor {
        return Ok(());
    }

    match run_anchor(config, &**db).await {
        Ok(txid) => {
            state.record_success();
            tracing::info!("Anchor broadcast success: txid={}", txid);

            // Signal notification
            notify_success(config, unanchored, &txid).await;

            // Webhook on success
            if let Some(ref webhook_url) = config.anchor_webhook_url {
                let root_hash = root.map(|r| r.root_hash).unwrap_or_default();
                webhook_event(
                    webhook_url,
                    "anchor_confirmed",
                    &serde_json::json!({
                        "txid": txid,
                        "root": root_hash,
                        "leaves": unanchored,
                    }),
                )
                .await;
            }

            // Spawn background confirmation checker
            let db_arc = Arc::clone(db);
            let txid_clone = txid.clone();
            let zebra_url = config.zebra_rpc_url.clone();
            tokio::spawn(async move {
                confirm_anchor_height(&db_arc, &zebra_url, &txid_clone).await;
            });
        }
        Err(e) => {
            let backoff_minutes = state.record_failure();
            let fail_count = state.failure_count();
            tracing::error!(
                "Anchor broadcast failed ({} consecutive): {:#}. Backoff {}m",
                fail_count,
                e,
                backoff_minutes
            );

            // Set backoff
            {
                let mut backoff = state.backoff_until.lock().await;
                *backoff = Some(Instant::now() + Duration::from_secs(backoff_minutes * 60));
            }

            // Signal alert on failure
            notify_failure(config, fail_count, backoff_minutes, &format!("{:#}", e)).await;

            // Webhook on failure
            if let Some(ref webhook_url) = config.anchor_webhook_url {
                let root_hash = root.map(|r| r.root_hash).unwrap_or_default();
                webhook_event(
                    webhook_url,
                    "anchor_failed",
                    &serde_json::json!({
                        "reason": format!("{:#}", e),
                        "fail_count": fail_count,
                        "backoff_minutes": backoff_minutes,
                        "root": root_hash,
                        "unanchored_leaves": unanchored,
                    }),
                )
                .await;
            }
        }
    }

    Ok(())
}

/// Execute the anchor broadcast via zingo-cli.
async fn run_anchor(config: &Config, db: &Db) -> Result<String> {
    let zingo_cli = config
        .anchor_zingo_cli
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("ANCHOR_ZINGO_CLI not configured"))?;
    let server = config
        .anchor_server
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("ANCHOR_SERVER not configured"))?;
    let data_dir = config
        .anchor_data_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("ANCHOR_DATA_DIR not configured"))?;
    let to_address = config
        .anchor_to_address
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("ANCHOR_TO_ADDRESS not configured"))?;

    let root = db
        .current_merkle_root()?
        .ok_or_else(|| anyhow::anyhow!("No Merkle root to anchor"))?;
    let root_bytes = decode_hash(&root.root_hash)?;
    let memo = merkle_root_memo(&root_bytes).encode();

    tracing::info!(
        "Anchoring root {} ({} leaves) via zingo-cli",
        root.root_hash,
        root.leaf_count
    );

    // Use quicksend (syncs, proposes, and broadcasts in one step)
    let send_output = tokio::process::Command::new(zingo_cli)
        .args([
            "--chain",
            &config.anchor_chain,
            "--server",
            server,
            "--data-dir",
            data_dir,
            "quicksend",
            to_address,
            &config.anchor_amount_zat.to_string(),
            &memo,
        ])
        .output()
        .await
        .context("Failed to execute zingo-cli quicksend")?;

    if !send_output.status.success() {
        anyhow::bail!(
            "zingo-cli quicksend failed: {}",
            String::from_utf8_lossy(&send_output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&send_output.stdout);
    let txid = extract_txid(&stdout)
        .ok_or_else(|| anyhow::anyhow!("Could not extract txid from zingo-cli output"))?;

    db.record_merkle_anchor(&root.root_hash, &txid, None)?;
    tracing::info!("Anchor recorded: root={} txid={}", root.root_hash, txid);

    Ok(txid)
}

/// Extract a 64-char hex txid from command output.
fn extract_txid(output: &str) -> Option<String> {
    output
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ':')
        .find(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|token| token.to_lowercase())
}

/// Background task: poll Zebra RPC to confirm anchor height.
async fn confirm_anchor_height(db: &Db, zebra_url: &str, txid: &str) {
    let client = reqwest::Client::new();
    for _ in 0..4 {
        sleep(Duration::from_secs(90)).await;
        if let Ok(height) = get_tx_height(&client, zebra_url, txid).await {
            if let Err(e) = db.record_merkle_anchor_height(txid, height) {
                tracing::warn!("Failed to record anchor height: {:#}", e);
            } else {
                tracing::info!("Anchor confirmed at height {}", height);
            }
            return;
        }
    }
    tracing::warn!("Anchor {} not confirmed after 6 minutes", &txid[..16]);
}

async fn get_tx_height(client: &reqwest::Client, url: &str, txid: &str) -> Result<u32> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getrawtransaction",
        "params": [txid, 1],
    });
    let resp: serde_json::Value = client
        .post(url)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;
    let height = resp["result"]["height"]
        .as_u64()
        .context("No height in tx")?;
    Ok(height as u32)
}

async fn notify_success(config: &Config, leaves: u32, txid: &str) {
    if let (Some(signal_url), Some(signal_number)) =
        (&config.signal_api_url, &config.signal_number)
    {
        let msg = format!(
            "Merkle root anchored to Zcash\nLeaves: {}\nTxid: {}...",
            leaves,
            &txid[..16]
        );
        let _ = reqwest::Client::new()
            .post(format!("{}/v2/send", signal_url))
            .json(&serde_json::json!({
                "number": signal_number,
                "recipients": [signal_number],
                "message": msg,
            }))
            .send()
            .await;
    }
}

async fn notify_failure(config: &Config, fail_count: u32, backoff_minutes: u64, reason: &str) {
    if let (Some(signal_url), Some(signal_number)) =
        (&config.signal_api_url, &config.signal_number)
    {
        let msg = format!(
            "Anchor broadcast FAILED\nReason: {}\nConsecutive failures: {}\nBackoff: {}m",
            reason, fail_count, backoff_minutes
        );
        let _ = reqwest::Client::new()
            .post(format!("{}/v2/send", signal_url))
            .json(&serde_json::json!({
                "number": signal_number,
                "recipients": [signal_number],
                "message": msg,
            }))
            .send()
            .await;
    }
}

async fn webhook_event(url: &str, event: &str, data: &serde_json::Value) {
    let payload = serde_json::json!({
        "event": event,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": data,
    });
    let _ = reqwest::Client::new()
        .post(url)
        .json(&payload)
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_txid_from_output() {
        let output = "Transaction submitted: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let txid = extract_txid(output);
        assert_eq!(
            txid,
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string())
        );
    }

    #[test]
    fn extract_txid_missing() {
        assert_eq!(extract_txid("no txid here"), None);
        assert_eq!(extract_txid("short: abcdef01"), None);
        assert_eq!(extract_txid(""), None);
    }

    #[test]
    fn extract_txid_mixed_output() {
        let output = r#"
            Syncing wallet...
            Proposing transaction...
            txid: "98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a"
            Done.
        "#;
        let txid = extract_txid(output);
        assert_eq!(
            txid,
            Some("98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a".to_string())
        );
    }

    #[test]
    fn backoff_calculation() {
        let state = AnchorState::new();
        assert_eq!(state.failure_count(), 0);

        let backoff1 = state.record_failure();
        assert_eq!(backoff1, 5); // 5 * 2^0

        let backoff2 = state.record_failure();
        assert_eq!(backoff2, 10); // 5 * 2^1

        let backoff3 = state.record_failure();
        assert_eq!(backoff3, 20); // 5 * 2^2

        let backoff4 = state.record_failure();
        assert_eq!(backoff4, 40); // 5 * 2^3

        let backoff5 = state.record_failure();
        assert_eq!(backoff5, 60); // capped at 60

        let backoff6 = state.record_failure();
        assert_eq!(backoff6, 60); // stays capped

        state.record_success();
        assert_eq!(state.failure_count(), 0);
    }
}
