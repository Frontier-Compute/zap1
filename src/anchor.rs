//! Anchor automation subsystem.
//!
//! Manages the lifecycle of Merkle root anchoring to Zcash mainnet:
//! - Monitors unanchored leaf count and time since last anchor
//! - Builds ZAP1:09 memo with current Merkle root
//! - Journals exact signed bytes before embedded-wallet broadcast
//! - Implements exponential backoff on failure (5m, 10m, 20m, 40m, 60m cap)
//! - Sends Signal + webhook notifications on success/failure
//! - Confirms anchor height from Zebra RPC after broadcast

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use incrementalmerkletree::Position;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::db::{AnchorBroadcastIntent, Db};
use crate::wallet::AnchorWallet;

/// Maximum consecutive failures before capping backoff.
const MAX_BACKOFF_MINUTES: u64 = 60;
/// Base backoff interval in minutes.
const BASE_BACKOFF_MINUTES: u64 = 5;
const RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
const RPC_TIMEOUT_SECS: u64 = 15;
const CONFIRMATION_BATCH_LIMIT: u32 = 8;
const BASE_CONFIRMATION_RETRY_SECS: u64 = 90;
const MAX_CONFIRMATION_RETRY_SECS: u64 = 3_600;

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

fn anchor_automation_eligible(config: &Config, wallet_present: bool) -> bool {
    config.anchor_enabled && wallet_present
}

pub(crate) fn anchor_due(
    unanchored: u32,
    threshold: u32,
    hours_since_last_anchor: Option<i64>,
    interval: u64,
) -> bool {
    unanchored >= threshold
        || (unanchored > 0 && hours_since_last_anchor.is_some_and(|hours| hours >= interval as i64))
}

/// Run the anchor automation loop. Call from main alongside the scanner.
pub async fn anchor_loop(config: Arc<Config>, db: Arc<Db>, wallet: Option<Arc<AnchorWallet>>) {
    let automation_eligible = anchor_automation_eligible(&config, wallet.is_some());
    if !config.anchor_enabled {
        tracing::info!(
            "Anchor broadcast disabled; durable confirmation reconciliation remains active"
        );
    } else if !automation_eligible {
        tracing::error!(
            "Anchor broadcast enabled without a validated embedded wallet; new broadcasts are blocked while confirmation reconciliation remains active"
        );
    } else {
        tracing::info!(
            "Anchor automation starting: threshold={} interval={}h",
            config.anchor_threshold,
            config.anchor_interval_hours
        );
    }

    let state = AnchorState::new();
    let check_interval = Duration::from_secs(60);

    loop {
        if let Err(error) = reconcile_due_anchor_confirmations(&config, &db).await {
            tracing::warn!("Anchor confirmation reconciliation error: {error:#}");
        }

        if automation_eligible {
            let backoff = state.backoff_until.lock().await;
            let in_backoff = backoff.is_some_and(|until| Instant::now() < until);
            drop(backoff);
            if !in_backoff {
                if let Err(error) = maybe_anchor(&config, &db, &state, wallet.as_deref()).await {
                    tracing::warn!("Anchor check error: {error:#}");
                }
            }
        }

        sleep(check_interval).await;
    }
}

/// Check if anchoring is needed and execute if so.
async fn maybe_anchor(
    config: &Config,
    db: &Arc<Db>,
    state: &AnchorState,
    wallet: Option<&AnchorWallet>,
) -> Result<()> {
    let pending = db.pending_anchor_broadcast()?;
    let root = db.current_merkle_root()?;
    if root.is_none() {
        return Ok(());
    }

    let unanchored = db.unanchored_leaf_count()?;
    let needs_anchor = pending.is_some()
        || match &root {
            Some(_) => {
                if unanchored >= config.anchor_threshold {
                    tracing::info!(
                        "Anchor trigger: {} unanchored leaves >= threshold {}",
                        unanchored,
                        config.anchor_threshold
                    );
                    true
                } else {
                    let reference_time = db
                        .anchor_interval_reference_created_at()?
                        .as_deref()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
                    if let Some(t) = reference_time {
                        let hours_since =
                            (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_hours();
                        if anchor_due(
                            unanchored,
                            config.anchor_threshold,
                            Some(hours_since),
                            config.anchor_interval_hours,
                        ) {
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
                }
            }
            None => false,
        };

    if !needs_anchor {
        return Ok(());
    }

    match run_anchor(config, &**db, wallet).await {
        Ok((txid, root_hash, leaf_count)) => {
            state.record_success();
            tracing::info!("Anchor transaction broadcast recorded: txid={}", txid);

            // Signal notification
            notify_success(config, leaf_count as u32, &txid).await;

            // Webhook on success
            if let Some(ref webhook_url) = config.anchor_webhook_url {
                webhook_event(
                    webhook_url,
                    "anchor_broadcast_recorded",
                    &serde_json::json!({
                        "txid": txid,
                        "root": root_hash,
                        "leaf_count": leaf_count,
                    }),
                )
                .await;
            }

            // Confirmation is reconciled from the durable journal by the main
            // loop. Process restarts do not discard retry state.
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

/// Execute or resume one exact journaled embedded-wallet broadcast.
async fn run_anchor(
    config: &Config,
    db: &Db,
    wallet: Option<&AnchorWallet>,
) -> Result<(String, String, usize)> {
    if !config.anchor_enabled {
        anyhow::bail!("anchor broadcast disabled by ANCHOR_BROADCAST_ENABLED");
    }

    if let Some(w) = wallet {
        let client = rpc_client()?;
        let intent = if let Some(pending) = db.pending_anchor_broadcast()? {
            tracing::warn!(
                "Resuming exact journaled anchor transaction {} for root {}",
                pending.txid,
                pending.root_hash
            );
            pending
        } else {
            let root = db
                .current_merkle_root()?
                .ok_or_else(|| anyhow::anyhow!("No Merkle root to anchor"))?;

            tracing::info!(
                "Anchoring root {} ({} leaves) via embedded wallet",
                root.root_hash,
                root.leaf_count
            );

            let height = get_chain_height(&client, &config.zebra_rpc_url).await?;
            let (raw_hex, txid, spent_pos) =
                w.build_anchor_tx(&config.network, config, &root.root_hash, height)?;
            let intent = AnchorBroadcastIntent {
                txid,
                root_hash: root.root_hash,
                leaf_count: root.leaf_count,
                raw_tx_hex: raw_hex,
                spent_position: u64::from(spent_pos),
            };
            db.prepare_anchor_broadcast(&intent)?;
            intent
        };

        let resp = client
            .post(&config.zebra_rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sendrawtransaction",
                "params": [&intent.raw_tx_hex]
            }))
            .send()
            .await
            .context("Zebra sendrawtransaction request failed")?
            .error_for_status()
            .context("Zebra sendrawtransaction returned an HTTP error")?;

        let body: serde_json::Value = resp.json().await?;
        let broadcast_matches = body.get("error").filter(|error| !error.is_null()).is_none()
            && body
                .get("result")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|returned| returned.eq_ignore_ascii_case(&intent.txid));
        if !broadcast_matches
            && !transaction_known(&client, &config.zebra_rpc_url, &intent.txid).await?
        {
            let reason = format!("sendrawtransaction did not confirm exact txid: {body}");
            db.record_anchor_broadcast_error(&intent.txid, &reason)?;
            anyhow::bail!("{reason}");
        }

        // Keep the journal prepared until both local wallet state and the
        // immutable root mapping are durable. Any retry reuses these exact
        // signed bytes and txid.
        w.ensure_spent_at_position(Position::from(intent.spent_position))?;
        db.finalize_anchor_broadcast(&intent.txid)?;
        tracing::info!(
            "Anchor recorded: root={} txid={}",
            intent.root_hash,
            intent.txid
        );

        return Ok((intent.txid, intent.root_hash, intent.leaf_count));
    }

    anyhow::bail!(
        "automatic zingo-cli quicksend is disabled because timeout and post-broadcast recovery cannot be made idempotent; use the operator-authorized manual QR flow"
    )
}

#[cfg(test)]
mod authority_tests {
    use super::anchor_automation_eligible;
    use crate::config::Config;

    #[test]
    fn signer_presence_never_enables_broadcast_by_itself() {
        let mut config = Config::test_defaults();
        config.anchor_seed = Some("test-only-seed-placeholder".to_string());
        assert!(!anchor_automation_eligible(&config, true));

        config.anchor_zingo_cli = Some("zingo-cli".to_string());
        assert!(!anchor_automation_eligible(&config, false));
    }

    #[test]
    fn explicit_gate_still_requires_a_signer_path() {
        let mut config = Config::test_defaults();
        config.anchor_enabled = true;
        assert!(!anchor_automation_eligible(&config, false));
        assert!(anchor_automation_eligible(&config, true));
    }
}

fn rpc_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(RPC_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
        .build()
        .context("failed to build bounded Zebra RPC client")
}

async fn get_chain_height(client: &reqwest::Client, zebra_url: &str) -> Result<u32> {
    let resp = client
        .post(zebra_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getblockcount",
            "params": []
        }))
        .send()
        .await
        .context("getblockcount request failed")?
        .error_for_status()
        .context("getblockcount returned an HTTP error")?;
    let body: serde_json::Value = resp.json().await?;
    if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
        anyhow::bail!("getblockcount RPC error: {error}");
    }
    body["result"]
        .as_u64()
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| anyhow::anyhow!("getblockcount returned no result"))
}

async fn transaction_known(client: &reqwest::Client, url: &str, txid: &str) -> Result<bool> {
    let response = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getrawtransaction",
            "params": [txid, 0],
        }))
        .send()
        .await
        .context("getrawtransaction recovery request failed")?
        .error_for_status()
        .context("getrawtransaction recovery returned an HTTP error")?;
    let body: serde_json::Value = response.json().await?;
    Ok(body.get("error").filter(|error| !error.is_null()).is_none()
        && !body
            .get("result")
            .unwrap_or(&serde_json::Value::Null)
            .is_null())
}

fn confirmation_retry_seconds(attempts: u32) -> u64 {
    let exponent = attempts.min(6);
    BASE_CONFIRMATION_RETRY_SECS
        .saturating_mul(1_u64 << exponent)
        .min(MAX_CONFIRMATION_RETRY_SECS)
}

async fn reconcile_due_anchor_confirmations(config: &Config, db: &Db) -> Result<()> {
    let due = db.due_anchor_confirmations(CONFIRMATION_BATCH_LIMIT)?;
    if due.is_empty() {
        return Ok(());
    }

    let client = rpc_client()?;
    for confirmation in due {
        match get_tx_height(&client, &config.zebra_rpc_url, &confirmation.txid).await {
            Ok(height) => {
                db.confirm_anchor_broadcast(&confirmation.txid, height)?;
                tracing::info!(
                    "Anchor transaction reference confirmed: txid={} height={}",
                    confirmation.txid,
                    height
                );
            }
            Err(error) => {
                let retry_seconds = confirmation_retry_seconds(confirmation.confirmation_attempts);
                db.record_anchor_confirmation_retry(
                    &confirmation.txid,
                    &format!("{error:#}"),
                    retry_seconds,
                )?;
                tracing::warn!(
                    "Anchor confirmation pending for txid={}; retry in {}s: {error:#}",
                    confirmation.txid,
                    retry_seconds
                );
            }
        }
    }
    Ok(())
}

async fn get_tx_height(client: &reqwest::Client, url: &str, txid: &str) -> Result<u32> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getrawtransaction",
        "params": [txid, 1],
    });
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .context("getrawtransaction confirmation request failed")?
        .error_for_status()
        .context("getrawtransaction confirmation returned an HTTP error")?;
    let response: serde_json::Value = response.json().await?;
    if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
        anyhow::bail!("getrawtransaction RPC error: {error}");
    }
    response
        .get("result")
        .and_then(|result| result.get("height"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
        .filter(|height| *height > 0)
        .context("transaction is absent or unconfirmed")
}

async fn notify_success(config: &Config, leaves: u32, txid: &str) {
    if let (Some(signal_url), Some(signal_number)) = (&config.signal_api_url, &config.signal_number)
    {
        let msg = format!(
            "Anchor transaction broadcast recorded; confirmation pending\nLeaves: {}\nTxid: {}...",
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
    if let (Some(signal_url), Some(signal_number)) = (&config.signal_api_url, &config.signal_number)
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
    let _ = reqwest::Client::new().post(url).json(&payload).send().await;
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn threshold_and_interval_policy_never_treats_one_fresh_leaf_as_due() {
        assert!(!anchor_due(0, 10, Some(100), 24));
        assert!(!anchor_due(1, 10, Some(1), 24));
        assert!(anchor_due(10, 10, Some(1), 24));
        assert!(anchor_due(1, 10, Some(24), 24));
        assert!(!anchor_due(1, 10, None, 24));
    }

    #[test]
    fn confirmation_retry_backoff_is_bounded_but_never_terminal() {
        assert_eq!(confirmation_retry_seconds(0), 90);
        assert_eq!(confirmation_retry_seconds(1), 180);
        assert_eq!(confirmation_retry_seconds(5), 2_880);
        assert_eq!(confirmation_retry_seconds(6), 3_600);
        assert_eq!(confirmation_retry_seconds(u32::MAX), 3_600);
    }
}
