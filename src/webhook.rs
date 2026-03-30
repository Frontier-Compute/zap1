//! Webhook delivery system for ZAP1 lifecycle events.
//!
//! Register URLs to receive POST notifications when leaves are created
//! or anchors are confirmed. Payloads are signed with a keyed BLAKE2b MAC.

use std::sync::Arc;

use anyhow::Result;
use tokio::time::{sleep, Duration};

use crate::db::Db;

/// Deliver a webhook notification for a lifecycle event.
pub async fn deliver_leaf_event(db: &Arc<Db>, leaf_hash: &str, event_type: &str, wallet_hash: &str) {
    let hooks = match db.list_webhooks() {
        Ok(h) => h,
        Err(_) => return,
    };

    let payload = serde_json::json!({
        "event": "leaf_created",
        "leaf_hash": leaf_hash,
        "event_type": event_type,
        "wallet_hash": wallet_hash,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    for hook in hooks {
        let payload_str = payload.to_string();
        let signature = compute_mac(&hook.secret, &payload_str);

        let url = hook.url.clone();
        let client = client.clone();
        tokio::spawn(async move {
            deliver_with_retry(&client, &url, &payload_str, &signature).await;
        });
    }
}

/// Deliver a webhook notification for an anchor confirmation.
pub async fn deliver_anchor_event(db: &Arc<Db>, root: &str, txid: &str, height: Option<u32>) {
    let hooks = match db.list_webhooks() {
        Ok(h) => h,
        Err(_) => return,
    };

    let payload = serde_json::json!({
        "event": "anchor_confirmed",
        "root": root,
        "txid": txid,
        "height": height,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    for hook in hooks {
        let payload_str = payload.to_string();
        let signature = compute_mac(&hook.secret, &payload_str);

        let url = hook.url.clone();
        let client = client.clone();
        tokio::spawn(async move {
            deliver_with_retry(&client, &url, &payload_str, &signature).await;
        });
    }
}

async fn deliver_with_retry(client: &reqwest::Client, url: &str, payload: &str, signature: &str) {
    for attempt in 0..3 {
        let result = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-ZAP1-Signature", signature)
            .body(payload.to_string())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => {
                tracing::debug!("Webhook delivery to {} returned {}, attempt {}", url, resp.status(), attempt + 1);
            }
            Err(e) => {
                tracing::debug!("Webhook delivery to {} failed: {}, attempt {}", url, e, attempt + 1);
            }
        }

        if attempt < 2 {
            sleep(Duration::from_secs(2u64.pow(attempt as u32))).await;
        }
    }
    tracing::warn!("Webhook delivery to {} failed after 3 attempts", url);
}

/// BLAKE2b-256 keyed MAC. Uses the secret as the BLAKE2b key parameter
/// (not prefix concatenation). Receivers verify by computing the same
/// keyed hash over the payload using their stored secret.
fn compute_mac(secret: &str, payload: &str) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZAP1_webhook_sig")
        .key(secret.as_bytes())
        .to_state()
        .update(payload.as_bytes())
        .finalize();
    hex::encode(hash.as_bytes())
}

/// Webhook registration record.
#[derive(Debug, Clone)]
pub struct WebhookRecord {
    pub id: String,
    pub url: String,
    pub secret: String,
}
