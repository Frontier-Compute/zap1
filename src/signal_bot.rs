//! Signal bot - public-facing 00zeven agent.
//! Polls Signal CLI REST API for incoming messages, routes commands,
//! sends responses, attests interactions.

use std::sync::Arc;
use std::time::Duration;

use zcash_keys::keys::UnifiedFullViewingKey;

use crate::config::Config;
use crate::db::Db;
use crate::keys::address_for_index_encoded;
use crate::models::{Invoice, InvoiceStatus};

const AGENT_ID: &str = "00zeven-alpha";
const POLL_SECS: u64 = 10;
const JOIN_AMOUNT_ZAT: u64 = 1_000_000; // 0.01 ZEC for testing
const SNOMP_API: &str = "http://127.0.0.1:8888";

pub async fn signal_bot_loop(config: Arc<Config>, db: Arc<Db>, ufvk: Arc<UnifiedFullViewingKey>) {
    let Some(ref number) = config.signal_number else {
        tracing::info!("Signal bot disabled (no SIGNAL_NUMBER)");
        return;
    };
    let signal_url = config
        .signal_api_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8080");

    tracing::info!("Signal bot started on {}", number);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    loop {
        match receive_messages(&client, signal_url, number).await {
            Ok(envelopes) => {
                for env in envelopes {
                    if let Err(e) =
                        handle_envelope(&config, &db, &ufvk, &client, signal_url, number, env).await
                    {
                        tracing::warn!("Signal bot handle error: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Signal bot receive error: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn receive_messages(
    client: &reqwest::Client,
    signal_url: &str,
    number: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let url = format!("{}/v1/receive/{}", signal_url, number);
    let resp = client.get(&url).send().await?;
    let envelopes: Vec<serde_json::Value> = resp.json().await?;
    Ok(envelopes)
}

async fn handle_envelope(
    config: &Config,
    db: &Db,
    ufvk: &UnifiedFullViewingKey,
    client: &reqwest::Client,
    signal_url: &str,
    our_number: &str,
    envelope: serde_json::Value,
) -> anyhow::Result<()> {
    let source = envelope["envelope"]["sourceNumber"]
        .as_str()
        .unwrap_or_default();
    let text = envelope["envelope"]["dataMessage"]["message"]
        .as_str()
        .unwrap_or_default()
        .trim();

    if source.is_empty() || text.is_empty() {
        return Ok(());
    }

    // Upsert contact
    db.upsert_signal_contact(source, source)?;

    let cmd = text.to_lowercase();
    let first_word = cmd.split_whitespace().next().unwrap_or("");

    let response = match first_word {
        "hi" | "hello" | "hey" | "start" | "help" => help_text(),
        "key" | "trial" => handle_key(db, source).await,
        "get" if cmd.starts_with("get key") => handle_key(db, source).await,
        "join" | "mine" | "program" => handle_join(config, db, ufvk, source).await,
        "dashboard" | "my" => handle_dashboard(db, source).await,
        "payout" | "balance" => handle_payout(db, source).await,
        "status" | "stats" => handle_status(db).await,
        "verify" => handle_verify(text),
        "pricing" | "upgrade" | "buy" => pricing_text(),
        "usage" => handle_usage(db, source),
        _ => "Type 'help' for commands.".to_string(),
    };

    // Send response
    send_signal(client, signal_url, our_number, source, &response).await;

    // Attest the interaction
    if let Err(e) = attest_signal_command(db, &cmd) {
        tracing::warn!("Failed to attest signal command: {}", e);
    }

    Ok(())
}

fn help_text() -> String {
    "00zeven here. I manage the ZAP1 attestation protocol on Zcash.\n\n\
     Commands:\n  \
     join - start mining program (creates invoice)\n  \
     dashboard - your leaves, events, attestation status\n  \
     payout - mining stats and estimated payout\n  \
     key - get a free trial API key\n  \
     status - protocol and pool stats\n  \
     verify <hash> - check a proof\n  \
     pricing - API tier info\n  \
     usage - check your usage\n  \
     help - this message"
        .to_string()
}

async fn handle_key(db: &Db, sender: &str) -> String {
    match db.create_api_key(sender, "explorer") {
        Ok((id, raw_key)) => {
            let _ = db.link_contact_to_key(sender, &id);
            format!(
                "Your API key (store it, shown once):\n\n\
                 {}\n\n\
                 Tier: Explorer (50 attestations/mo)\n\
                 Endpoint: POST https://api.frontiercompute.cash/attest\n\
                 Docs: https://api.frontiercompute.cash/protocol/info",
                raw_key
            )
        }
        Err(e) => format!("Failed to create key: {}", e),
    }
}

async fn handle_join(
    config: &Config,
    db: &Db,
    ufvk: &UnifiedFullViewingKey,
    sender: &str,
) -> String {
    // Check if already pending or active
    if let Ok(Some(contact)) = db.get_signal_contact(sender) {
        if contact.status == "pending_join" {
            if let Some(ref inv_id) = contact.invoice_id {
                if let Ok(Some(inv)) = db.get_invoice(inv_id) {
                    if inv.status == InvoiceStatus::Pending {
                        return format!(
                            "You already have a pending join invoice.\n\n\
                             zcash:{}?amount=0.01\n\n\
                             Send 0.01 ZEC to complete enrollment.",
                            inv.address
                        );
                    }
                }
            }
        }
        if contact.status == "active" {
            return "You're already enrolled. Type 'dashboard' for your status.".to_string();
        }
    }

    // Create invoice
    let div_idx = match db.allocate_diversifier_index() {
        Ok(idx) => idx,
        Err(e) => return format!("Failed to allocate address: {}", e),
    };

    let address = match address_for_index_encoded(ufvk, &config.network, div_idx) {
        Ok(a) => a,
        Err(e) => return format!("Failed to derive address: {}", e),
    };

    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::hours(168)).to_rfc3339(); // 7 days

    let invoice_id = uuid::Uuid::new_v4().to_string();
    let wallet_hash = quick_hash(sender.as_bytes());

    let invoice = Invoice {
        id: invoice_id.clone(),
        diversifier_index: div_idx,
        address: address.clone(),
        amount_zat: JOIN_AMOUNT_ZAT,
        memo: Some(format!("NS-join-{}", &wallet_hash[..8])),
        invoice_type: "program".to_string(),
        wallet_hash: Some(wallet_hash.clone()),
        status: InvoiceStatus::Pending,
        received_zat: 0,
        created_at: now.to_rfc3339(),
        expires_at: Some(expires_at),
        paid_at: None,
        paid_txid: None,
        paid_height: None,
        fee_amount_zat: None,
        fee_address: None,
    };

    if let Err(e) = db.create_invoice(&invoice) {
        return format!("Failed to create invoice: {}", e);
    }

    // Link contact to invoice and set pending_join
    let _ = db.link_contact_to_invoice(sender, &invoice_id);
    let _ = db.link_contact_to_wallet(sender, &wallet_hash);
    let _ = db.update_signal_contact_status(sender, "pending_join");

    // Attest onboard start
    if let Err(e) = db.insert_agent_action_leaf(
        AGENT_ID,
        "onboard_start",
        &quick_hash(sender.as_bytes()),
        &quick_hash(invoice_id.as_bytes()),
    ) {
        tracing::warn!("Failed to attest onboard_start: {}", e);
    }

    format!(
        "Mining program enrollment started.\n\n\
         Send 0.01 ZEC (testing amount) to:\n\n\
         zcash:{}?amount=0.01\n\n\
         Invoice: {}\n\
         Expires in 7 days.\n\n\
         Once paid, you'll get a PROGRAM_ENTRY leaf and miner assignment.",
        address,
        &invoice_id[..8]
    )
}

async fn handle_dashboard(db: &Db, sender: &str) -> String {
    let contact = match db.get_signal_contact(sender) {
        Ok(Some(c)) => c,
        Ok(None) => return "No profile found. Type 'join' to get started.".to_string(),
        Err(e) => return format!("Error: {}", e),
    };

    let wallet_hash = match contact.wallet_hash {
        Some(ref wh) => wh.clone(),
        None => return "No wallet linked yet. Type 'join' to enroll.".to_string(),
    };

    let leaves = db.get_leaves_by_wallet(&wallet_hash).unwrap_or_default();
    let miners = db
        .get_miners_by_wallet_hash(&wallet_hash)
        .unwrap_or_default();

    let last_event = leaves
        .last()
        .map(|l| format!("{:?} at {}", l.event_type, &l.created_at[..10]));

    let anchored_count = leaves
        .iter()
        .filter(|l| {
            db.get_root_covering_leaf(&l.leaf_hash)
                .ok()
                .flatten()
                .is_some()
        })
        .count();

    let mut msg = format!(
        "Dashboard for {}...\n\n\
         Status: {}\n\
         Leaves: {} ({} anchored)\n\
         Miners: {}",
        &wallet_hash[..12],
        contact.status,
        leaves.len(),
        anchored_count,
        miners.len()
    );

    if let Some(last) = last_event {
        msg.push_str(&format!("\nLast event: {}", last));
    }

    for (i, (_, serial, fid)) in miners.iter().enumerate() {
        msg.push_str(&format!(
            "\nMiner {}: {} (foreman: {})",
            i + 1,
            serial,
            fid.map(|id| id.to_string())
                .unwrap_or_else(|| "unlinked".to_string())
        ));
    }

    msg.push_str(&format!(
        "\n\nhttps://api.frontiercompute.cash/miner/{}",
        wallet_hash
    ));

    msg
}

async fn handle_payout(db: &Db, sender: &str) -> String {
    let contact = match db.get_signal_contact(sender) {
        Ok(Some(c)) => c,
        Ok(None) => return "No profile found. Type 'join' to get started.".to_string(),
        Err(e) => return format!("Error: {}", e),
    };

    let wallet_hash = match contact.wallet_hash {
        Some(ref wh) => wh.clone(),
        None => return "No wallet linked. Type 'join' to enroll.".to_string(),
    };

    let miners = db
        .get_miners_by_wallet_hash(&wallet_hash)
        .unwrap_or_default();

    if miners.is_empty() {
        return "No miners assigned yet. If you just paid, wait for confirmation.".to_string();
    }

    let invoices = db.get_invoices_by_wallet(&wallet_hash).unwrap_or_default();
    let total_paid: u64 = invoices
        .iter()
        .filter(|i| i.status == InvoiceStatus::Paid)
        .map(|i| i.received_zat)
        .sum();

    let mut msg = format!(
        "Payout info for {}...\n\n\
         Miners: {}\n\
         Total paid: {:.4} ZEC",
        &wallet_hash[..12],
        miners.len(),
        total_paid as f64 / 100_000_000.0
    );

    for (i, (addr, serial, _fid)) in miners.iter().enumerate() {
        msg.push_str(&format!(
            "\n\nMiner {}: {}\nPayout addr: {}...{}",
            i + 1,
            serial,
            &addr[..20],
            &addr[addr.len().saturating_sub(8)..]
        ));
    }

    msg.push_str(&format!(
        "\n\nhttps://api.frontiercompute.cash/miner/{}",
        wallet_hash
    ));

    msg
}

async fn handle_status(db: &Db) -> String {
    let leaves = db.total_leaf_count().unwrap_or(0);
    let roots = db.all_anchored_roots().unwrap_or_default();
    let anchors = roots.iter().filter(|r| r.anchor_txid.is_some()).count();
    let unanchored = db.unanchored_leaf_count().unwrap_or(0);
    let threshold = 10_u32; // matches anchor_threshold default

    // Pool stats from s-nomp
    let pool_stats = fetch_pool_stats().await;

    let mut msg = format!(
        "ZAP1 Protocol\n\n\
         {} leaves, {} anchors, {} unanchored\n\
         Next anchor: ~{} leaves to go\n\
         18 event types deployed",
        leaves,
        anchors,
        unanchored,
        threshold.saturating_sub(unanchored)
    );

    if let Some(stats) = pool_stats {
        msg.push_str(&format!(
            "\n\nPool\n\
             Hashrate: {}\n\
             Workers: {}\n\
             Blocks found: {}",
            stats.hashrate, stats.workers, stats.blocks
        ));
    }

    msg.push_str("\n\nhttps://api.frontiercompute.cash/stats");
    msg
}

struct PoolStats {
    hashrate: String,
    workers: u64,
    blocks: u64,
}

async fn fetch_pool_stats() -> Option<PoolStats> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let url = format!("{}/api/stats", SNOMP_API);
    let resp = client.get(&url).send().await.ok()?;
    let data: serde_json::Value = resp.json().await.ok()?;

    // s-nomp stats format varies by pool config. Extract what we can.
    let mut total_hashrate: f64 = 0.0;
    let mut total_workers: u64 = 0;
    let mut total_blocks: u64 = 0;

    if let Some(pools) = data["pools"].as_object() {
        for (_name, pool) in pools {
            if let Some(hr) = pool["hashrate"].as_f64() {
                total_hashrate += hr;
            }
            if let Some(w) = pool["workerCount"].as_u64() {
                total_workers += w;
            }
            if let Some(stats) = pool["poolStats"].as_object() {
                if let Some(b) = stats["validBlocks"].as_u64() {
                    total_blocks += b;
                }
            }
        }
    }

    let hashrate_str = if total_hashrate > 1_000_000_000.0 {
        format!("{:.2} GH/s", total_hashrate / 1_000_000_000.0)
    } else if total_hashrate > 1_000_000.0 {
        format!("{:.2} MH/s", total_hashrate / 1_000_000.0)
    } else if total_hashrate > 1_000.0 {
        format!("{:.2} KH/s", total_hashrate / 1_000.0)
    } else {
        format!("{:.0} H/s", total_hashrate)
    };

    Some(PoolStats {
        hashrate: hashrate_str,
        workers: total_workers,
        blocks: total_blocks,
    })
}

fn handle_verify(text: &str) -> String {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 2 {
        return "Usage: verify <hex-hash>".to_string();
    }
    let hash = parts[1];
    // Basic hex validation
    if hash.len() < 8 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return "Provide a valid hex hash after 'verify'.".to_string();
    }
    format!(
        "Verify: https://api.frontiercompute.cash/verify/{}/check\n\
         Proof: https://api.frontiercompute.cash/verify/{}/proof.json",
        hash,
        hash
    )
}

fn pricing_text() -> String {
    "ZAP1 API tiers:\n\n\
     Explorer (free): 50 attestations/mo\n\
     Builder (0.01 ZEC/mo): 500 attestations/mo\n\
     Operator (0.1 ZEC/mo): unlimited\n\n\
     All shielded ZEC. Details: https://frontiercompute.io/pricing.html"
        .to_string()
}

fn handle_usage(db: &Db, sender: &str) -> String {
    match db.get_signal_contact(sender) {
        Ok(Some(contact)) => {
            if let Some(key_id) = contact.key_id {
                match db.get_api_key_by_id(&key_id) {
                    Ok(Some(key)) => format!(
                        "Usage: {} / {} attestations this month\nTier: {}",
                        key.leaves_used, key.leaves_limit, key.tier
                    ),
                    _ => "No API key found. Type 'key' to get one.".to_string(),
                }
            } else {
                "No API key found. Type 'key' to get one.".to_string()
            }
        }
        _ => "No API key found. Type 'key' to get one.".to_string(),
    }
}

async fn send_signal(
    client: &reqwest::Client,
    signal_url: &str,
    our_number: &str,
    recipient: &str,
    message: &str,
) {
    let payload = serde_json::json!({
        "message": message,
        "number": our_number,
        "recipients": [recipient]
    });

    let url = format!("{}/v2/send", signal_url);
    match client.post(&url).json(&payload).send().await {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!("Signal send to {} returned {}", recipient, resp.status());
        }
        Err(e) => {
            tracing::warn!("Signal send failed to {}: {}", recipient, e);
        }
        _ => {}
    }
}

fn quick_hash(data: &[u8]) -> String {
    let h = blake2b_simd::Params::new().hash_length(32).hash(data);
    hex::encode(h.as_bytes())
}

fn attest_signal_command(db: &Db, command: &str) -> anyhow::Result<()> {
    let input_hash = quick_hash(command.as_bytes());
    let output_hash = quick_hash(b"signal_command");
    db.insert_agent_action_leaf(AGENT_ID, "signal_command", &input_hash, &output_hash)?;
    Ok(())
}

/// Send a message to a specific Signal number. Used by agent.rs for payment confirmations.
pub async fn send_signal_message(config: &Config, recipient: &str, message: &str) {
    let Some(ref our_number) = config.signal_number else {
        return;
    };
    let signal_url = config
        .signal_api_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8080");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    send_signal(&client, signal_url, our_number, recipient, message).await;
}
