//! 00zeven agent loop - autonomous mining operations monitor.
//! Polls Foreman for miner telemetry, detects anomalies,
//! takes action, attests everything via ZAP1 AGENT_ACTION events.

use chrono::Datelike;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::foreman::{ForemanClient, MinerStatus};

const AGENT_ID: &str = "00zeven-alpha";
const POLL_INTERVAL_SECS: u64 = 60;

// Thresholds
const HASHRATE_FLOOR_KHS: f64 = 100.0; // alert if below this
const TEMP_CEILING_C: f64 = 85.0; // alert if above this
const STALE_MINUTES: u64 = 10; // alert if last_seen older than this

#[derive(Debug, Clone)]
pub struct AgentAlert {
    pub miner_id: u64,
    pub miner_name: String,
    pub alert_type: String,
    pub detail: String,
    pub action_taken: String,
}

#[allow(dead_code)]
struct MinerSnapshot {
    hashrate: f64,
    status: String,
    temp: Option<f64>,
}

pub async fn agent_loop(config: Arc<Config>, db: Arc<Db>, foreman: Arc<ForemanClient>) {
    tracing::info!(
        "00zeven agent started - polling every {}s",
        POLL_INTERVAL_SECS
    );

    // Register agent on first run
    if let Err(e) = register_agent(&config, &db).await {
        tracing::warn!("Agent registration failed: {}", e);
    }

    let mut prev_snapshots: HashMap<u64, MinerSnapshot> = HashMap::new();

    loop {
        match foreman.get_all_miners().await {
            Ok(miners) => {
                let alerts = evaluate_miners(&miners, &prev_snapshots);

                for alert in &alerts {
                    tracing::warn!(
                        "00zeven alert: {} on {} - {} (action: {})",
                        alert.alert_type,
                        alert.miner_name,
                        alert.detail,
                        alert.action_taken
                    );

                    // Attest action
                    if let Err(e) = attest_action(&db, &alert.alert_type, &alert.detail).await {
                        tracing::warn!("Failed to attest agent action: {}", e);
                    }

                    // Signal alert
                    send_agent_alert(&config, alert).await;
                }

                // Update snapshots
                prev_snapshots.clear();
                for m in &miners {
                    prev_snapshots.insert(
                        m.miner_id,
                        MinerSnapshot {
                            hashrate: m.hashrate,
                            status: m.status.clone(),
                            temp: m.temp,
                        },
                    );
                }

                tracing::debug!(
                    "00zeven tick: {} miners, {} alerts",
                    miners.len(),
                    alerts.len()
                );
            }
            Err(e) => {
                tracing::warn!("Foreman poll failed: {}", e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

fn evaluate_miners(miners: &[MinerStatus], prev: &HashMap<u64, MinerSnapshot>) -> Vec<AgentAlert> {
    let mut alerts = Vec::new();

    for m in miners {
        // Hashrate drop
        if m.hashrate < HASHRATE_FLOOR_KHS && m.status != "offline" {
            let detail = format!(
                "{:.0} {} (floor: {:.0} KH/s)",
                m.hashrate, m.hashrate_unit, HASHRATE_FLOOR_KHS
            );
            alerts.push(AgentAlert {
                miner_id: m.miner_id,
                miner_name: m.name.clone(),
                alert_type: "hashrate_low".to_string(),
                detail,
                action_taken: "alert_sent".to_string(),
            });
        }

        // Temp spike
        if let Some(temp) = m.temp {
            if temp > TEMP_CEILING_C {
                alerts.push(AgentAlert {
                    miner_id: m.miner_id,
                    miner_name: m.name.clone(),
                    alert_type: "temp_high".to_string(),
                    detail: format!("{:.1}C (ceiling: {:.0}C)", temp, TEMP_CEILING_C),
                    action_taken: "alert_sent".to_string(),
                });
            }
        }

        // Miner went offline (was online in previous snapshot)
        if m.status == "offline" || m.status == "error" {
            if let Some(prev_snap) = prev.get(&m.miner_id) {
                if prev_snap.status != "offline" && prev_snap.status != "error" {
                    alerts.push(AgentAlert {
                        miner_id: m.miner_id,
                        miner_name: m.name.clone(),
                        alert_type: "miner_offline".to_string(),
                        detail: format!("was {}, now {}", prev_snap.status, m.status),
                        action_taken: "alert_sent".to_string(),
                    });
                }
            }
        }

        // Stale last_seen
        if let Some(ref last_seen) = m.last_seen {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(last_seen) {
                let age = chrono::Utc::now().signed_duration_since(ts);
                if age.num_minutes() > STALE_MINUTES as i64 && m.status != "offline" {
                    alerts.push(AgentAlert {
                        miner_id: m.miner_id,
                        miner_name: m.name.clone(),
                        alert_type: "stale_telemetry".to_string(),
                        detail: format!(
                            "last seen {}m ago (threshold: {}m)",
                            age.num_minutes(),
                            STALE_MINUTES
                        ),
                        action_taken: "alert_sent".to_string(),
                    });
                }
            }
        }
    }

    alerts
}

fn quick_hash(data: &[u8]) -> String {
    let h = blake2b_simd::Params::new().hash_length(32).hash(data);
    hex::encode(h.as_bytes())
}

async fn register_agent(_config: &Config, db: &Db) -> anyhow::Result<()> {
    let policy_hash = quick_hash(b"00zeven-monitor-v1");
    let model_hash = quick_hash(b"foreman-poller");
    let pubkey_hash = quick_hash(AGENT_ID.as_bytes());

    db.insert_agent_register_leaf(AGENT_ID, &pubkey_hash, &model_hash, &policy_hash)?;
    tracing::info!("00zeven agent registered: {}", AGENT_ID);
    Ok(())
}

async fn attest_action(db: &Db, action_type: &str, detail: &str) -> anyhow::Result<()> {
    let input_hash = quick_hash(detail.as_bytes());
    let output_hash = quick_hash(action_type.as_bytes());

    db.insert_agent_action_leaf(AGENT_ID, action_type, &input_hash, &output_hash)?;
    Ok(())
}

async fn send_agent_alert(config: &Config, alert: &AgentAlert) {
    let Some(number) = &config.signal_number else {
        return;
    };
    let signal_url = config
        .signal_api_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8080");

    let msg = format!(
        "00zeven alert\n\n\
         Miner: {}\n\
         Type: {}\n\
         Detail: {}\n\
         Action: {}",
        alert.miner_name, alert.alert_type, alert.detail, alert.action_taken
    );

    let payload = serde_json::json!({
        "message": msg,
        "number": number,
        "recipients": [number]
    });

    let url = format!("{}/v2/send", signal_url);
    let _ = reqwest::Client::new()
        .post(&url)
        .json(&payload)
        .send()
        .await;
}

const BUSINESS_CHECK_SECS: u64 = 300; // check every 5 minutes
const USAGE_WARN_PERCENT: f64 = 0.8;

/// Run the API business operations loop alongside the miner monitor.
pub async fn business_loop(config: Arc<Config>, db: Arc<Db>) {
    tracing::info!(
        "00zeven business ops started - checking every {}s",
        BUSINESS_CHECK_SECS
    );

    let mut last_month: u32 = chrono::Utc::now().month();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(BUSINESS_CHECK_SECS)).await;

        // Monthly usage reset on the 1st
        let now = chrono::Utc::now();
        let current_month = now.month();
        if current_month != last_month {
            if let Err(e) = monthly_reset(&db).await {
                tracing::warn!("Monthly reset failed: {}", e);
            } else {
                if let Err(e) = attest_action(
                    &db,
                    "monthly_reset",
                    &format!("usage counters reset for month {}", current_month),
                )
                .await
                {
                    tracing::warn!("Failed to attest monthly reset: {}", e);
                }
                tracing::info!("00zeven: monthly usage counters reset");
            }
            last_month = current_month;
        }

        // Check for paid API subscription invoices that need key provisioning
        if let Err(e) = check_paid_subscriptions(&config, &db).await {
            tracing::warn!("Subscription check failed: {}", e);
        }

        // Check usage warnings
        if let Err(e) = check_usage_limits(&config, &db).await {
            tracing::warn!("Usage limit check failed: {}", e);
        }

        // Check for pending_join contacts whose invoices got paid
        if let Err(e) = check_onboard_completions(&config, &db).await {
            tracing::warn!("Onboard completion check failed: {}", e);
        }
    }
}

/// Check for paid api_subscription invoices and provision keys.
async fn check_paid_subscriptions(config: &Config, db: &Db) -> anyhow::Result<()> {
    let invoices = db.list_invoices(Some("paid"))?;

    for inv in invoices {
        if inv.invoice_type != "api_subscription" {
            continue;
        }

        // Check if a key already exists for this wallet_hash
        let wallet = inv.wallet_hash.as_deref().unwrap_or("unknown");
        let existing_keys = db.list_api_keys()?;
        let already_provisioned = existing_keys.iter().any(|k| k.name == wallet);
        if already_provisioned {
            continue;
        }

        // Determine tier from payment amount
        let tier = if inv.amount_zat >= 10_000_000 {
            // 0.1 ZEC = Operator
            "operator"
        } else {
            // 0.01 ZEC = Builder
            "builder"
        };

        match db.create_api_key(wallet, tier) {
            Ok((_id, raw_key)) => {
                tracing::info!(
                    "00zeven: provisioned {} key for {} (invoice {})",
                    tier,
                    wallet,
                    inv.id
                );

                // Attest the key creation
                let detail = format!("key_provisioned:{}:{}:{}", wallet, tier, inv.id);
                let _ = attest_action(db, "key_provision", &detail).await;

                // Notify via Signal
                send_business_alert(
                    config,
                    &format!(
                        "API key provisioned\n\nTier: {}\nWallet: {}\nKey: {}\n\nStore this key. It won't be shown again.",
                        tier, wallet, raw_key
                    ),
                ).await;
            }
            Err(e) => {
                tracing::warn!("Failed to provision key for {}: {}", wallet, e);
            }
        }
    }

    Ok(())
}

/// Check API key usage against limits and warn at 80%.
async fn check_usage_limits(config: &Config, db: &Db) -> anyhow::Result<()> {
    let keys = db.list_api_keys()?;

    for key in &keys {
        if key.leaves_limit <= 0 {
            continue;
        }

        let usage_ratio = key.leaves_used as f64 / key.leaves_limit as f64;

        if usage_ratio >= 1.0 {
            // At or over limit
            let detail = format!(
                "limit_hit:{}:{}:{}/{}",
                key.name, key.tier, key.leaves_used, key.leaves_limit
            );
            let _ = attest_action(db, "usage_limit_hit", &detail).await;

            send_business_alert(
                config,
                &format!(
                    "API usage limit reached\n\nKey: {}\nTier: {}\nUsage: {}/{}\n\nUpgrade to Operator tier or wait for monthly reset.",
                    key.name, key.tier, key.leaves_used, key.leaves_limit
                ),
            ).await;
        } else if usage_ratio >= USAGE_WARN_PERCENT {
            send_business_alert(
                config,
                &format!(
                    "API usage warning\n\nKey: {}\nTier: {}\nUsage: {}/{} ({:.0}%)",
                    key.name,
                    key.tier,
                    key.leaves_used,
                    key.leaves_limit,
                    usage_ratio * 100.0
                ),
            )
            .await;
        }
    }

    Ok(())
}

/// Reset monthly usage counters.
async fn monthly_reset(db: &Db) -> anyhow::Result<()> {
    db.reset_monthly_usage()?;
    Ok(())
}

/// Send a business operations alert via Signal.
async fn send_business_alert(config: &Config, msg: &str) {
    let Some(number) = &config.signal_number else {
        return;
    };
    let signal_url = config
        .signal_api_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8080");

    let payload = serde_json::json!({
        "message": format!("00zeven ops\n\n{}", msg),
        "number": number,
        "recipients": [number]
    });

    let url = format!("{}/v2/send", signal_url);
    let _ = reqwest::Client::new()
        .post(&url)
        .json(&payload)
        .send()
        .await;
}

/// Check pending_join contacts whose invoices have been paid.
/// Creates PROGRAM_ENTRY leaf, assigns miner if serial available,
/// sends confirmation via Signal.
async fn check_onboard_completions(config: &Config, db: &Db) -> anyhow::Result<()> {
    let pending = db.list_pending_join_contacts()?;

    for contact in pending {
        let invoice_id = match contact.invoice_id {
            Some(ref id) => id.clone(),
            None => continue,
        };

        let invoice = match db.get_invoice(&invoice_id)? {
            Some(inv) => inv,
            None => continue,
        };

        if invoice.status != crate::models::InvoiceStatus::Paid {
            continue;
        }

        let wallet_hash = match contact.wallet_hash {
            Some(ref wh) => wh.clone(),
            None => match invoice.wallet_hash {
                Some(ref wh) => {
                    let _ = db.link_contact_to_wallet(&contact.number, wh);
                    wh.clone()
                }
                None => continue,
            },
        };

        // Create PROGRAM_ENTRY leaf
        let leaf_result = match db.insert_program_entry_leaf(&wallet_hash) {
            Ok((leaf, _root)) => {
                tracing::info!(
                    "00zeven: PROGRAM_ENTRY created for {} (invoice {})",
                    &wallet_hash[..12],
                    &invoice_id[..8]
                );
                Some(leaf)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create PROGRAM_ENTRY for {}: {}",
                    &wallet_hash[..12],
                    e
                );
                None
            }
        };

        // Mark contact active
        let _ = db.update_signal_contact_status(&contact.number, "active");

        // Attest onboard_complete
        let detail = format!(
            "onboard_complete:{}:{}",
            &wallet_hash[..12],
            &invoice_id[..8]
        );
        let _ = attest_action(db, "onboard_complete", &detail).await;

        // Build confirmation message
        let mut msg = format!(
            "Payment confirmed. Welcome to the mining program.\n\n\
             Wallet: {}...{}",
            &wallet_hash[..8],
            &wallet_hash[wallet_hash.len().saturating_sub(6)..]
        );

        if let Some(ref leaf) = leaf_result {
            msg.push_str(&format!(
                "\nPROGRAM_ENTRY leaf: {}...{}",
                &leaf.leaf_hash[..12],
                &leaf.leaf_hash[leaf.leaf_hash.len().saturating_sub(8)..]
            ));
            msg.push_str(&format!(
                "\nVerify: https://api.frontiercompute.cash/verify/{}/check",
                leaf.leaf_hash
            ));
        }

        msg.push_str(&format!(
            "\n\nDashboard: https://api.frontiercompute.cash/miner/{}\n\n\
             Type 'dashboard' anytime for your status.",
            wallet_hash
        ));

        // Send confirmation via Signal
        crate::signal_bot::send_signal_message(config, &contact.number, &msg).await;

        // Ops notification
        send_business_alert(
            config,
            &format!(
                "New member onboarded\n\nWallet: {}...\nInvoice: {}",
                &wallet_hash[..12],
                &invoice_id[..8]
            ),
        )
        .await;
    }

    Ok(())
}
