use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Json},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

fn check_api_key(config: &Config, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Some(expected) = &config.api_key {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match provided {
            Some(key) if key == expected => Ok(()),
            _ => Err((
                StatusCode::UNAUTHORIZED,
                "Invalid or missing API key".to_string(),
            )),
        }
    } else {
        Ok(()) // No API key configured = no auth required (dev mode)
    }
}

fn generate_qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::QrCode;
    match QrCode::new(data) {
        Ok(code) => code.render::<svg::Color>()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(_) => "<svg width=\"200\" height=\"200\"><text x=\"10\" y=\"100\" fill=\"#666\" font-size=\"12\">QR failed</text></svg>".to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
use serde::Deserialize;
use std::sync::Arc;

use zcash_keys::keys::UnifiedFullViewingKey;

use crate::config::Config;
use crate::db::Db;
use crate::foreman::ForemanClient;
use crate::keys::address_for_index_encoded;
use crate::models::{CreateInvoiceRequest, HealthResponse, Invoice, InvoiceStatus};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub ufvk: Arc<UnifiedFullViewingKey>,
    pub config: Arc<Config>,
    pub foreman: Option<Arc<ForemanClient>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/invoice", post(create_invoice))
        .route("/invoice/{id}", get(get_invoice))
        .route("/invoices", get(list_invoices))
        .route("/pay/{id}", get(payment_page))
        .route("/miner/{wallet_hash}", get(miner_dashboard))
        .route("/miner/{wallet_hash}/status", get(miner_status_json))
        .route("/miner/{wallet_hash}/verify", get(viewing_key_info))
        .route("/verify/{leaf_hash}", get(verify_page))
        .route("/assign", post(assign_miner))
        .route("/event", post(create_lifecycle_event))
        .route("/lifecycle/{wallet_hash}", get(lifecycle))
        .route("/stats", get(stats))
        .route("/health", get(health))
        .route("/anchor/status", get(anchor_status))
        .route("/verify/{leaf_hash}/proof.json", get(proof_bundle_json))
        .route("/auto-invoice", post(auto_invoice))
        .route("/cohort", get(cohort_stats))
        .route("/admin/overview", get(admin_overview))
        .route("/verify/{leaf_hash}/check", get(verify_check))
        .route("/anchor/history", get(anchor_history))
        .route("/protocol/info", get(protocol_info))
        .route("/badge/status.svg", get(badge_status))
        .route("/badge/leaf/{leaf_hash}", get(badge_leaf))
        .route("/badge/anchor/{txid_prefix}", get(badge_anchor))
        .route("/build/info", get(build_info))
        .route("/events", get(recent_events))
        .route("/memo/decode", post(memo_decode_endpoint))
        .route("/webhooks", get(list_webhooks))
        .route("/webhooks/register", post(register_webhook))
        .route("/webhooks/{id}", delete(delete_webhook))
        .route("/admin/anchor/qr", get(admin_anchor_qr))
        .route("/admin/anchor/record", post(admin_anchor_record))
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "https://frontiercompute.cash".parse().unwrap(),
                    "https://frontiercompute.io".parse().unwrap(),
                    "https://verify.frontiercompute.cash".parse().unwrap(),
                    "https://nordicshield.cash".parse().unwrap(),
                    "https://pay.frontiercompute.io".parse().unwrap(),
                ])
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
                .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]),
        )
        .with_state(state)
}

async fn create_invoice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInvoiceRequest>,
) -> Result<(StatusCode, Json<Invoice>), (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    if req.amount_zec <= 0.0 || req.amount_zec > 21_000_000.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Amount must be > 0 and <= 21000000".to_string(),
        ));
    }
    let amount_zat = (req.amount_zec * 100_000_000.0).round() as u64;
    if amount_zat == 0 {
        return Err((StatusCode::BAD_REQUEST, "Amount must be > 0".to_string()));
    }

    let div_idx = state
        .db
        .allocate_diversifier_index()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let address = address_for_index_encoded(&state.ufvk, &state.config.network, div_idx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = chrono::Utc::now();
    let expires_at = req
        .expires_in_hours
        .map(|h| (now + chrono::Duration::hours(h as i64)).to_rfc3339());

    let invoice = Invoice {
        id: uuid::Uuid::new_v4().to_string(),
        diversifier_index: div_idx,
        address,
        amount_zat,
        memo: req.memo,
        invoice_type: req.invoice_type,
        wallet_hash: req.wallet_hash,
        status: InvoiceStatus::Pending,
        received_zat: 0,
        created_at: now.to_rfc3339(),
        expires_at,
        paid_at: None,
        paid_txid: None,
        paid_height: None,
    };

    state
        .db
        .create_invoice(&invoice)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("Created invoice {} -> {}", invoice.id, invoice.address);

    // Signal notification
    let config = state.config.clone();
    let inv_clone = invoice.clone();
    tokio::spawn(async move {
        crate::notify::invoice_created(&config, &inv_clone).await;
    });

    Ok((StatusCode::CREATED, Json(invoice)))
}

async fn get_invoice(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Invoice>, (StatusCode, String)> {
    let invoice = state
        .db
        .get_invoice(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Invoice not found".to_string()))?;

    Ok(Json(invoice))
}

/// Payment page - participant-facing HTML with address, amount, and live status.
async fn payment_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let invoice = state
        .db
        .get_invoice(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Invoice not found".to_string()))?;

    let amount_zec = invoice.amount_zat as f64 / 100_000_000.0;
    let received_zec = invoice.received_zat as f64 / 100_000_000.0;

    let status_color = match invoice.status {
        InvoiceStatus::Paid => "#3d9b8f",
        InvoiceStatus::Partial => "#d4a843",
        InvoiceStatus::Expired => "#e74c3c",
        InvoiceStatus::Pending => "#7a8194",
    };

    let status_text = match invoice.status {
        InvoiceStatus::Paid => "PAID",
        InvoiceStatus::Partial => "PARTIAL PAYMENT",
        InvoiceStatus::Expired => "EXPIRED",
        InvoiceStatus::Pending => "AWAITING PAYMENT",
    };

    let paid_info = if invoice.status == InvoiceStatus::Paid {
        format!(
            r#"<div class="paid-box">
                <div class="label">Payment Confirmed</div>
                <div class="txid">{}</div>
            </div>"#,
            invoice.paid_txid.as_deref().unwrap_or("confirming...")
        )
    } else {
        String::new()
    };

    let refresh_script =
        if invoice.status == InvoiceStatus::Pending || invoice.status == InvoiceStatus::Partial {
            r#"<script>setTimeout(()=>location.reload(),15000)</script>"#
        } else {
            ""
        };

    let is_testnet = matches!(
        state.config.network,
        zcash_protocol::consensus::Network::TestNetwork
    );
    let testnet_banner = if is_testnet {
        r#"<div style="position:fixed;top:0;left:0;right:0;background:#e74c3c;color:#fff;text-align:center;padding:8px;font-size:12px;font-weight:600;letter-spacing:0.1em;z-index:100">TESTNET - NOT REAL ZEC</div>"#
    } else {
        ""
    };
    let testnet_title = if is_testnet { " (Testnet)" } else { "" };
    let testnet_padding = if is_testnet { "padding-top:40px;" } else { "" };

    let invoice_short = if invoice.id.len() >= 8 {
        &invoice.id[..8]
    } else {
        &invoice.id
    };
    let zcash_uri = format!(
        "zcash:{}?amount={:.4}&memo=NS-{}",
        invoice.address, amount_zec, invoice_short
    );
    let zcash_uri_short = if zcash_uri.len() > 60 {
        format!(
            "zcash:{}...?amount={:.4}",
            &invoice.address[..invoice.address.len().min(20)],
            amount_zec
        )
    } else {
        zcash_uri.clone()
    };

    let html = include_str!("payment_page.html")
        .replace("{TESTNET_TITLE}", testnet_title)
        .replace("{TESTNET_PADDING}", testnet_padding)
        .replace("{TESTNET_BANNER}", testnet_banner)
        .replace("{STATUS_COLOR}", status_color)
        .replace("{STATUS_TEXT}", status_text)
        .replace(
            "{MEMO_LINE}",
            &if invoice.memo.is_some() {
                format!(
                    "<div class=\"memo\">{}</div>",
                    html_escape(invoice.memo.as_deref().unwrap_or(""))
                )
            } else {
                String::new()
            },
        )
        .replace("{AMOUNT_ZEC}", &format!("{:.4}", amount_zec))
        .replace(
            "{RECEIVED_LINE}",
            &if invoice.received_zat > 0 {
                format!(
                    "<div class=\"received\">Received: {:.4} ZEC</div>",
                    received_zec
                )
            } else {
                String::new()
            },
        )
        .replace("{QR_SVG}", &generate_qr_svg(&zcash_uri))
        .replace("{ZCASH_URI_RAW}", &zcash_uri)
        .replace("{ZCASH_URI_SHORT}", &zcash_uri_short)
        .replace("{ADDRESS}", &invoice.address)
        .replace("{PAID_INFO}", &paid_info)
        .replace(
            "{INVOICE_SHORT}",
            if invoice.id.len() >= 8 {
                &invoice.id[..8]
            } else {
                &invoice.id
            },
        )
        .replace(
            "{EXPIRES_LINE}",
            &invoice
                .expires_at
                .as_deref()
                .map(|e| format!("Expires: {}<br>", &e[..e.len().min(19)]))
                .unwrap_or_default(),
        )
        .replace("{REFRESH_SCRIPT}", refresh_script);

    Ok(Html(html))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
}

async fn list_invoices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<Invoice>>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    let invoices = state
        .db
        .list_invoices(query.status.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(invoices))
}

async fn health(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, (StatusCode, String)> {
    let (last_scanned, _) = state
        .db
        .get_scan_state()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let pending = state
        .db
        .count_pending()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fetch real chain tip from Zebra (5s timeout)
    let rpc_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let (chain_tip, rpc_reachable) = match rpc_client
        .post(&state.config.zebra_rpc_url)
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                (json["result"]["blocks"].as_u64().unwrap_or(0) as u32, true)
            } else {
                (0, false)
            }
        }
        Err(_) => (0, false),
    };

    let sync_lag = chain_tip.saturating_sub(last_scanned);
    let scanner_operational = rpc_reachable && chain_tip > 0 && sync_lag < 100;

    let network = format!("{:?}", state.config.network);

    Ok(Json(HealthResponse {
        last_scanned_height: last_scanned,
        chain_tip,
        sync_lag,
        pending_invoices: pending,
        scanner_operational,
        network,
        rpc_reachable,
    }))
}

async fn anchor_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let root = state
        .db
        .current_merkle_root()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let unanchored = state
        .db
        .unanchored_leaf_count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (root_hash, leaf_count, anchor_txid, anchor_height, needs_anchor) = match &root {
        Some(r) => (
            r.root_hash.clone(),
            r.leaf_count,
            r.anchor_txid.clone(),
            r.anchor_height,
            r.anchor_txid.is_none() || unanchored > 0,
        ),
        None => ("none".to_string(), 0, None, None, false),
    };

    Ok(Json(serde_json::json!({
        "current_root": root_hash,
        "leaf_count": leaf_count,
        "unanchored_leaves": unanchored,
        "last_anchor_txid": anchor_txid,
        "last_anchor_height": anchor_height,
        "needs_anchor": needs_anchor,
        "anchor_threshold": 10,
        "recommendation": if unanchored >= 10 { "anchor now" } else if unanchored > 0 { "anchor when convenient" } else { "up to date" },
    })))
}

async fn miner_dashboard(
    State(state): State<AppState>,
    Path(wallet_hash): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let miners = state
        .db
        .get_miners_by_wallet_hash(&wallet_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if miners.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "No miners assigned to this wallet".to_string(),
        ));
    }

    // Build HTML for each miner card
    let mut miners_html = String::new();
    for (_wallet_addr, serial, foreman_id) in &miners {
        let (status, color, hr, temp, pool, seen) =
            if let (Some(foreman), Some(mid)) = (&state.foreman, foreman_id) {
                match foreman.get_miner(*mid).await {
                    Ok(Some(m)) => {
                        let c = match m.status.as_str() {
                            "mining" | "hashing" => "#3d9b8f",
                            "offline" | "error" => "#e74c3c",
                            _ => "#d4a843",
                        };
                        (
                            m.status.to_uppercase(),
                            c,
                            format!("{:.0}", m.hashrate),
                            m.temp.map(|t| format!("{:.0}C", t)).unwrap_or("--".into()),
                            m.pool.unwrap_or("--".into()),
                            m.last_seen.unwrap_or("--".into()),
                        )
                    }
                    _ => (
                        "PENDING".into(),
                        "#d4a843",
                        "--".into(),
                        "--".into(),
                        "--".into(),
                        "--".into(),
                    ),
                }
            } else {
                (
                    "AWAITING DEPLOYMENT".into(),
                    "#d4a843",
                    "--".into(),
                    "--".into(),
                    "--".into(),
                    "--".into(),
                )
            };

        miners_html.push_str(&format!(
            r#"<div class="miner-card">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <span style="font-size:13px;font-weight:600;color:#e2e4e8;font-family:monospace">{serial}</span>
    <span class="miner-status" style="color:{color};border:1px solid {color}30;background:{color}08">{status}</span>
  </div>
  <div class="miner-stats">
    <div class="stat"><div class="stat-value">{hr}</div><div class="stat-label">KH/s</div></div>
    <div class="stat"><div class="stat-value">{temp}</div><div class="stat-label">Temp</div></div>
    <div class="stat"><div class="stat-value">Z15P</div><div class="stat-label">Model</div></div>
  </div>
  <div class="miner-detail"><span class="label">Pool</span><span class="value">{pool}</span></div>
  <div class="miner-detail"><span class="label">Last seen</span><span class="value">{seen}</span></div>
</div>"#
        ));
    }

    // Build billing HTML from invoices linked to this wallet
    let invoices = state
        .db
        .get_invoices_by_wallet(&wallet_hash)
        .unwrap_or_default();
    let mut billing_html = String::new();
    if invoices.is_empty() {
        billing_html.push_str(r#"<div style="color:#4a5168;font-size:12px;text-align:center;padding:16px">No invoices yet. Billing starts when your miner is deployed.</div>"#);
    } else {
        for inv in &invoices {
            let amt = inv.amount_zat as f64 / 100_000_000.0;
            let status_class = if inv.status == crate::models::InvoiceStatus::Paid {
                "paid"
            } else {
                "pending"
            };
            let status_label = inv.status.as_str().to_uppercase();
            let pay_link = if inv.status != crate::models::InvoiceStatus::Paid {
                format!(r#"<a class="pay-btn" href="/pay/{}">Pay</a>"#, inv.id)
            } else {
                String::new()
            };
            let memo = html_escape(inv.memo.as_deref().unwrap_or(""));
            billing_html.push_str(&format!(
                r#"<div class="invoice-row">
  <div><div style="color:#e2e4e8">{:.4} ZEC</div><div style="color:#4a5168;font-size:9px;margin-top:2px">{memo}</div></div>
  <div style="display:flex;align-items:center;gap:10px"><span class="invoice-status {status_class}">{status_label}</span>{pay_link}</div>
</div>"#, amt
            ));
        }
    }

    let is_testnet = matches!(
        state.config.network,
        zcash_protocol::consensus::Network::TestNetwork
    );
    let testnet_banner = if is_testnet {
        r#"<div style="position:fixed;top:0;left:0;right:0;background:#e74c3c;color:#fff;text-align:center;padding:8px;font-size:12px;font-weight:600;letter-spacing:0.1em;z-index:100">TESTNET</div>"#
    } else {
        ""
    };
    let testnet_title = if is_testnet { " (Testnet)" } else { "" };
    let wallet_short = if wallet_hash.len() > 14 {
        format!(
            "{}...{}",
            &wallet_hash[..wallet_hash.len().min(8)],
            &wallet_hash[wallet_hash.len().saturating_sub(6)..]
        )
    } else {
        wallet_hash.clone()
    };

    // Cohort stats (compute first so we can use tier for revenue math)
    let total_machines = state.db.count_total_machines().unwrap_or(0);
    let kw_per_machine = 2.78;
    let total_kw = total_machines as f64 * kw_per_machine;
    let at_discount_tier = total_kw >= 80.0;
    let current_tier = if at_discount_tier {
        "$0.09/kWh"
    } else {
        "$0.10/kWh"
    };
    let machines_to_next = if !at_discount_tier {
        ((80.0 - total_kw) / kw_per_machine).ceil() as u32
    } else {
        0
    };
    let tier_progress = ((total_kw / 80.0) * 100.0).min(100.0) as u32;

    // Revenue estimates - tier-aware
    let num_miners = miners.len();
    let hosting_per_machine = if at_discount_tier { 182.0 } else { 202.0 }; // ~$0.09 vs ~$0.10 effective
    let zec_per_month = num_miners as f64 * 2.6;
    let zec_per_year = zec_per_month * 12.0;
    let hosting_monthly = num_miners as f64 * hosting_per_machine;
    let total_3yr_cost =
        (5499.0 * num_miners as f64) + (hosting_monthly * 36.0) + (299.0 * 2.0 * num_miners as f64);
    let total_zec_3yr = zec_per_month * 36.0;
    let cost_per_zec = if total_zec_3yr > 0.0 {
        (total_3yr_cost / total_zec_3yr).round() as u32
    } else {
        0
    };

    let html = include_str!("miner_page.html")
        .replace("{TESTNET_TITLE}", testnet_title)
        .replace("{TESTNET_BANNER}", testnet_banner)
        .replace("{WALLET_SHORT}", &wallet_short)
        .replace("{MINERS_HTML}", &miners_html)
        .replace("{BILLING_HTML}", &billing_html)
        .replace("{ZEC_PER_MONTH}", &format!("{:.1}", zec_per_month))
        .replace("{ZEC_PER_YEAR}", &format!("{:.0}", zec_per_year))
        .replace("{COST_PER_ZEC}", &cost_per_zec.to_string())
        .replace("{MONTHLY_HOSTING}", &format!("{:.0}", hosting_monthly))
        .replace("{TOTAL_MACHINES}", &total_machines.to_string())
        .replace("{CURRENT_TIER}", current_tier)
        .replace("{MACHINES_TO_NEXT}", &machines_to_next.to_string())
        .replace("{NEXT_TIER}", "$0.09/kWh")
        .replace("{TIER_PROGRESS}", &tier_progress.to_string())
        .replace(
            "{REFRESH_SCRIPT}",
            r#"<script>setTimeout(()=>location.reload(),60000)</script>"#,
        );

    Ok(Html(html))
}

async fn miner_status_json(
    State(state): State<AppState>,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let assignment = state
        .db
        .get_miner_by_wallet_hash(&wallet_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Not found".to_string()))?;

    let (_wallet, serial, foreman_id) = assignment;

    let miner_data = if let (Some(foreman), Some(miner_id)) = (&state.foreman, foreman_id) {
        foreman.get_miner(miner_id).await.ok().flatten()
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "serial": serial,
        "wallet_hash": wallet_hash,
        "status": miner_data.as_ref().map(|m| m.status.as_str()).unwrap_or("pending"),
        "hashrate": miner_data.as_ref().map(|m| m.hashrate).unwrap_or(0.0),
        "temp": miner_data.as_ref().and_then(|m| m.temp),
        "pool": miner_data.as_ref().and_then(|m| m.pool.as_deref()),
        "last_seen": miner_data.as_ref().and_then(|m| m.last_seen.as_deref()),
    })))
}

#[derive(Deserialize)]
struct AssignMinerRequest {
    wallet_hash: String,
    wallet_address: String,
    serial_number: String,
    foreman_miner_id: Option<u64>,
}

async fn assign_miner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AssignMinerRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    state
        .db
        .assign_miner(
            &req.wallet_hash,
            &req.wallet_address,
            &req.serial_number,
            req.foreman_miner_id,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (leaf, root) = state
        .db
        .insert_ownership_leaf(&req.wallet_hash, &req.serial_number)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "assigned",
            "wallet_hash": req.wallet_hash,
            "serial": req.serial_number,
            "leaf_hash": leaf.leaf_hash,
            "root_hash": root.root_hash,
            "verify_url": format!("/verify/{}", leaf.leaf_hash),
        })),
    ))
}

/// Viewing key verification endpoint.
/// Provides the participant with information to independently verify
/// their mining payouts without trusting our dashboard.
async fn viewing_key_info(
    State(state): State<AppState>,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let miners = state
        .db
        .get_miners_by_wallet_hash(&wallet_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if miners.is_empty() {
        return Err((StatusCode::NOT_FOUND, "No miners assigned".to_string()));
    }

    // Show ownership attestation info, not the program UFVK.
    // Exposing the UFVK would let any participant see ALL payment volumes.
    let miner_info: Vec<serde_json::Value> = miners
        .iter()
        .map(|(_, serial, _)| {
            let leaf_hash = hex::encode(crate::memo::hash_ownership_attest(&wallet_hash, serial));
            serde_json::json!({
                "serial": serial,
                "verify_url": format!("/verify/{}", leaf_hash),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "wallet_hash": wallet_hash,
        "verification_method": "On-chain cryptographic ownership attestation",
        "note": "Each miner assignment is committed to a BLAKE2b Merkle tree anchored on Zcash. Use the verify links below to check your ownership proof independently.",
        "miners": miner_info,
    })))
}

async fn verify_page(
    State(state): State<AppState>,
    Path(leaf_hash): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let bundle = state
        .db
        .get_verification_bundle(&leaf_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Verification record not found".to_string(),
        ))?;

    let serial = bundle
        .leaf
        .serial_number
        .as_deref()
        .unwrap_or("Not assigned yet");
    let wallet_short = if bundle.leaf.wallet_hash.len() > 14 {
        format!(
            "{}...{}",
            &bundle.leaf.wallet_hash[..bundle.leaf.wallet_hash.len().min(8)],
            &bundle.leaf.wallet_hash[bundle.leaf.wallet_hash.len().saturating_sub(6)..]
        )
    } else {
        bundle.leaf.wallet_hash.clone()
    };

    let proof_json = serde_json::to_string_pretty(&bundle.proof)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let event_label = bundle.leaf.event_type.label();
    let explorer_link = bundle
        .root
        .anchor_txid
        .as_deref()
        .map(|txid| {
            if matches!(
                state.config.network,
                zcash_protocol::consensus::Network::MainNetwork
            ) {
                format!("https://blockchair.com/zcash/transaction/{txid}")
            } else {
                String::new()
            }
        })
        .filter(|link| !link.is_empty())
        .unwrap_or_default();
    let anchor_link = match bundle.root.anchor_txid.as_deref() {
        Some(txid) if !explorer_link.is_empty() => {
            format!(
                r#"<a class="txid-link" href="{explorer_link}" target="_blank" rel="noopener noreferrer">{txid}</a>"#
            )
        }
        Some(txid) => txid.to_string(),
        None => "Pending anchor".to_string(),
    };
    let anchor_height = bundle
        .root
        .anchor_height
        .map(|height| height.to_string())
        .unwrap_or_else(|| "Pending confirmation".to_string());

    let html = include_str!("verify_page.html")
        .replace("{LEAF_HASH}", &bundle.leaf.leaf_hash)
        .replace("{EVENT_TYPE}", event_label)
        .replace("{SERIAL}", serial)
        .replace("{WALLET_SHORT}", &wallet_short)
        .replace("{ROOT_HASH}", &bundle.root.root_hash)
        .replace("{LEAF_COUNT}", &bundle.root.leaf_count.to_string())
        .replace("{ANCHOR_TXID}", &anchor_link)
        .replace("{ANCHOR_HEIGHT}", &anchor_height)
        .replace("{PROOF_JSON}", &proof_json)
        .replace("{LEAF_CREATED_AT}", &bundle.leaf.created_at)
        .replace("{ROOT_CREATED_AT}", &bundle.root.created_at)
        .replace(
            "{VERIFY_NOTE}",
            "This audit and commitment layer lets anyone verify without trusting the operator.",
        );

    Ok(Html(html))
}

/// Downloadable JSON proof bundle for independent verification.
async fn proof_bundle_json(
    State(state): State<AppState>,
    Path(leaf_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bundle = state
        .db
        .get_verification_bundle(&leaf_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Leaf not found".to_string()))?;

    let proof_steps: Vec<serde_json::Value> = bundle.proof.iter().map(|s| {
        serde_json::json!({ "hash": s.hash, "position": format!("{:?}", s.position).to_lowercase() })
    }).collect();

    Ok(Json(serde_json::json!({
        "protocol": "ZAP1",
        "version": "2",
        "leaf": {
            "hash": bundle.leaf.leaf_hash,
            "event_type": bundle.leaf.event_type.label(),
            "wallet_hash": bundle.leaf.wallet_hash,
            "serial_number": bundle.leaf.serial_number,
            "created_at": bundle.leaf.created_at,
        },
        "proof": proof_steps,
        "root": {
            "hash": bundle.root.root_hash,
            "leaf_count": bundle.root.leaf_count,
            "created_at": bundle.root.created_at,
        },
        "anchor": {
            "txid": bundle.root.anchor_txid,
            "height": bundle.root.anchor_height,
        },
        "verify_command": format!(
            "python3 verify_proof.py --wallet-hash {} {} --proof proof.json --root {}",
            bundle.leaf.wallet_hash,
            bundle.leaf.serial_number.as_ref().map(|s| format!("--serial {}", s)).unwrap_or_default(),
            bundle.root.root_hash
        ),
    })))
}

/// Server-side Merkle proof verification using zap1-verify SDK.
async fn verify_check(
    State(state): State<AppState>,
    Path(leaf_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bundle = state
        .db
        .get_verification_bundle(&leaf_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Leaf not found".to_string()))?;

    // Convert proof steps to zap1_verify types
    let leaf_bytes = zap1_verify::hex_to_bytes32(&bundle.leaf.leaf_hash)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid leaf hash hex".to_string()))?;
    let root_bytes = zap1_verify::hex_to_bytes32(&bundle.root.root_hash)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid root hash hex".to_string()))?;

    let proof_steps: Vec<zap1_verify::ProofStep> = bundle
        .proof
        .iter()
        .map(|s| {
            let hash = zap1_verify::hex_to_bytes32(&s.hash).unwrap_or([0u8; 32]);
            let position = match format!("{:?}", s.position).to_lowercase().as_str() {
                "left" => zap1_verify::SiblingPosition::Left,
                _ => zap1_verify::SiblingPosition::Right,
            };
            zap1_verify::ProofStep { hash, position }
        })
        .collect();

    let valid = zap1_verify::verify_proof(&leaf_bytes, &proof_steps, &root_bytes);

    Ok(Json(serde_json::json!({
        "protocol": "ZAP1",
        "valid": valid,
        "leaf_hash": bundle.leaf.leaf_hash,
        "event_type": bundle.leaf.event_type.label(),
        "root": bundle.root.root_hash,
        "anchor": {
            "txid": bundle.root.anchor_txid,
            "height": bundle.root.anchor_height,
        },
        "server_verified": true,
        "verification_sdk": "zap1-verify",
    })))
}

/// Anchor history for auditors and validators.
async fn anchor_history(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let roots = state
        .db
        .all_anchored_roots()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let anchors: Vec<serde_json::Value> = roots
        .iter()
        .filter(|r| r.anchor_txid.is_some())
        .map(|r| {
            serde_json::json!({
                "root": r.root_hash,
                "txid": r.anchor_txid,
                "height": r.anchor_height,
                "leaf_count": r.leaf_count,
                "created_at": r.created_at,
            })
        })
        .collect();

    let total = anchors.len();
    let last_anchor_age_hours = roots
        .iter()
        .filter(|r| r.anchor_txid.is_some())
        .last()
        .and_then(|r| chrono::DateTime::parse_from_rfc3339(&r.created_at).ok())
        .map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_hours())
        .unwrap_or(-1);

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "total": total,
        "last_anchor_age_hours": last_anchor_age_hours,
    })))
}

/// Recent attestation events. Discoverable feed for explorers and indexers.
async fn recent_events(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);

    let leaves = state
        .db
        .list_recent_leaves(limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let events: Vec<serde_json::Value> = leaves
        .iter()
        .map(|l| {
            serde_json::json!({
                "leaf_hash": l.leaf_hash,
                "event_type": l.event_type.label(),
                "description": match l.event_type.label() {
                    "PROGRAM_ENTRY" => "Operator registration",
                    "OWNERSHIP_ATTEST" => "Ownership attestation",
                    "CONTRACT_ANCHOR" => "Contract hash anchored",
                    "DEPLOYMENT" => "Hardware deployment",
                    "HOSTING_PAYMENT" => "Hosting payment recorded",
                    "SHIELD_RENEWAL" => "Shield renewed",
                    "TRANSFER" => "Ownership transferred",
                    "EXIT" => "Hardware decommissioned",
                    "MERKLE_ROOT" => "Merkle root anchor",
                    "STAKING_DEPOSIT" => "Staking deposit",
                    "STAKING_WITHDRAW" => "Staking withdrawal",
                    "STAKING_REWARD" => "Staking reward",
                    "GOVERNANCE_PROPOSAL" => "Governance proposal",
                    "GOVERNANCE_VOTE" => "Governance vote",
                    "GOVERNANCE_RESULT" => "Governance result",
                    "AGENT_REGISTER" => "Agent registered",
                    "AGENT_POLICY" => "Agent policy committed",
                    "AGENT_ACTION" => "Agent action attested",
                    _ => "Unknown event",
                },
                "wallet_hash": l.wallet_hash,
                "serial_number": l.serial_number,
                "created_at": l.created_at,
                "verify_url": format!("/verify/{}", l.leaf_hash),
                "proof_url": format!("/verify/{}/proof.json", l.leaf_hash),
                "badge_url": format!("/badge/leaf/{}", l.leaf_hash),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "protocol": "ZAP1",
        "total_returned": events.len(),
        "events": events,
    })))
}

/// Protocol metadata for ecosystem discovery.
async fn protocol_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "protocol": "ZAP1",
        "version": "3.0.0",
        "event_types": 18,
        "deployed_types": 15,
        "reserved_types": 3,
        "hash_function": "BLAKE2b-256",
        "leaf_personalization": "NordicShield_",
        "node_personalization": "NordicShield_MRK",
        "verification_sdk": "zap1-verify (Rust + WASM)",
        "verification_sdk_repo": "https://github.com/Frontier-Compute/zap1-verify",
        "frost_status": "design_complete",
        "frost_ciphersuite": "FROST(Pallas, BLAKE2b-512)",
        "frost_threshold": "2-of-3",
        "zip_status": "draft",
        "specification": "https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md",
    }))
}

fn svg_badge(label: &str, value: &str, color: &str) -> String {
    let label_width = label.len() as u32 * 7 + 12;
    let value_width = value.len() as u32 * 7 + 12;
    let total_width = label_width + value_width;
    let lx = label_width / 2;
    let vx = label_width + value_width / 2;
    let mut svg = String::with_capacity(1024);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"20\" role=\"img\">",
        total_width
    ));
    svg.push_str("<linearGradient id=\"s\" x2=\"0\" y2=\"100%\"><stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/><stop offset=\"1\" stop-opacity=\".1\"/></linearGradient>");
    svg.push_str(&format!(
        "<clipPath id=\"r\"><rect width=\"{}\" height=\"20\" rx=\"3\" fill=\"#fff\"/></clipPath>",
        total_width
    ));
    svg.push_str("<g clip-path=\"url(#r)\">");
    svg.push_str(&format!(
        "<rect width=\"{}\" height=\"20\" fill=\"#555\"/>",
        label_width
    ));
    svg.push_str(&format!(
        "<rect x=\"{}\" width=\"{}\" height=\"20\" fill=\"{}\"/>",
        label_width, value_width, color
    ));
    svg.push_str(&format!(
        "<rect width=\"{}\" height=\"20\" fill=\"url(#s)\"/>",
        total_width
    ));
    svg.push_str("</g>");
    svg.push_str("<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,sans-serif\" font-size=\"11\">");
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{}</text>",
        lx, label
    ));
    svg.push_str(&format!("<text x=\"{}\" y=\"14\">{}</text>", lx, label));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{}</text>",
        vx, value
    ));
    svg.push_str(&format!("<text x=\"{}\" y=\"14\">{}</text>", vx, value));
    svg.push_str("</g></svg>");
    svg
}

/// Dynamic SVG badge showing protocol status.
/// Embed: ![ZAP1](https://pay.frontiercompute.io/badge/status.svg)
async fn badge_status(
    State(state): State<AppState>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 2],
    String,
) {
    let (leaves, anchors) = match (state.db.total_leaf_count(), state.db.all_anchored_roots()) {
        (Ok(l), Ok(roots)) => {
            let anchor_count = roots.iter().filter(|r| r.anchor_txid.is_some()).count();
            (l, anchor_count)
        }
        _ => (0, 0),
    };

    let svg = svg_badge(
        "ZAP1",
        &format!("{} leaves | {} anchors", leaves, anchors),
        "#c8a84e",
    );

    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "max-age=300"),
        ],
        svg,
    )
}

/// Dynamic SVG badge for a specific leaf.
async fn badge_leaf(
    State(state): State<AppState>,
    Path(leaf_hash): Path<String>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 2],
    String,
) {
    let exists = state
        .db
        .get_verification_bundle(&leaf_hash)
        .ok()
        .flatten()
        .is_some();

    let (value, color) = if exists {
        ("verified", "#4c1")
    } else {
        ("not found", "#e05d44")
    };

    let svg = svg_badge("ZAP1 leaf", value, color);

    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "max-age=300"),
        ],
        svg,
    )
}

/// Dynamic SVG badge for a specific anchor, looked up by txid prefix.
async fn badge_anchor(
    State(state): State<AppState>,
    Path(txid_prefix): Path<String>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 2],
    String,
) {
    let prefix = txid_prefix.to_lowercase();
    if prefix.len() < 8 || prefix.len() > 16 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        let svg = svg_badge("ZAP1", "invalid prefix", "#e05d44");
        return (
            StatusCode::BAD_REQUEST,
            [
                (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            svg,
        );
    }

    let found = state
        .db
        .all_anchored_roots()
        .unwrap_or_default()
        .into_iter()
        .find(|r| {
            r.anchor_txid
                .as_deref()
                .map(|t| t.starts_with(&prefix))
                .unwrap_or(false)
        });

    let (value, color) = match found {
        Some(r) => match r.anchor_height {
            Some(h) => (format!("anchored at block {}", h), "#4c1".to_string()),
            None => ("anchored (unconfirmed)".to_string(), "#c8a84e".to_string()),
        },
        None => ("anchor not found".to_string(), "#e05d44".to_string()),
    };

    let svg = svg_badge("ZAP1", &value, &color);

    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "max-age=300"),
        ],
        svg,
    )
}

/// Build provenance: version, dependencies, reproducibility metadata.
async fn build_info() -> Json<serde_json::Value> {
    let build_info = std::fs::read_to_string("/usr/local/share/zap1/BUILD_INFO")
        .unwrap_or_else(|_| "not available (dev build)".to_string());
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "librustzcash_rev": "1f736379a4099ef1ba3b3bff4035c725e28a018a",
        "deterministic_build": {
            "source_date_epoch": std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "unset".to_string()),
            "path_remapping": true,
            "cargo_lock": true,
            "note": "Follows StageX/Zaino approach SOURCE_DATE_EPOCH eliminates timestamp non-determinism. RUSTFLAGS --remap-path-prefix strips build paths."
        },
        "supply_chain": {
            "dependency_pinning": "git rev (Cargo.toml [patch.crates-io])",
            "lock_file": "Cargo.lock committed",
            "verification": "cargo build --locked reproduces the same binary given the same toolchain"
        },
        "build_metadata": build_info.trim(),
    }))
}

async fn list_webhooks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    let hooks = state
        .db
        .list_webhooks()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<serde_json::Value> = hooks
        .iter()
        .map(|h| serde_json::json!({ "id": h.id, "url": h.url }))
        .collect();
    Ok(Json(
        serde_json::json!({ "webhooks": items, "count": items.len() }),
    ))
}

#[derive(serde::Deserialize)]
struct RegisterWebhookRequest {
    url: String,
}

async fn register_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    let id = uuid::Uuid::new_v4().to_string();
    let secret = uuid::Uuid::new_v4().to_string().replace('-', "");
    state
        .db
        .register_webhook(&id, &req.url, &secret)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "url": req.url,
            "secret": secret,
            "note": "Store the secret. Use it to verify X-ZAP1-Signature headers on deliveries.",
        })),
    ))
}

async fn delete_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
    let deleted = state
        .db
        .delete_webhook(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()))
    }
}

#[derive(Deserialize)]
struct CreateEventRequest {
    event_type: String,
    wallet_hash: String,
    serial_number: Option<String>,
    // Type-specific fields
    contract_sha256: Option<String>,
    facility_id: Option<String>,
    month: Option<u32>,
    year: Option<u32>,
    new_wallet_hash: Option<String>,
    amount_zat: Option<u64>,
    validator_id: Option<String>,
    epoch: Option<u32>,
    proposal_id: Option<String>,
    proposal_hash: Option<String>,
    vote_commitment: Option<String>,
    result_hash: Option<String>,
    // Agent fields
    agent_id: Option<String>,
    pubkey_hash: Option<String>,
    model_hash: Option<String>,
    policy_hash: Option<String>,
    policy_version: Option<u32>,
    rules_hash: Option<String>,
    action_type: Option<String>,
    input_hash: Option<String>,
    output_hash: Option<String>,
}

async fn create_lifecycle_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateEventRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;

    // Validate wallet_hash: 1-128 chars, alphanumeric + underscore + hyphen
    if req.wallet_hash.is_empty() || req.wallet_hash.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "wallet_hash must be 1-128 characters".to_string()));
    }
    if !req.wallet_hash.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err((StatusCode::BAD_REQUEST, "wallet_hash must be alphanumeric, underscore, or hyphen".to_string()));
    }

    let now_ts = chrono::Utc::now().timestamp() as u64;

    let (leaf, root) = match req.event_type.as_str() {
        "CONTRACT_ANCHOR" => {
            let serial = req
                .serial_number
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "serial_number required".into()))?;
            let sha = req
                .contract_sha256
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "contract_sha256 required".into()))?;
            state
                .db
                .insert_contract_anchor_leaf(&req.wallet_hash, serial, sha)
        }
        "DEPLOYMENT" => {
            let serial = req
                .serial_number
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "serial_number required".into()))?;
            let facility = req
                .facility_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "facility_id required".into()))?;
            state
                .db
                .insert_deployment_leaf(&req.wallet_hash, serial, facility, now_ts)
        }
        "HOSTING_PAYMENT" => {
            let serial = req
                .serial_number
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "serial_number required".into()))?;
            let month = req
                .month
                .ok_or((StatusCode::BAD_REQUEST, "month required".into()))?;
            if !(1..=12).contains(&month) {
                return Err((StatusCode::BAD_REQUEST, "month must be 1-12".into()));
            }
            let year = req
                .year
                .ok_or((StatusCode::BAD_REQUEST, "year required".into()))?;
            if !(2020..=2100).contains(&year) {
                return Err((StatusCode::BAD_REQUEST, "year must be 2020-2100".into()));
            }
            state
                .db
                .insert_hosting_payment_leaf(&req.wallet_hash, serial, month, year)
        }
        "SHIELD_RENEWAL" => {
            let year = req
                .year
                .ok_or((StatusCode::BAD_REQUEST, "year required".into()))?;
            state.db.insert_shield_renewal_leaf(&req.wallet_hash, year)
        }
        "TRANSFER" => {
            let serial = req
                .serial_number
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "serial_number required".into()))?;
            let new_wallet = req
                .new_wallet_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "new_wallet_hash required".into()))?;
            state
                .db
                .insert_transfer_leaf(&req.wallet_hash, new_wallet, serial)
        }
        "EXIT" => {
            let serial = req
                .serial_number
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "serial_number required".into()))?;
            state.db.insert_exit_leaf(&req.wallet_hash, serial, now_ts)
        }
        "STAKING_DEPOSIT" => {
            let amount = req
                .amount_zat
                .ok_or((StatusCode::BAD_REQUEST, "amount_zat required".into()))?;
            let validator = req
                .validator_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "validator_id required".into()))?;
            state
                .db
                .insert_staking_deposit_leaf(&req.wallet_hash, amount, validator)
        }
        "STAKING_WITHDRAW" => {
            let amount = req
                .amount_zat
                .ok_or((StatusCode::BAD_REQUEST, "amount_zat required".into()))?;
            let validator = req
                .validator_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "validator_id required".into()))?;
            state
                .db
                .insert_staking_withdraw_leaf(&req.wallet_hash, amount, validator)
        }
        "STAKING_REWARD" => {
            let amount = req
                .amount_zat
                .ok_or((StatusCode::BAD_REQUEST, "amount_zat required".into()))?;
            let epoch = req
                .epoch
                .ok_or((StatusCode::BAD_REQUEST, "epoch required".into()))?;
            state
                .db
                .insert_staking_reward_leaf(&req.wallet_hash, amount, epoch)
        }
        "GOVERNANCE_PROPOSAL" => {
            let pid = req
                .proposal_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "proposal_id required".into()))?;
            let phash = req
                .proposal_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "proposal_hash required".into()))?;
            state
                .db
                .insert_governance_proposal_leaf(&req.wallet_hash, pid, phash)
        }
        "GOVERNANCE_VOTE" => {
            let pid = req
                .proposal_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "proposal_id required".into()))?;
            let vc = req
                .vote_commitment
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "vote_commitment required".into()))?;
            state
                .db
                .insert_governance_vote_leaf(&req.wallet_hash, pid, vc)
        }
        "GOVERNANCE_RESULT" => {
            let pid = req
                .proposal_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "proposal_id required".into()))?;
            let rh = req
                .result_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "result_hash required".into()))?;
            state
                .db
                .insert_governance_result_leaf(&req.wallet_hash, pid, rh)
        }
        "AGENT_REGISTER" => {
            let aid = req
                .agent_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "agent_id required".into()))?;
            let pk = req
                .pubkey_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "pubkey_hash required".into()))?;
            let mh = req
                .model_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "model_hash required".into()))?;
            let ph = req
                .policy_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "policy_hash required".into()))?;
            state.db.insert_agent_register_leaf(aid, pk, mh, ph)
        }
        "AGENT_POLICY" => {
            let aid = req
                .agent_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "agent_id required".into()))?;
            let pv = req
                .policy_version
                .ok_or((StatusCode::BAD_REQUEST, "policy_version required".into()))?;
            let rh = req
                .rules_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "rules_hash required".into()))?;
            state.db.insert_agent_policy_leaf(aid, pv, rh)
        }
        "AGENT_ACTION" => {
            let aid = req
                .agent_id
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "agent_id required".into()))?;
            let at = req
                .action_type
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "action_type required".into()))?;
            let ih = req
                .input_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "input_hash required".into()))?;
            let oh = req
                .output_hash
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "output_hash required".into()))?;
            state.db.insert_agent_action_leaf(aid, at, ih, oh)
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported event_type: {other}"),
            ));
        }
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(
        "Lifecycle event {} for wallet {}",
        req.event_type,
        req.wallet_hash
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created",
            "event_type": req.event_type,
            "wallet_hash": req.wallet_hash,
            "leaf_hash": leaf.leaf_hash,
            "root_hash": root.root_hash,
            "verify_url": format!("/verify/{}", leaf.leaf_hash),
        })),
    ))
}

async fn lifecycle(
    State(state): State<AppState>,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let leaves = state
        .db
        .get_leaves_by_wallet(&wallet_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if leaves.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "No events for this wallet".to_string(),
        ));
    }

    let events: Vec<serde_json::Value> = leaves
        .iter()
        .map(|leaf| {
            let anchor = state
                .db
                .get_root_covering_leaf(&leaf.leaf_hash)
                .ok()
                .flatten();
            serde_json::json!({
                "leaf_hash": leaf.leaf_hash,
                "event_type": leaf.event_type.label(),
                "serial_number": leaf.serial_number,
                "created_at": leaf.created_at,
                "anchor_txid": anchor.as_ref().and_then(|a| a.anchor_txid.as_deref()),
                "anchor_height": anchor.as_ref().and_then(|a| a.anchor_height),
                "anchored": anchor.is_some(),
                "verify_url": format!("/verify/{}", leaf.leaf_hash),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "wallet_hash": wallet_hash,
        "event_count": events.len(),
        "events": events,
    })))
}

async fn stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (total_leaves, total_anchors, first_height, last_height) = state
        .db
        .get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let network = format!("{:?}", state.config.network);

    let type_names = [
        (1, "PROGRAM_ENTRY"),
        (2, "OWNERSHIP_ATTEST"),
        (3, "CONTRACT_ANCHOR"),
        (4, "DEPLOYMENT"),
        (5, "HOSTING_PAYMENT"),
        (6, "SHIELD_RENEWAL"),
        (7, "TRANSFER"),
        (8, "EXIT"),
        (9, "MERKLE_ROOT"),
        (10, "STAKING_DEPOSIT"),
        (11, "STAKING_WITHDRAW"),
        (12, "STAKING_REWARD"),
        (13, "GOVERNANCE_PROPOSAL"),
        (14, "GOVERNANCE_VOTE"),
        (15, "GOVERNANCE_RESULT"),
        (64, "AGENT_REGISTER"),
        (65, "AGENT_POLICY"),
        (66, "AGENT_ACTION"),
    ];
    let db_counts = state.db.leaf_counts_by_type().unwrap_or_default();
    let mut type_counts = serde_json::Map::new();
    for (id, name) in &type_names {
        let count = db_counts
            .iter()
            .find(|(t, _)| t == id)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        type_counts.insert(name.to_string(), serde_json::json!(count));
    }

    Ok(Json(serde_json::json!({
        "total_leaves": total_leaves,
        "total_anchors": total_anchors,
        "first_anchor_block": first_height,
        "last_anchor_block": last_height,
        "network": network,
        "protocol": "ZAP1",
        "event_types": type_names.iter().map(|(_, n)| n).collect::<Vec<_>>(),
        "type_counts": type_counts,
    })))
}

#[derive(Deserialize)]
struct AutoInvoiceRequest {
    amount_zec: f64,
    month: u32,
    year: u32,
    expires_in_hours: Option<u64>,
}

async fn auto_invoice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AutoInvoiceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;

    if !(1..=12).contains(&req.month) {
        return Err((StatusCode::BAD_REQUEST, "month must be 1-12".into()));
    }
    if !(2020..=2100).contains(&req.year) {
        return Err((StatusCode::BAD_REQUEST, "year must be 2020-2100".into()));
    }

    let miners = state
        .db
        .list_miner_assignments()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Aggregate by wallet: count machines per wallet
    let mut wallet_machines: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (wallet_hash, _wallet_address, serial, _foreman_id) in &miners {
        wallet_machines
            .entry(wallet_hash.clone())
            .or_default()
            .push(serial.clone());
    }

    let mut created = Vec::new();
    let mut skipped = Vec::new();

    for (wallet_hash, serials) in &wallet_machines {
        let machine_count = serials.len();

        // Skip if invoice already exists for this month
        let exists = state
            .db
            .has_hosting_invoice(wallet_hash, req.month, req.year)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if exists {
            skipped.push(wallet_hash.clone());
            continue;
        }

        let div_idx = state
            .db
            .allocate_diversifier_index()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let address =
            crate::keys::address_for_index_encoded(&state.ufvk, &state.config.network, div_idx)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Multiply by machine count
        let amount_zat = (req.amount_zec * machine_count as f64 * 100_000_000.0).round() as u64;
        let now = chrono::Utc::now();
        let expires_at = req
            .expires_in_hours
            .unwrap_or(168) // default 7 days
            .min(720); // max 30 days
        let expires = (now + chrono::Duration::hours(expires_at as i64)).to_rfc3339();

        let memo = format!(
            "NS-hosting-{}-{:02}-{}-{}x",
            req.year, req.month, wallet_hash, machine_count
        );

        let invoice = Invoice {
            id: uuid::Uuid::new_v4().to_string(),
            diversifier_index: div_idx,
            address,
            amount_zat,
            memo: Some(memo),
            invoice_type: "hosting".to_string(),
            wallet_hash: Some(wallet_hash.clone()),
            status: InvoiceStatus::Pending,
            received_zat: 0,
            created_at: now.to_rfc3339(),
            expires_at: Some(expires),
            paid_at: None,
            paid_txid: None,
            paid_height: None,
        };

        state
            .db
            .create_invoice(&invoice)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        tracing::info!(
            "Auto-invoice created: {} for {} ({}-{:02})",
            invoice.id,
            wallet_hash,
            req.year,
            req.month
        );

        // Signal notification
        let config = state.config.clone();
        let inv_clone = invoice.clone();
        tokio::spawn(async move {
            crate::notify::invoice_created(&config, &inv_clone).await;
        });

        created.push(serde_json::json!({
            "invoice_id": invoice.id,
            "wallet_hash": wallet_hash,
            "machines": machine_count,
            "serials": serials,
            "pay_url": format!("/pay/{}", invoice.id),
        }));
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "created": created.len(),
            "skipped": skipped.len(),
            "invoices": created,
            "period": format!("{}-{:02}", req.year, req.month),
        })),
    ))
}

async fn cohort_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let total_machines = state
        .db
        .count_total_machines()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let total_participants = state
        .db
        .count_active_miners()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (total_leaves, total_anchors, first_height, last_height) = state
        .db
        .get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Volume tier calculation
    let kwh_per_machine = 2.78; // Z15 Pro = 2780W
    let total_kw = total_machines as f64 * kwh_per_machine;
    let current_tier = if total_kw >= 80.0 {
        "$0.09/kWh"
    } else {
        "$0.10/kWh"
    };
    let machines_to_next_tier = if total_kw < 80.0 {
        ((80.0 - total_kw) / kwh_per_machine).ceil() as u32
    } else {
        0
    };

    // Total hashrate
    let hashrate_khs = total_machines as f64 * 840.0;

    Ok(Json(serde_json::json!({
        "total_machines": total_machines,
        "total_participants": total_participants,
        "total_hashrate_khs": hashrate_khs,
        "total_kw": total_kw,
        "current_tier": current_tier,
        "machines_to_next_tier": machines_to_next_tier,
        "next_tier": "$0.09/kWh",
        "total_leaves": total_leaves,
        "total_anchors": total_anchors,
        "first_anchor_block": first_height,
        "last_anchor_block": last_height,
        "zec_per_month_per_machine": 2.6,
        "estimated_total_zec_month": total_machines as f64 * 2.6,
    })))
}

async fn admin_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;

    let miners = state
        .db
        .list_miner_assignments()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let all_invoices = state
        .db
        .list_invoices(None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let pending_invoices: Vec<&Invoice> = all_invoices
        .iter()
        .filter(|i| i.status == InvoiceStatus::Pending)
        .collect();

    let overdue: Vec<serde_json::Value> = all_invoices
        .iter()
        .filter(|i| {
            i.status == InvoiceStatus::Pending
                && i.expires_at
                    .as_ref()
                    .map(|e| e.as_str() < chrono::Utc::now().to_rfc3339().as_str())
                    .unwrap_or(false)
        })
        .map(|i| {
            serde_json::json!({
                "invoice_id": i.id,
                "wallet_hash": i.wallet_hash,
                "amount_zec": i.amount_zat as f64 / 100_000_000.0,
                "type": i.invoice_type,
                "created": i.created_at,
                "expires": i.expires_at,
            })
        })
        .collect();

    let participants: Vec<serde_json::Value> = {
        let mut wallet_map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (wh, _wa, serial, _fid) in &miners {
            wallet_map
                .entry(wh.clone())
                .or_default()
                .push(serial.clone());
        }
        wallet_map
            .iter()
            .map(|(wh, serials)| {
                let wallet_invoices: Vec<&Invoice> = all_invoices
                    .iter()
                    .filter(|i| i.wallet_hash.as_deref() == Some(wh.as_str()))
                    .collect();
                let paid = wallet_invoices
                    .iter()
                    .filter(|i| i.status == InvoiceStatus::Paid)
                    .count();
                let pending = wallet_invoices
                    .iter()
                    .filter(|i| i.status == InvoiceStatus::Pending)
                    .count();
                serde_json::json!({
                    "wallet_hash": wh,
                    "machines": serials.len(),
                    "serials": serials,
                    "invoices_paid": paid,
                    "invoices_pending": pending,
                    "dashboard": format!("/miner/{}", wh),
                })
            })
            .collect()
    };

    let (total_leaves, total_anchors, _, _) = state
        .db
        .get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "participants": participants,
        "total_participants": participants.len(),
        "total_machines": miners.len(),
        "total_invoices": all_invoices.len(),
        "pending_invoices": pending_invoices.len(),
        "overdue_invoices": overdue.len(),
        "overdue": overdue,
        "total_leaves": total_leaves,
        "total_anchors": total_anchors,
    })))
}

/// Decode any Zcash shielded memo. POST hex-encoded memo bytes, get back format classification.
/// Uses zcash-memo-decode crate (zero deps, wallet-importable).
async fn memo_decode_endpoint(
    body: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hex_str = body.trim();
    if hex_str.len() > 2048 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "Memo hex limited to 1024 bytes (2048 hex chars)".to_string()));
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;

    let decoded = zcash_memo_decode::decode(&bytes);
    let fmt = zcash_memo_decode::label(&decoded);

    let result = match decoded {
        zcash_memo_decode::MemoFormat::Text(s) => serde_json::json!({
            "format": fmt,
            "text": s,
        }),
        zcash_memo_decode::MemoFormat::Attestation {
            protocol,
            event_type,
            event_label,
            payload_hash,
            raw,
        } => serde_json::json!({
            "format": fmt,
            "protocol": match protocol {
                zcash_memo_decode::AttestationProtocol::Zap1 => "ZAP1",
                zcash_memo_decode::AttestationProtocol::Nsm1Legacy => "NSM1",
            },
            "event_type": format!("0x{:02x}", event_type),
            "event_label": event_label,
            "payload_hash": hex::encode(payload_hash),
            "raw": raw,
        }),
        zcash_memo_decode::MemoFormat::Zip302Tvlv { parts } => {
            let parts_json: Vec<serde_json::Value> = parts
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "part_type": p.part_type,
                        "version": p.version,
                        "value_hex": hex::encode(&p.value),
                        "value_utf8": String::from_utf8(p.value.clone()).ok(),
                    })
                })
                .collect();
            serde_json::json!({
                "format": fmt,
                "parts": parts_json,
            })
        }
        zcash_memo_decode::MemoFormat::Empty => serde_json::json!({
            "format": fmt,
        }),
        zcash_memo_decode::MemoFormat::Binary(data) => serde_json::json!({
            "format": fmt,
            "length": data.len(),
            "hex": hex::encode(&data),
        }),
        zcash_memo_decode::MemoFormat::Unknown { first_byte, length } => serde_json::json!({
            "format": fmt,
            "first_byte": format!("0x{:02x}", first_byte),
            "length": length,
        }),
    };

    Ok(Json(result))
}

#[derive(Deserialize, Default)]
struct AdminQuery {
    key: Option<String>,
}

async fn admin_anchor_qr(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Accept key via header OR query param for browser access
    if let Some(expected) = &state.config.api_key {
        let header_ok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|k| k == expected)
            .unwrap_or(false);
        let query_ok = q.key.as_deref().map(|k| k == expected).unwrap_or(false);
        if !header_ok && !query_ok {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid or missing API key".into(),
            ));
        }
    }

    let root = state
        .db
        .current_merkle_root()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let unanchored = state
        .db
        .unanchored_leaf_count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let root = root.ok_or((StatusCode::BAD_REQUEST, "no Merkle root yet".into()))?;
    let addr = state.config.anchor_to_address.as_deref().ok_or((
        StatusCode::BAD_REQUEST,
        "ANCHOR_TO_ADDRESS not configured".into(),
    ))?;

    let memo_text = format!("ZAP1:09:{}", root.root_hash);
    let memo_hex = hex::encode(memo_text.as_bytes());
    let uri = format!("zcash:{}?amount=0.0001&memo={}", addr, memo_hex);
    let qr_svg = generate_qr_svg(&uri);

    let status = if root.anchor_txid.is_some() && unanchored == 0 {
        "up to date"
    } else {
        "needs anchor"
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anchor QR</title>
<style>
body {{ background:#0a0e17; color:#e2e4e8; font-family:monospace; display:flex; flex-direction:column; align-items:center; padding:40px 20px; }}
.qr {{ background:#fff; padding:16px; border-radius:8px; margin:24px 0; }}
.info {{ font-size:12px; color:#888; max-width:500px; word-break:break-all; text-align:center; line-height:1.6; }}
.status {{ font-size:14px; color:{}; margin-bottom:16px; }}
h1 {{ font-size:18px; margin-bottom:8px; }}
.memo {{ background:#1a1e27; padding:12px; border-radius:4px; font-size:11px; margin:16px 0; word-break:break-all; }}
form {{ margin-top:24px; display:flex; flex-direction:column; gap:8px; }}
input {{ background:#1a1e27; border:1px solid #333; color:#e2e4e8; padding:8px; border-radius:4px; font-family:monospace; font-size:12px; }}
button {{ background:#d4a843; color:#0a0e17; border:none; padding:10px 20px; border-radius:4px; font-weight:bold; cursor:pointer; }}
</style></head><body>
<h1>Anchor #{}</h1>
<div class="status">{}</div>
<div class="qr">{}</div>
<div class="info">
  <div>Root: {}</div>
  <div>Leaves: {} ({} unanchored)</div>
  <div class="memo">Memo: {}</div>
  <div>Scan with Zodl. Send 0.0001 ZEC.</div>
</div>
<form method="POST" action="/admin/anchor/record">
  <input type="hidden" name="root" value="{}">
  <input name="txid" placeholder="txid after send" required>
  <input name="height" type="number" placeholder="block height" required>
  <button type="submit">Record Anchor</button>
</form>
</body></html>"#,
        if status == "up to date" {
            "#4caf50"
        } else {
            "#d4a843"
        },
        root.leaf_count / 4 + 1,
        status,
        qr_svg,
        root.root_hash,
        root.leaf_count,
        unanchored,
        html_escape(&memo_text),
        root.root_hash,
    );

    Ok(Html(html))
}

#[derive(Deserialize)]
struct AnchorRecordForm {
    root: String,
    txid: String,
    height: u32,
}

async fn admin_anchor_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<AnchorRecordForm>,
) -> Result<Html<String>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;

    state
        .db
        .record_merkle_anchor(&form.root, &form.txid, Some(form.height))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3;url=/admin/anchor/qr">
<style>body {{ background:#0a0e17; color:#4caf50; font-family:monospace; display:flex; justify-content:center; align-items:center; height:100vh; }}</style>
</head><body>
<div>Anchor recorded. Root: {}...  Txid: {}...  Height: {}. Redirecting...</div>
</body></html>"#,
        &form.root[..16],
        &form.txid[..16],
        form.height,
    )))
}
