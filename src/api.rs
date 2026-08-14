use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Json},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

const DEFAULT_HEALTH_MAX_SYNC_LAG_BLOCKS: u32 = 10;

fn check_api_key(config: &Config, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    check_api_key_with_db(config, headers, None)
}

fn check_api_key_with_db(
    config: &Config,
    headers: &HeaderMap,
    db: Option<&crate::db::Db>,
) -> Result<(), (StatusCode, String)> {
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Invalid or missing API key".to_string(),
        ))?;

    if config
        .api_key
        .as_deref()
        .is_some_and(|expected| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
    {
        return Ok(());
    }

    // A configured master authority is the explicit switch that permits the
    // database-backed delegated-key plane. Missing API_KEY closes all writes,
    // including legacy trial credentials.
    if config.api_key.is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Write API is disabled".to_string(),
        ));
    }

    if let Some(db) = db {
        let hash = sha256_hex(provided);
        match db.consume_api_key_quota(&hash) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                tracing::error!("API-key quota check failed: {error:#}");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "API-key validation unavailable".to_string(),
                ));
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "Invalid or missing API key".to_string(),
    ))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
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

pub(crate) fn zatoshi_amount(amount_zat: u64) -> String {
    let whole = amount_zat / 100_000_000;
    let fraction = amount_zat % 100_000_000;
    if fraction == 0 {
        whole.to_string()
    } else {
        let fraction = format!("{fraction:08}").trim_end_matches('0').to_string();
        format!("{whole}.{fraction}")
    }
}

fn zip321_uri(address: &str, amount_zat: u64, memo: &[u8]) -> String {
    use base64::Engine;
    let memo = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(memo);
    format!(
        "zcash:{address}?amount={}&memo={memo}",
        zatoshi_amount(amount_zat)
    )
}

fn anchor_send_required(anchor_txid: Option<&str>, unanchored_leaves: u32) -> bool {
    anchor_txid.is_none() && unanchored_leaves > 0
}

fn invoice_payment_uri(address: &str, amount_zat: u64, invoice_short: &str) -> String {
    zip321_uri(
        address,
        amount_zat,
        format!("NS-{invoice_short}").as_bytes(),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn shorten_identifier(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 14 {
        return value.to_string();
    }
    let start: String = chars.iter().take(8).collect();
    let end: String = chars.iter().skip(chars.len().saturating_sub(6)).collect();
    format!("{start}...{end}")
}

fn take_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn validate_identifier(name: &str, value: &str) -> Result<(), (StatusCode, String)> {
    if value.is_empty() || value.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must be 1-128 bytes"),
        ));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must use only ASCII letters, digits, underscore, or hyphen"),
        ));
    }
    Ok(())
}

fn validate_bounded_text(name: &str, value: &str) -> Result<(), (StatusCode, String)> {
    if value.is_empty() || value.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must be 1-512 UTF-8 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must not contain control characters"),
        ));
    }
    Ok(())
}

fn validate_hex_digest(name: &str, value: &str) -> Result<(), (StatusCode, String)> {
    if value.len() != 64 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must be exactly 64 hexadecimal characters"),
        ));
    }
    Ok(())
}
use serde::Deserialize;
use std::sync::Arc;

use zcash_keys::keys::UnifiedFullViewingKey;

use crate::config::Config;
use crate::db::{canonical_anchor_hex, AnchorRecordConflict, Db};
use crate::foreman::ForemanClient;
use crate::keys::address_for_index_encoded;
use crate::memo::MemoType;
use crate::models::{CreateInvoiceRequest, HealthResponse, Invoice, InvoiceStatus};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub ufvk: Arc<UnifiedFullViewingKey>,
    pub config: Arc<Config>,
    pub foreman: Option<Arc<ForemanClient>>,
}

pub const PROTOCOL_VERSION: &str = "3.0.0";
const COUNT_BOUND_SCHEME: &str = "ZAP1_COUNT_BOUND_V2";
const LEGACY_SCHEME: &str = "ZAP1_LEGACY_DUPLICATE_ODD";
const INVALID_SCHEME: &str = "INVALID";
const LEGACY_ROOT_MAX_ANCHOR_HEIGHT: u32 = 3_317_133;
const PUBLIC_TYPED_LEAF_AUTHENTICATION: &str =
    "unverified_server_metadata_without_disclosed_witness";

const SYSTEM_MANAGED_EVENT_TYPES: [MemoType; 3] = [
    MemoType::ProgramEntry,
    MemoType::OwnershipAttest,
    MemoType::MerkleRoot,
];

fn is_system_managed(memo_type: MemoType) -> bool {
    SYSTEM_MANAGED_EVENT_TYPES.contains(&memo_type)
}

fn write_api_event_types() -> Vec<&'static str> {
    MemoType::ALL
        .iter()
        .copied()
        .filter(|memo_type| !is_system_managed(*memo_type))
        .map(MemoType::label)
        .collect()
}

fn public_stats_snapshot(
    db_counts: &[(i32, i64)],
) -> (
    Vec<&'static str>,
    serde_json::Map<String, serde_json::Value>,
    i64,
    i64,
) {
    let mut event_types = Vec::with_capacity(MemoType::ALL.len());
    let mut type_counts = serde_json::Map::new();
    let mut classified = 0_i64;

    for memo_type in MemoType::ALL {
        let id = i32::from(memo_type.as_u8());
        let name = memo_type.label();
        let count = db_counts
            .iter()
            .find(|(event_type, _)| *event_type == id)
            .map(|(_, count)| *count)
            .unwrap_or(0);
        classified += count;
        event_types.push(name);
        type_counts.insert(name.to_string(), serde_json::json!(count));
    }

    let total: i64 = db_counts.iter().map(|(_, count)| *count).sum();
    let unclassified = total.saturating_sub(classified);
    if unclassified > 0 {
        type_counts.insert("OTHER_UNKNOWN".to_string(), serde_json::json!(unclassified));
    }

    (event_types, type_counts, classified, unclassified)
}

fn anchor_recommendation(
    needs_anchor: bool,
    unanchored: u32,
    threshold: u32,
    broadcast_enabled: bool,
    signer_configured: bool,
) -> &'static str {
    if !needs_anchor {
        "up to date"
    } else if !broadcast_enabled {
        "anchoring paused; leaves staged for the next operator-authorized anchor run"
    } else if !signer_configured {
        "broadcast enabled but signer unavailable; no transaction can be sent"
    } else if unanchored == 0 || unanchored >= threshold {
        "eligible for the configured automatic anchor run"
    } else {
        "below the configured automatic anchor threshold"
    }
}

fn protocol_metadata() -> serde_json::Value {
    let defined_event_types: Vec<&str> = MemoType::ALL
        .iter()
        .map(|event_type| event_type.label())
        .collect();
    let write_api_event_types = write_api_event_types();
    let system_managed_event_types: Vec<&str> = SYSTEM_MANAGED_EVENT_TYPES
        .iter()
        .map(|event_type| event_type.label())
        .collect();

    serde_json::json!({
        "protocol": "ZAP1",
        "version": PROTOCOL_VERSION,
        "event_types": MemoType::ALL.len(),
        "event_types_semantics": "deprecated alias for defined_types",
        "deployed_types": write_api_event_types.len(),
        "deployed_types_semantics": "deprecated alias for write_api_types",
        "reserved_types": system_managed_event_types.len(),
        "reserved_types_semantics": "deprecated legacy count; these are system-managed defined types, not reserved or unallocated codes",
        "defined_types": MemoType::ALL.len(),
        "defined_event_types": defined_event_types,
        "write_api_types": write_api_event_types.len(),
        "write_api_event_types": write_api_event_types,
        "system_managed_types": system_managed_event_types.len(),
        "system_managed_event_types": system_managed_event_types,
        "hash_function": "BLAKE2b-256",
        "leaf_personalization": "NordicShield_",
        "node_personalization": "NordicShield_MRK",
        "verification_sdk": "zap1-verify (Rust + WASM)",
        "verification_sdk_repo": "https://github.com/Frontier-Compute/zap1/tree/main/zap1-verify",
        "frost_status": "experimental_colocated_non_production",
        "frost_ciphersuite": "FROST(Pallas, BLAKE2b-512)",
        "frost_threshold": "2-of-3",
        "frost_custody": "one process holds ANCHOR_SEED and two shares; no independent threshold custody",
        "zip_status": "draft",
        "specification": "https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md",
    })
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/retrogrant", get(evidence_room))
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
        .route("/trial-key", post(create_trial_key))
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "https://frontiercompute.cash".parse().unwrap(),
                    "https://frontiercompute.io".parse().unwrap(),
                    "https://verify.frontiercompute.cash".parse().unwrap(),
                    "https://nordicshield.cash".parse().unwrap(),
                    "https://api.frontiercompute.cash".parse().unwrap(),
                ])
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        )
        .with_state(state)
}

fn block_label(block: Option<u32>) -> String {
    block
        .map(|height| height.to_string())
        .unwrap_or_else(|| "pending first anchor".to_string())
}

fn anchor_range_label(first: Option<u32>, last: Option<u32>) -> String {
    match (first, last) {
        (Some(first), Some(last)) if first == last => first.to_string(),
        (Some(first), Some(last)) => format!("{} to {}", first, last),
        _ => "pending first anchor".to_string(),
    }
}

async fn evidence_room(
    State(state): State<AppState>,
) -> Result<Html<String>, (StatusCode, String)> {
    let (_, total_anchors, first_height, last_height) = state
        .db
        .get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let network = format!("{:?}", state.config.network);
    let db_counts = state
        .db
        .leaf_counts_by_type()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let total_leaves: i64 = db_counts.iter().map(|(_, count)| *count).sum();
    let page = include_str!("evidence_page.html")
        .replace("{TOTAL_ANCHORS}", &total_anchors.to_string())
        .replace("{TOTAL_LEAVES}", &total_leaves.to_string())
        .replace("{EVENT_TYPES_TRACKED}", &MemoType::ALL.len().to_string())
        .replace("{NETWORK}", &html_escape(&network))
        .replace("{PROTOCOL_VERSION}", PROTOCOL_VERSION)
        .replace(
            "{ANCHOR_RANGE}",
            &anchor_range_label(first_height, last_height),
        )
        .replace("{FIRST_ANCHOR_BLOCK}", &block_label(first_height))
        .replace("{LAST_ANCHOR_BLOCK}", &block_label(last_height));

    Ok(Html(page))
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

    tracing::info!("Created invoice {}", invoice.id);

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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Invoice>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
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

    let amount_zec = zatoshi_amount(invoice.amount_zat);
    let received_zec = zatoshi_amount(invoice.received_zat);

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
            html_escape(invoice.paid_txid.as_deref().unwrap_or("confirming..."))
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

    let invoice_short = take_chars(&invoice.id, 8);
    let zcash_uri = invoice_payment_uri(&invoice.address, invoice.amount_zat, &invoice_short);
    let zcash_uri_short = if zcash_uri.len() > 60 {
        format!(
            "zcash:{}...?amount={}",
            take_chars(&invoice.address, 20),
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
        .replace("{AMOUNT_ZEC}", &amount_zec)
        .replace(
            "{RECEIVED_LINE}",
            &if invoice.received_zat > 0 {
                format!(
                    "<div class=\"received\">Received: {} ZEC</div>",
                    received_zec
                )
            } else {
                String::new()
            },
        )
        .replace("{QR_SVG}", &generate_qr_svg(&zcash_uri))
        .replace("{ZCASH_URI_RAW}", &html_escape(&zcash_uri))
        .replace("{ZCASH_URI_SHORT}", &html_escape(&zcash_uri_short))
        .replace("{ADDRESS}", &html_escape(&invoice.address))
        .replace("{PAID_INFO}", &paid_info)
        .replace("{INVOICE_SHORT}", &html_escape(&invoice_short))
        .replace(
            "{EXPIRES_LINE}",
            &invoice
                .expires_at
                .as_deref()
                .map(|e| format!("Expires: {}<br>", html_escape(&take_chars(e, 19))))
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
    let scanner_operational =
        rpc_reachable && chain_tip > 0 && sync_lag <= DEFAULT_HEALTH_MAX_SYNC_LAG_BLOCKS;

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

    let signer_configured =
        state.config.anchor_seed.is_some() || state.config.anchor_zingo_cli.is_some();
    let can_broadcast = state.config.anchor_enabled && signer_configured;
    let recommendation = anchor_recommendation(
        needs_anchor,
        unanchored,
        state.config.anchor_threshold,
        state.config.anchor_enabled,
        signer_configured,
    );

    Ok(Json(serde_json::json!({
        "current_root": root_hash,
        "leaf_count": leaf_count,
        "unanchored_leaves": unanchored,
        "last_anchor_txid": anchor_txid,
        "last_anchor_height": anchor_height,
        "needs_anchor": needs_anchor,
        "anchor_threshold": state.config.anchor_threshold,
        "broadcast_enabled": state.config.anchor_enabled,
        "signer_configured": signer_configured,
        "can_broadcast": can_broadcast,
        "recommendation": recommendation,
        "transaction_reference_semantics": "A recorded txid proves transaction existence; binding an encrypted Orchard memo to this root requires a separate disclosure artifact.",
    })))
}

async fn miner_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(wallet_hash): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
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
        let serial = html_escape(serial);
        let status = html_escape(&status);
        let pool = html_escape(&pool);
        let seen = html_escape(&seen);

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
            let amt = zatoshi_amount(inv.amount_zat);
            let status_class = if inv.status == crate::models::InvoiceStatus::Paid {
                "paid"
            } else {
                "pending"
            };
            let status_label = inv.status.as_str().to_uppercase();
            let pay_link = if inv.status != crate::models::InvoiceStatus::Paid {
                format!(
                    r#"<a class="pay-btn" href="/pay/{}">Pay</a>"#,
                    html_escape(&inv.id)
                )
            } else {
                String::new()
            };
            let memo = html_escape(inv.memo.as_deref().unwrap_or(""));
            billing_html.push_str(&format!(
                r#"<div class="invoice-row">
  <div><div style="color:#e2e4e8">{} ZEC</div><div style="color:#4a5168;font-size:9px;margin-top:2px">{memo}</div></div>
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
    let wallet_short = html_escape(&shorten_identifier(&wallet_hash));

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

    let html = include_str!("miner_page.html")
        .replace("{TESTNET_TITLE}", testnet_title)
        .replace("{TESTNET_BANNER}", testnet_banner)
        .replace("{WALLET_SHORT}", &wallet_short)
        .replace("{MINERS_HTML}", &miners_html)
        .replace("{BILLING_HTML}", &billing_html)
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
    headers: HeaderMap,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
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
    validate_identifier("wallet_hash", &req.wallet_hash)?;
    validate_bounded_text("wallet_address", &req.wallet_address)?;
    validate_bounded_text("serial_number", &req.serial_number)?;
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
            "verify_url": format!("/verify/{}/check", leaf.leaf_hash),
        })),
    ))
}

/// Authenticated ownership-receipt lookup.
/// This does not expose the program UFVK or prove mining payouts.
async fn viewing_key_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
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
                "verify_url": format!("/verify/{}/check", leaf_hash),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "wallet_hash": wallet_hash,
        "verification_method": "Merkle inclusion with optional transaction reference",
        "note": "Each assignment is an operator claim committed to a BLAKE2b Merkle tree. The verify links recompute inclusion in the supplied root. This does not prove assignment or payout. A listed txid proves transaction existence; binding an encrypted Orchard memo to that root requires a separate disclosure artifact.",
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

    let proof_json = html_escape(
        &serde_json::to_string_pretty(&bundle.proof)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    let event_label = bundle.leaf.event_type.label();
    let explorer_link = bundle
        .root
        .anchor_txid
        .as_deref()
        .map(|txid| {
            if txid.len() == 64
                && txid.chars().all(|character| character.is_ascii_hexdigit())
                && matches!(
                    state.config.network,
                    zcash_protocol::consensus::Network::MainNetwork
                )
            {
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
                r#"<a class="txid-link" href="{}" target="_blank" rel="noopener noreferrer">{}</a>"#,
                html_escape(&explorer_link),
                html_escape(txid)
            )
        }
        Some(txid) => html_escape(txid),
        None => "Pending anchor".to_string(),
    };
    let anchor_height = bundle
        .root
        .anchor_height
        .map(|height| height.to_string())
        .unwrap_or_else(|| "Pending confirmation".to_string());

    let html = include_str!("verify_page.html")
        .replace("{LEAF_HASH}", &html_escape(&bundle.leaf.leaf_hash))
        .replace("{EVENT_TYPE}", event_label)
        .replace("{ROOT_HASH}", &html_escape(&bundle.root.root_hash))
        .replace("{LEAF_COUNT}", &bundle.root.leaf_count.to_string())
        .replace("{ANCHOR_TXID}", &anchor_link)
        .replace("{ANCHOR_HEIGHT}", &anchor_height)
        .replace("{PROOF_JSON}", &proof_json)
        .replace("{LEAF_CREATED_AT}", &html_escape(&bundle.leaf.created_at))
        .replace("{ROOT_CREATED_AT}", &html_escape(&bundle.root.created_at))
        .replace(
            "{VERIFY_NOTE}",
            "This page lets anyone recompute Merkle inclusion for the supplied leaf hash. Because the public receipt withholds the typed preimage, the claimed event type is not authenticated. This page also does not authenticate root publication, prove the underlying claim, or independently bind an encrypted memo to that root.",
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

    let merkle = verify_bundle_merkle(&bundle)?;
    let proof_steps: Vec<serde_json::Value> = bundle.proof.iter().map(|s| {
        serde_json::json!({ "hash": s.hash, "position": format!("{:?}", s.position).to_lowercase() })
    }).collect();

    Ok(Json(serde_json::json!({
        "protocol": "ZAP1",
        "version": "2",
        "leaf": {
            "hash": bundle.leaf.leaf_hash,
              "event_type": bundle.leaf.event_type.label(),
              "created_at": bundle.leaf.created_at,
              "preimage_disclosure": "withheld from the public proof bundle",
              "event_type_authentication": PUBLIC_TYPED_LEAF_AUTHENTICATION,
        },
        "proof": proof_steps,
        "root": {
            "hash": bundle.root.root_hash,
            "leaf_count": bundle.root.leaf_count,
            "created_at": bundle.root.created_at,
            "scheme": merkle.scheme,
            "legacy_allowed": merkle.legacy_allowed,
            "legacy_max_anchor_height": LEGACY_ROOT_MAX_ANCHOR_HEIGHT,
        },
        "anchor": {
            "txid": bundle.root.anchor_txid,
            "height": bundle.root.anchor_height,
        },
        "verify_command": "python3 examples/verify_proof.py proof.json",
    })))
}

struct BundleMerkleCheck {
    valid: bool,
    scheme: &'static str,
    valid_count_bound: bool,
    valid_legacy_raw: bool,
    legacy_allowed: bool,
}

fn is_historical_legacy_anchor(anchor_height: Option<u32>) -> bool {
    anchor_height
        .map(|height| height <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT)
        .unwrap_or(false)
}

fn bundle_proof_steps(
    bundle: &crate::merkle::VerificationBundle,
) -> Result<Vec<zap1_verify::ProofStep>, (StatusCode, String)> {
    bundle
        .proof
        .iter()
        .map(|s| {
            let hash = zap1_verify::hex_to_bytes32(&s.hash).ok_or((
                StatusCode::BAD_REQUEST,
                format!("Invalid proof hash hex: {}", s.hash),
            ))?;
            let position = match format!("{:?}", s.position).to_lowercase().as_str() {
                "left" => zap1_verify::SiblingPosition::Left,
                "right" => zap1_verify::SiblingPosition::Right,
                other => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid proof position: {other}"),
                    ))
                }
            };
            Ok(zap1_verify::ProofStep { hash, position })
        })
        .collect()
}

fn verify_bundle_merkle(
    bundle: &crate::merkle::VerificationBundle,
) -> Result<BundleMerkleCheck, (StatusCode, String)> {
    let leaf_bytes = zap1_verify::hex_to_bytes32(&bundle.leaf.leaf_hash)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid leaf hash hex".to_string()))?;
    let root_bytes = zap1_verify::hex_to_bytes32(&bundle.root.root_hash)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid root hash hex".to_string()))?;
    let proof_steps = bundle_proof_steps(bundle)?;

    let valid_count_bound = zap1_verify::verify_proof(
        &leaf_bytes,
        &proof_steps,
        bundle.root.leaf_count,
        &root_bytes,
    );
    let valid_legacy_raw = zap1_verify::verify_legacy_proof(&leaf_bytes, &proof_steps, &root_bytes);
    let legacy_allowed = valid_legacy_raw && is_historical_legacy_anchor(bundle.root.anchor_height);
    let scheme = if valid_count_bound {
        COUNT_BOUND_SCHEME
    } else if valid_legacy_raw {
        LEGACY_SCHEME
    } else {
        INVALID_SCHEME
    };

    Ok(BundleMerkleCheck {
        valid: valid_count_bound || legacy_allowed,
        scheme,
        valid_count_bound,
        valid_legacy_raw,
        legacy_allowed,
    })
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

    let merkle = verify_bundle_merkle(&bundle)?;

    Ok(Json(serde_json::json!({
        "protocol": "ZAP1",
        "valid": merkle.valid,
        "merkle_scheme": merkle.scheme,
        "legacy_shape_warning": merkle.valid_legacy_raw && !merkle.valid_count_bound,
        "legacy_accepted": merkle.legacy_allowed,
        "legacy_max_anchor_height": LEGACY_ROOT_MAX_ANCHOR_HEIGHT,
        "leaf_hash": bundle.leaf.leaf_hash,
          "event_type": bundle.leaf.event_type.label(),
          "claimed_event_type": bundle.leaf.event_type.label(),
          "event_type_authentication": PUBLIC_TYPED_LEAF_AUTHENTICATION,
          "typed_leaf_verified": serde_json::Value::Null,
        "root": bundle.root.root_hash,
        "leaf_count": bundle.root.leaf_count,
        "anchor": {
            "txid": bundle.root.anchor_txid,
            "height": bundle.root.anchor_height,
        },
        "merkle_valid": merkle.valid,
        "server_verified": merkle.valid,
        "server_verified_semantics": "deprecated alias for merkle_valid; the server re-walked inclusion against the supplied root",
        "verification_scope": "Merkle inclusion only. This result does not prove the underlying event, authenticate the operator, or bind an encrypted memo to the supplied root.",
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
                "scheme": if is_historical_legacy_anchor(r.anchor_height) {
                    LEGACY_SCHEME
                } else {
                    COUNT_BOUND_SCHEME
                },
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
        "record_semantics": "Locally recorded root, transaction-id, and height mappings. Transaction existence is separately checkable; encrypted memo-to-root binding requires a disclosure artifact.",
    })))
}

/// Recent operator-issued event claims for explorers and indexers.
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
                    "PROGRAM_ENTRY" => "Claimed operator registration",
                    "OWNERSHIP_ATTEST" => "Claimed ownership",
                    "CONTRACT_ANCHOR" => "Claimed contract commitment",
                    "DEPLOYMENT" => "Claimed hardware deployment",
                    "HOSTING_PAYMENT" => "Claimed hosting payment",
                    "SHIELD_RENEWAL" => "Claimed shield renewal",
                    "TRANSFER" => "Claimed ownership transfer",
                    "EXIT" => "Claimed hardware decommission",
                    "MERKLE_ROOT" => "Merkle root record",
                    "STAKING_DEPOSIT" => "Claimed staking deposit",
                    "STAKING_WITHDRAW" => "Claimed staking withdrawal",
                    "STAKING_REWARD" => "Claimed staking reward",
                    "GOVERNANCE_PROPOSAL" => "Claimed governance proposal",
                    "GOVERNANCE_VOTE" => "Claimed governance vote",
                    "GOVERNANCE_RESULT" => "Claimed governance result",
                    "AGENT_REGISTER" => "Claimed agent registration",
                    "AGENT_POLICY" => "Claimed agent policy",
                    "AGENT_ACTION" => "Claimed agent action",
                    _ => "Unknown event",
                },
                "created_at": l.created_at,
                "preimage_disclosure": "withheld from the public event feed",
                "event_type_authentication": PUBLIC_TYPED_LEAF_AUTHENTICATION,
                "verify_url": format!("/verify/{}/check", l.leaf_hash),
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
    Json(protocol_metadata())
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
/// Embed: ![ZAP1](https://api.frontiercompute.cash/badge/status.svg)
async fn badge_status(
    State(state): State<AppState>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 2],
    String,
) {
    let (value, color) = match (state.db.total_leaf_count(), state.db.all_anchored_roots()) {
        (Ok(l), Ok(roots)) => {
            let record_count = roots.iter().filter(|r| r.anchor_txid.is_some()).count();
            (
                format!("{} leaves | {} tx records", l, record_count),
                "#c8a84e",
            )
        }
        _ => ("status unavailable".to_string(), "#e05d44"),
    };

    let svg = svg_badge("ZAP1", &value, color);

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
    let (value, color) = match state.db.get_verification_bundle(&leaf_hash) {
        Ok(Some(bundle)) => match verify_bundle_merkle(&bundle) {
            Ok(check) if check.valid => ("Merkle match", "#4c1"),
            Ok(_) => ("bundle invalid", "#e05d44"),
            Err(_) => ("check failed", "#e05d44"),
        },
        Ok(None) => ("not found", "#e05d44"),
        Err(_) => ("lookup failed", "#e05d44"),
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
            Some(h) => (format!("recorded at block {}", h), "#c8a84e".to_string()),
            None => ("recorded (unconfirmed)".to_string(), "#c8a84e".to_string()),
        },
        None => ("record not found".to_string(), "#e05d44".to_string()),
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

async fn create_trial_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    if !state.config.trial_key_issuance_enabled {
        return Err((
            StatusCode::NOT_FOUND,
            "Trial-key issuance is disabled".to_string(),
        ));
    }
    check_api_key(&state.config, &headers)?;
    state
        .db
        .create_api_keys_table()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw_key = format!(
        "zap1_trial_{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    );
    let key_hash = sha256_hex(&raw_key);
    let id = uuid::Uuid::new_v4().to_string();
    let expires = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    state
        .db
        .insert_api_key(&id, &key_hash, "trial", 5, Some(&expires))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("Trial key issued: id={}", id);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "key": raw_key,
            "tier": "trial",
            "quota": 5,
            "expires_in_days": 30,
        })),
    ))
}

fn parse_build_metadata(raw: &str) -> serde_json::Map<String, serde_json::Value> {
    raw.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            (
                key.trim().to_string(),
                serde_json::Value::String(value.trim().to_string()),
            )
        })
        .collect()
}

fn metadata_bool(metadata: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    metadata.get(key).and_then(|value| value.as_str()) == Some("true")
}

fn metadata_hex_len(
    metadata: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    length: usize,
) -> bool {
    metadata
        .get(key)
        .and_then(|value| value.as_str())
        .is_some_and(|value| {
            value.len() == length && value.chars().all(|character| character.is_ascii_hexdigit())
        })
}

async fn build_info() -> Json<serde_json::Value> {
    let raw = std::fs::read_to_string("/usr/local/share/zap1/BUILD_INFO").unwrap_or_default();
    let metadata = parse_build_metadata(&raw);
    let deployment_revision = metadata
        .get("source_revision")
        .and_then(|value| value.as_str());
    let source_tree = metadata.get("source_tree").and_then(|value| value.as_str());
    let source_manifest_sha256 = metadata
        .get("source_manifest_sha256")
        .and_then(|value| value.as_str());
    let public_evidence_revision = metadata
        .get("public_evidence_revision")
        .and_then(|value| value.as_str());
    let public_evidence_url = public_evidence_revision
        .map(|revision| format!("https://github.com/Frontier-Compute/zap1/commit/{revision}"));
    let cargo_locked = metadata_bool(&metadata, "cargo_locked");
    let path_remapping = metadata_bool(&metadata, "path_remapping");
    let source_manifest_verified = metadata_bool(&metadata, "source_manifest_verified");
    let metadata_complete = metadata_hex_len(&metadata, "source_revision", 40)
        && metadata_hex_len(&metadata, "source_tree", 40)
        && metadata_hex_len(&metadata, "public_evidence_revision", 40)
        && metadata_hex_len(&metadata, "source_manifest_sha256", 64)
        && metadata_hex_len(&metadata, "cargo_lock_sha256", 64)
        && metadata_hex_len(&metadata, "zap1_binary_sha256", 64);
    let deployment_image_id = std::env::var("ZAP1_DEPLOYMENT_IMAGE_ID")
        .ok()
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..].chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        });
    let deployment_image_id_present = deployment_image_id.is_some();

    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "librustzcash_rev": "1f736379a4099ef1ba3b3bff4035c725e28a018a",
        "deployment": {
            "image_id": deployment_image_id,
            "image_id_present": deployment_image_id_present,
            "binding": "The deployment image ID is injected by the operator from docker image inspect and must be matched to the external build and deployment receipt. It is a deployment declaration, not remote attestation."
        },
        "source": {
            "deployment_revision": deployment_revision,
            "source_tree": source_tree,
            "source_manifest_sha256": source_manifest_sha256,
            "source_manifest_verified": source_manifest_verified,
            "public_evidence_revision": public_evidence_revision,
            "public_evidence_url": public_evidence_url,
            "parity_scope": "The source manifest is recomputed from runtime-source bytes inside the image. Revision and Git tree identifiers are declarations derived by the clean-archive build driver and require the external build receipt for commit binding; bit-for-bit equality is not asserted."
        },
        "build_assurance": {
            "metadata_available": !metadata.is_empty(),
            "metadata_complete": metadata_complete,
            "path_remapping": path_remapping,
            "cargo_locked": cargo_locked,
            "source_manifest_verified": source_manifest_verified,
            "bit_for_bit_reproduction": "not asserted",
            "note": "The image verifies its runtime-source manifest and records declared revision/tree, lockfile, toolchain, and artifact hashes. The external clean-archive build receipt binds the declared Git identifiers; an independent matching reproduction is a separate evidence step."
        },
        "supply_chain": {
            "dependency_pinning": "git rev (Cargo.toml [patch.crates-io])",
            "lock_file": "Cargo.lock committed",
            "verification": "the image build fails unless Cargo.lock is present and cargo build --locked succeeds"
        },
        "build_metadata": metadata,
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
    check_api_key_with_db(&state.config, &headers, Some(&state.db))?;

    validate_identifier("wallet_hash", &req.wallet_hash)?;
    if let Some(value) = req.new_wallet_hash.as_deref() {
        validate_identifier("new_wallet_hash", value)?;
    }
    if let Some(value) = req.agent_id.as_deref() {
        validate_identifier("agent_id", value)?;
    }
    for (name, value) in [
        ("serial_number", req.serial_number.as_deref()),
        ("facility_id", req.facility_id.as_deref()),
        ("validator_id", req.validator_id.as_deref()),
        ("proposal_id", req.proposal_id.as_deref()),
        ("action_type", req.action_type.as_deref()),
    ] {
        if let Some(value) = value {
            validate_bounded_text(name, value)?;
        }
    }
    for (name, value) in [
        ("contract_sha256", req.contract_sha256.as_deref()),
        ("proposal_hash", req.proposal_hash.as_deref()),
        ("vote_commitment", req.vote_commitment.as_deref()),
        ("result_hash", req.result_hash.as_deref()),
        ("pubkey_hash", req.pubkey_hash.as_deref()),
        ("model_hash", req.model_hash.as_deref()),
        ("policy_hash", req.policy_hash.as_deref()),
        ("rules_hash", req.rules_hash.as_deref()),
        ("input_hash", req.input_hash.as_deref()),
        ("output_hash", req.output_hash.as_deref()),
    ] {
        if let Some(value) = value {
            validate_hex_digest(name, value)?;
        }
    }

    let is_agent_event = matches!(
        req.event_type.as_str(),
        "AGENT_REGISTER" | "AGENT_POLICY" | "AGENT_ACTION"
    );
    if is_agent_event && req.agent_id.as_deref() != Some(req.wallet_hash.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent events require wallet_hash to equal agent_id so the stored and returned subject cannot diverge"
                .to_string(),
        ));
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
            if !(2020..=2100).contains(&year) {
                return Err((StatusCode::BAD_REQUEST, "year must be 2020-2100".into()));
            }
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
            if !(1..=2_100_000_000_000_000).contains(&amount) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "amount_zat must be between 1 and the Zcash maximum supply".into(),
                ));
            }
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
            if !(1..=2_100_000_000_000_000).contains(&amount) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "amount_zat must be between 1 and the Zcash maximum supply".into(),
                ));
            }
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
            if !(1..=2_100_000_000_000_000).contains(&amount) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "amount_zat must be between 1 and the Zcash maximum supply".into(),
                ));
            }
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
            if pv == 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "policy_version must be greater than zero".into(),
                ));
            }
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

    let subject_kind = if is_agent_event { "agent" } else { "wallet" };
    let subject_id = req.agent_id.as_deref().unwrap_or(req.wallet_hash.as_str());

    tracing::info!(
        "Lifecycle event {} for {} {}",
        req.event_type,
        subject_kind,
        subject_id
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created",
            "event_type": req.event_type,
            "wallet_hash": req.wallet_hash,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "leaf_hash": leaf.leaf_hash,
            "root_hash": root.root_hash,
            "verify_url": format!("/verify/{}/check", leaf.leaf_hash),
        })),
    ))
}

async fn lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(wallet_hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;
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
                "anchored_semantics": "deprecated compatibility field: true means an API-recorded transaction reference covers this leaf",
                "transaction_reference_recorded": anchor.is_some(),
                "verify_url": format!("/verify/{}/check", leaf.leaf_hash),
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
    let (_, total_anchors, first_height, last_height) = state
        .db
        .get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let network = format!("{:?}", state.config.network);

    let db_counts = state
        .db
        .leaf_counts_by_type()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (event_types, type_counts, classified_leaves, unclassified_leaves) =
        public_stats_snapshot(&db_counts);
    let total_leaves: i64 = db_counts.iter().map(|(_, count)| *count).sum();

    Ok(Json(serde_json::json!({
        "total_leaves": total_leaves,
        "total_anchors": total_anchors,
        "total_anchor_records": total_anchors,
        "total_anchors_semantics": "deprecated compatibility field: locally recorded transaction references, not independent proof of encrypted memo contents",
        "first_anchor_block": first_height,
        "last_anchor_block": last_height,
        "network": network,
        "protocol": "ZAP1",
        "event_types": event_types,
        "type_counts": type_counts,
        "classified_leaves": classified_leaves,
        "unclassified_leaves": unclassified_leaves,
    })))
}

#[cfg(test)]
mod evidence_surface_tests {
    use super::{
        anchor_recommendation, anchor_send_required, invoice_payment_uri, metadata_bool,
        metadata_hex_len, parse_build_metadata, protocol_metadata, public_stats_snapshot,
        zip321_uri, MemoType, SYSTEM_MANAGED_EVENT_TYPES,
    };

    #[test]
    fn public_stats_include_every_defined_type_without_dropping_leaves() {
        let db_counts = vec![
            (0x03, 118),
            (0x04, 4),
            (0x08, 66),
            (0x0a, 2),
            (0x0d, 7),
            (0x40, 48),
            (0x42, 152),
        ];
        let (event_types, type_counts, classified, unclassified) =
            public_stats_snapshot(&db_counts);

        assert_eq!(event_types.len(), MemoType::ALL.len());
        assert_eq!(type_counts["STAKING_DEPOSIT"], 2);
        assert_eq!(type_counts["GOVERNANCE_PROPOSAL"], 7);
        assert_eq!(type_counts["AGENT_REGISTER"], 48);
        assert_eq!(type_counts["AGENT_ACTION"], 152);
        assert_eq!(classified, 397);
        assert_eq!(unclassified, 0);
        let reported_total: i64 = type_counts
            .values()
            .map(|value| value.as_i64().unwrap())
            .sum();
        assert_eq!(reported_total, 397);
    }

    #[test]
    fn public_stats_fail_visibly_into_other_unknown() {
        let db_counts = vec![(0x01, 1), (0x7f, 2)];
        let (event_types, type_counts, classified, unclassified) =
            public_stats_snapshot(&db_counts);

        assert_eq!(event_types.len(), MemoType::ALL.len());
        assert!(!event_types.contains(&"OTHER_UNKNOWN"));
        assert_eq!(type_counts["OTHER_UNKNOWN"], 2);
        assert_eq!(classified, 1);
        assert_eq!(unclassified, 2);
        assert_eq!(
            type_counts
                .values()
                .map(|value| value.as_i64().unwrap())
                .sum::<i64>(),
            3
        );
    }

    #[test]
    fn protocol_metadata_preserves_legacy_fields_with_explicit_semantics() {
        let metadata = protocol_metadata();
        assert_eq!(metadata["event_types"], 18);
        assert_eq!(metadata["deployed_types"], 15);
        assert_eq!(metadata["reserved_types"], 3);
        assert_eq!(metadata["defined_types"], 18);
        assert_eq!(metadata["write_api_types"], 15);
        assert_eq!(metadata["system_managed_types"], 3);
        assert_eq!(SYSTEM_MANAGED_EVENT_TYPES.len(), 3);
        assert_eq!(
            metadata["write_api_event_types"].as_array().unwrap().len(),
            15
        );
    }

    #[test]
    fn paused_anchor_copy_wins_even_when_a_signer_is_present() {
        assert_eq!(
            anchor_recommendation(true, 150, 10, false, true),
            "anchoring paused; leaves staged for the next operator-authorized anchor run"
        );
        assert_eq!(
            anchor_recommendation(true, 150, 10, true, false),
            "broadcast enabled but signer unavailable; no transaction can be sent"
        );
    }

    #[test]
    fn build_metadata_parser_preserves_machine_readable_identity_fields() {
        let metadata = parse_build_metadata(
            "source_revision=0123456789abcdef0123456789abcdef01234567\n\
             cargo_locked=true\n\
             rustc_version=rustc 1.85.1 (test)\n",
        );
        assert_eq!(
            metadata["source_revision"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(metadata["cargo_locked"], "true");
        assert_eq!(metadata["rustc_version"], "rustc 1.85.1 (test)");
        assert!(metadata_bool(&metadata, "cargo_locked"));
        assert!(metadata_hex_len(&metadata, "source_revision", 40));
        assert!(!metadata_bool(&metadata, "path_remapping"));
        assert!(!metadata_hex_len(&metadata, "source_manifest_sha256", 64));
    }

    #[test]
    fn zip321_uri_uses_configured_zatoshi_amount_and_base64url_memo() {
        use base64::Engine;

        let memo = b"ZAP1:09:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let uri = zip321_uri("u1test", 10_000, memo);
        let expected_memo = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(memo);
        assert_eq!(
            uri,
            format!("zcash:u1test?amount=0.0001&memo={expected_memo}")
        );
        assert!(!uri.contains(&hex::encode(memo)));
    }

    #[test]
    fn anchor_qr_send_action_fails_closed_after_a_reference_exists() {
        assert!(anchor_send_required(None, 150));
        assert!(!anchor_send_required(None, 0));
        assert!(!anchor_send_required(Some(&"a".repeat(64)), 0));
        assert!(!anchor_send_required(Some(&"a".repeat(64)), 1));
    }

    #[test]
    fn invoice_uri_preserves_every_requested_zatoshi() {
        use base64::Engine;

        let uri = invoice_payment_uri("u1test", 100_004_999, "12345678");
        let memo = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"NS-12345678");
        assert_eq!(uri, format!("zcash:u1test?amount=1.00004999&memo={memo}"));
    }
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
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Memo hex limited to 1024 bytes (2048 hex chars)".to_string(),
        ));
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

async fn admin_anchor_qr(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, (StatusCode, String)> {
    // Secrets in URLs leak through browser history, referrers, reverse-proxy
    // logs, and screenshots. This endpoint accepts header auth only.
    check_api_key(&state.config, &headers)?;

    let root = state
        .db
        .current_merkle_root()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let unanchored = state
        .db
        .unanchored_leaf_count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let root = root.ok_or((StatusCode::BAD_REQUEST, "no Merkle root yet".into()))?;
    let memo_text = format!("ZAP1:09:{}", root.root_hash);
    let send_required = anchor_send_required(root.anchor_txid.as_deref(), unanchored);
    let action_panel = if send_required {
        let addr = state.config.anchor_to_address.as_deref().ok_or((
            StatusCode::BAD_REQUEST,
            "ANCHOR_TO_ADDRESS not configured".into(),
        ))?;
        let uri = zip321_uri(addr, state.config.anchor_amount_zat, memo_text.as_bytes());
        let qr_svg = generate_qr_svg(&uri);
        let record_command = html_escape(&format!(
            r#": "${{ZAP1_API_BASE:?set ZAP1_API_BASE to this deployment}}"
curl -X POST "${{ZAP1_API_BASE%/}}/admin/anchor/record" \
  -H 'Authorization: Bearer <operator-key>' \
  -H 'Content-Type: application/json' \
  -d '{{"root":"{}","txid":"<64-hex-txid>","height":<confirmed-height>}}'"#,
            root.root_hash
        ));
        format!(
            r#"<div class="anchor-action" data-anchor-send-enabled="true">
<div class="qr">{qr_svg}</div>
<div class="memo">Memo: {}</div>
<div>Scan with a ZIP-321-compatible wallet. Send {} ZEC.</div>
<p>After configured-node confirmation, record the transaction reference with header authentication.</p>
<pre>{record_command}</pre>
</div>"#,
            html_escape(&memo_text),
            zatoshi_amount(state.config.anchor_amount_zat),
        )
    } else {
        r#"<div class="anchor-action" data-anchor-send-enabled="false">
<p>No wallet send action is available for this root. A transaction reference already exists or there are no unanchored leaves.</p>
</div>"#
            .to_string()
    };

    let status = if root.anchor_txid.is_some() && root.anchor_height.is_some() && unanchored == 0 {
        "transaction reference confirmed"
    } else if root.anchor_txid.is_some() {
        "transaction broadcast recorded, confirmation pending"
    } else if send_required {
        "needs transaction reference"
    } else {
        "wallet send unavailable for the current state"
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
pre {{ background:#1a1e27; border:1px solid #333; color:#e2e4e8; padding:12px; border-radius:4px; font-size:11px; max-width:760px; white-space:pre-wrap; word-break:break-word; }}
</style></head><body>
<h1>Anchor #{}</h1>
<div class="status">{}</div>
<div class="info">
  <div>Root: {}</div>
  <div>Leaves: {} ({} unanchored)</div>
</div>
{}
<p>This checks transaction existence and height only. It does not open the encrypted memo or independently prove that the memo contains this root.</p>
</body></html>"#,
        if status == "transaction reference confirmed" {
            "#4caf50"
        } else {
            "#d4a843"
        },
        root.leaf_count / 4 + 1,
        status,
        root.root_hash,
        root.leaf_count,
        unanchored,
        action_panel,
    );

    Ok(Html(html))
}

#[derive(Deserialize)]
struct AnchorRecordRequest {
    root: String,
    txid: String,
    height: u32,
}

async fn admin_anchor_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<AnchorRecordRequest>,
) -> Result<Html<String>, (StatusCode, String)> {
    check_api_key(&state.config, &headers)?;

    let root = canonical_anchor_hex(&form.root, "root")
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let txid = canonical_anchor_hex(&form.txid, "txid")
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    if form.height == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "height must be greater than zero".into(),
        ));
    }

    let observed_height = transaction_height_from_zebra(&state.config.zebra_rpc_url, &txid)
        .await
        .map_err(|error| {
            tracing::warn!("Manual anchor transaction lookup failed: {error:#}");
            (
                StatusCode::BAD_GATEWAY,
                "Unable to verify the transaction against the configured Zebra node".to_string(),
            )
        })?;
    if observed_height != form.height {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "claimed height {} does not match configured-node height {}",
                form.height, observed_height
            ),
        ));
    }

    let reconciled_prepared = state
        .db
        .record_confirmed_manual_anchor_reference(&root, &txid, form.height)
        .map_err(|error| {
            let status = if error.downcast_ref::<AnchorRecordConflict>().is_some() {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, error.to_string())
        })?;
    let recovery_note = if reconciled_prepared {
        " The exact prepared transaction was reconciled. Embedded-wallet state finalization remains pending."
    } else {
        ""
    };

    Ok(Html(format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3;url=/admin/anchor/qr">
<style>body {{ background:#0a0e17; color:#4caf50; font-family:monospace; display:flex; justify-content:center; align-items:center; height:100vh; }}</style>
</head><body>
<div>Transaction reference recorded. Root: {}...  Txid: {}...  Height: {}. Configured-node confirmation does not prove encrypted memo contents or independent root binding.{} Redirecting...</div>
</body></html>"#,
        &root[..16],
        &txid[..16],
        form.height,
        recovery_note,
    )))
}

async fn transaction_height_from_zebra(url: &str, txid: &str) -> anyhow::Result<u32> {
    let response = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getrawtransaction",
            "params": [txid, 1],
        }))
        .send()
        .await?
        .error_for_status()?;
    let body: serde_json::Value = response.json().await?;
    if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
        anyhow::bail!("getrawtransaction RPC error: {error}");
    }
    body.get("result")
        .and_then(|result| result.get("height"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
        .filter(|height| *height > 0)
        .ok_or_else(|| anyhow::anyhow!("transaction is absent or unconfirmed"))
}
