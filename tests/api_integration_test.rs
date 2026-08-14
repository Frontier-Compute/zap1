//! Integration tests for the ZAP1 HTTP API.
//! Tests endpoints that don't require a real UFVK or chain connection.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn test_app() -> axum::Router {
    test_app_with_config(zap1::config::Config::test_defaults())
}

fn test_app_with_config(config: zap1::config::Config) -> axum::Router {
    let db = std::sync::Arc::new(zap1::db::Db::open(":memory:").unwrap());
    test_app_with_config_and_db(config, db)
}

fn test_app_with_config_and_db(
    config: zap1::config::Config,
    db: std::sync::Arc<zap1::db::Db>,
) -> axum::Router {
    let config = std::sync::Arc::new(config);

    // Generate a test UFVK from a random seed
    let mut seed = [0u8; 32];
    seed[0] = 1; // deterministic test seed
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &zcash_protocol::consensus::MainNetwork,
        &seed,
        zip32::AccountId::ZERO,
    )
    .unwrap();
    let ufvk = std::sync::Arc::new(usk.to_unified_full_viewing_key());

    let state = zap1::api::AppState {
        db,
        ufvk,
        config,
        foreman: None,
    };
    zap1::api::router(state)
}

#[tokio::test]
async fn memo_decode_route_labels_all_defined_event_types() {
    let app = test_app();
    let cases = [
        (0x01u8, "PROGRAM_ENTRY"),
        (0x02, "OWNERSHIP_ATTEST"),
        (0x03, "CONTRACT_ANCHOR"),
        (0x04, "DEPLOYMENT"),
        (0x05, "HOSTING_PAYMENT"),
        (0x06, "SHIELD_RENEWAL"),
        (0x07, "TRANSFER"),
        (0x08, "EXIT"),
        (0x09, "MERKLE_ROOT"),
        (0x0A, "STAKING_DEPOSIT"),
        (0x0B, "STAKING_WITHDRAW"),
        (0x0C, "STAKING_REWARD"),
        (0x0D, "GOVERNANCE_PROPOSAL"),
        (0x0E, "GOVERNANCE_VOTE"),
        (0x0F, "GOVERNANCE_RESULT"),
        (0x40, "AGENT_REGISTER"),
        (0x41, "AGENT_POLICY"),
        (0x42, "AGENT_ACTION"),
    ];

    for (event_type, expected_label) in cases {
        let memo = format!("ZAP1:{event_type:02x}:{}", "aa".repeat(32));
        let resp = app
            .clone()
            .oneshot(
                Request::post("/memo/decode")
                    .header("content-type", "text/plain")
                    .body(Body::from(hex::encode(memo)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "type 0x{event_type:02x}");
        let body = axum::body::to_bytes(resp.into_body(), 10_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["format"], "zap1", "type 0x{event_type:02x}");
        assert_eq!(
            json["event_label"], expected_label,
            "type 0x{event_type:02x}"
        );
    }
}

#[tokio::test]
async fn protocol_info_returns_zap1() {
    let app = test_app();
    let resp = app
        .oneshot(Request::get("/protocol/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["protocol"], "ZAP1");
    assert_eq!(json["version"], zap1::api::PROTOCOL_VERSION);
    assert_eq!(json["defined_types"], 18);
    assert_eq!(json["write_api_types"], 15);
    assert_eq!(json["system_managed_types"], 3);
}

#[tokio::test]
async fn stats_returns_zeroes_on_empty_db() {
    let app = test_app();
    let resp = app
        .oneshot(Request::get("/stats").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_anchors"], 0);
    assert_eq!(json["total_leaves"], 0);
    assert_eq!(json["protocol"], "ZAP1");
    assert_eq!(json["classified_leaves"], 0);
    assert_eq!(json["unclassified_leaves"], 0);
    assert_eq!(
        json["type_counts"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_i64().unwrap())
            .sum::<i64>(),
        0
    );
}

#[tokio::test]
async fn admin_without_key_returns_401() {
    let app = test_app();
    let resp = app
        .oneshot(Request::get("/admin/overview").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_with_key_returns_200() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::get("/admin/overview")
                .header("authorization", "Bearer test_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn badge_status_returns_svg() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::get("/badge/status.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("svg"));
}

#[tokio::test]
async fn anchor_status_on_empty_db() {
    let app = test_app();
    let resp = app
        .oneshot(Request::get("/anchor/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["needs_anchor"], false);
    assert_eq!(json["unanchored_leaves"], 0);
}

#[tokio::test]
async fn create_event_requires_auth() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"event_type":"DEPLOYMENT","wallet_hash":"test","serial_number":"s1","facility_id":"f1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_master_key_never_opens_write_routes() {
    let mut config = zap1::config::Config::test_defaults();
    config.api_key = None;
    let app = test_app_with_config(config);
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"event_type":"DEPLOYMENT","wallet_hash":"test","serial_number":"s1","facility_id":"f1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn trial_key_issuance_is_hidden_by_default() {
    let app = test_app();
    let resp = app
        .oneshot(Request::post("/trial-key").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn enabled_trial_key_issuance_still_requires_operator_auth() {
    let mut config = zap1::config::Config::test_defaults();
    config.trial_key_issuance_enabled = true;
    let app = test_app_with_config(config);
    let resp = app
        .oneshot(Request::post("/trial-key").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_qr_rejects_api_keys_in_urls() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::get("/admin/anchor/qr?key=test_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn database_api_keys_expire_and_consume_quota_atomically() {
    use sha2::{Digest, Sha256};

    let db = zap1::db::Db::open(":memory:").unwrap();
    let active_key = hex::encode(Sha256::digest(b"active"));
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    db.insert_api_key("active-id", &active_key, "trial", 1, Some(&future))
        .unwrap();
    assert!(db.consume_api_key_quota(&active_key).unwrap());
    assert!(!db.consume_api_key_quota(&active_key).unwrap());

    let expired_key = hex::encode(Sha256::digest(b"expired"));
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    db.insert_api_key("expired-id", &expired_key, "trial", 5, Some(&past))
        .unwrap();
    assert!(!db.consume_api_key_quota(&expired_key).unwrap());

    let legacy_key = hex::encode(Sha256::digest(b"legacy-no-expiry"));
    db.insert_api_key("legacy-id", &legacy_key, "trial", 5, None)
        .unwrap();
    assert!(!db.consume_api_key_quota(&legacy_key).unwrap());
}

#[tokio::test]
async fn missing_master_key_disables_even_unexpired_delegated_keys() {
    use sha2::{Digest, Sha256};

    let db = std::sync::Arc::new(zap1::db::Db::open(":memory:").unwrap());
    let raw_key = "delegated-active";
    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    db.insert_api_key("delegated-id", &key_hash, "trial", 5, Some(&future))
        .unwrap();

    let mut config = zap1::config::Config::test_defaults();
    config.api_key = None;
    let app = test_app_with_config_and_db(config, db);
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {raw_key}"))
                .body(Body::from(
                    r#"{"event_type":"DEPLOYMENT","wallet_hash":"test","serial_number":"s1","facility_id":"f1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_event_with_auth() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(
                    r#"{"event_type":"DEPLOYMENT","wallet_hash":"test","serial_number":"s1","facility_id":"f1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["event_type"], "DEPLOYMENT");
    assert!(json["leaf_hash"].is_string());
    assert!(json["root_hash"].is_string());
}

#[tokio::test]
async fn create_governance_event() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(
                    r#"{"event_type":"GOVERNANCE_PROPOSAL","wallet_hash":"dao","proposal_id":"p1","proposal_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["event_type"], "GOVERNANCE_PROPOSAL");
}

#[tokio::test]
async fn create_staking_event() {
    let app = test_app();
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(
                    r#"{"event_type":"STAKING_DEPOSIT","wallet_hash":"val1","amount_zat":1000000,"validator_id":"v1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn oversized_length_prefixed_event_field_is_rejected_before_hashing() {
    let app = test_app();
    let body = serde_json::json!({
        "event_type": "CONTRACT_ANCHOR",
        "wallet_hash": "wallet",
        "serial_number": "x".repeat(65_536),
        "contract_sha256": "a".repeat(64),
    })
    .to_string();
    let resp = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn public_receipts_and_feed_do_not_disclose_stored_subject_preimages() {
    let app = test_app();
    let hostile = r#"<img src=x onerror=alert(1)>"#;
    let wallet = "private-wallet-marker";
    let body = serde_json::json!({
        "event_type": "CONTRACT_ANCHOR",
        "wallet_hash": wallet,
        "serial_number": hostile,
        "contract_sha256": "a".repeat(64),
    })
    .to_string();
    let created = app
        .clone()
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(created.into_body(), 10_000)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let leaf_hash = json["leaf_hash"].as_str().unwrap();

    let page = app
        .clone()
        .oneshot(
            Request::get(format!("/verify/{leaf_hash}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(page.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!html.contains(hostile));
    assert!(!html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(!html.contains(wallet));

    let proof = app
        .clone()
        .oneshot(
            Request::get(format!("/verify/{leaf_hash}/proof.json"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proof.status(), StatusCode::OK);
    let proof_body = axum::body::to_bytes(proof.into_body(), 100_000)
        .await
        .unwrap();
    let proof_json: serde_json::Value = serde_json::from_slice(&proof_body).unwrap();
    assert!(proof_json["leaf"].get("wallet_hash").is_none());
    assert!(proof_json["leaf"].get("serial_number").is_none());
    assert_eq!(
        proof_json["leaf"]["event_type_authentication"],
        "unverified_server_metadata_without_disclosed_witness"
    );
    let proof_text = String::from_utf8(proof_body.to_vec()).unwrap();
    assert!(!proof_text.contains(wallet));
    assert!(!proof_text.contains(hostile));

    let feed = app
        .oneshot(Request::get("/events").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(feed.status(), StatusCode::OK);
    let feed_body = axum::body::to_bytes(feed.into_body(), 100_000)
        .await
        .unwrap();
    let feed_json: serde_json::Value = serde_json::from_slice(&feed_body).unwrap();
    let event = feed_json["events"].as_array().unwrap().first().unwrap();
    assert!(event.get("wallet_hash").is_none());
    assert!(event.get("serial_number").is_none());
    assert_eq!(
        event["event_type_authentication"],
        "unverified_server_metadata_without_disclosed_witness"
    );
    let feed_text = String::from_utf8(feed_body.to_vec()).unwrap();
    assert!(!feed_text.contains(wallet));
    assert!(!feed_text.contains(hostile));
}

#[tokio::test]
async fn participant_detail_routes_require_operator_auth() {
    let app = test_app();
    for path in [
        "/miner/private-subject",
        "/miner/private-subject/status",
        "/miner/private-subject/verify",
        "/lifecycle/private-subject",
        "/invoice/private-invoice",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn agent_event_subject_cannot_diverge_from_stored_identity() {
    let digest = "a".repeat(64);
    let mismatched = serde_json::json!({
        "event_type": "AGENT_REGISTER",
        "wallet_hash": "wallet_a",
        "agent_id": "agent_b",
        "pubkey_hash": digest,
        "model_hash": "b".repeat(64),
        "policy_hash": "c".repeat(64),
    })
    .to_string();
    let app = test_app();
    let rejected = app
        .clone()
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(mismatched))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let matched = serde_json::json!({
        "event_type": "AGENT_REGISTER",
        "wallet_hash": "agent_b",
        "agent_id": "agent_b",
        "pubkey_hash": "a".repeat(64),
        "model_hash": "b".repeat(64),
        "policy_hash": "c".repeat(64),
    })
    .to_string();
    let created = app
        .oneshot(
            Request::post("/event")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test_key")
                .body(Body::from(matched))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(created.into_body(), 10_000)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["subject_kind"], "agent");
    assert_eq!(json["subject_id"], "agent_b");
    assert_eq!(json["wallet_hash"], "agent_b");
}
