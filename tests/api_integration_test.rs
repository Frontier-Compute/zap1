//! Integration tests for the ZAP1 HTTP API.
//! Tests endpoints that don't require a real UFVK or chain connection.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn test_app() -> axum::Router {
    // protocol/info and badge endpoints don't need UFVK or DB
    // We test them directly via the router
    let db = std::sync::Arc::new(zap1::db::Db::open(":memory:").unwrap());
    let config = std::sync::Arc::new(zap1::config::Config::test_defaults());

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
    assert_eq!(json["version"], "3.0.0");
    assert_eq!(json["deployed_types"], 15);
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
                    r#"{"event_type":"GOVERNANCE_PROPOSAL","wallet_hash":"dao","proposal_id":"p1","proposal_hash":"abc123"}"#,
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
