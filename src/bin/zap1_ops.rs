use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
enum InputSource {
    Live { base_url: String },
    FixtureDir { dir: PathBuf },
}

#[derive(Debug)]
struct Cli {
    source: InputSource,
    json: bool,
    max_sync_lag: u32,
    max_anchor_age_hours: i64,
}

#[derive(Debug, Deserialize)]
struct ProtocolInfo {
    protocol: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    last_scanned_height: u32,
    chain_tip: u32,
    sync_lag: u32,
    pending_invoices: usize,
    scanner_operational: bool,
    network: String,
    rpc_reachable: bool,
}

#[derive(Debug, Deserialize)]
struct StatsResponse {
    total_anchors: usize,
    total_leaves: usize,
    first_anchor_block: Option<u32>,
    last_anchor_block: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AnchorStatusResponse {
    current_root: String,
    leaf_count: usize,
    unanchored_leaves: u32,
    last_anchor_txid: Option<String>,
    last_anchor_height: Option<u32>,
    needs_anchor: bool,
    recommendation: String,
}

#[derive(Debug, Deserialize)]
struct AnchorHistoryResponse {
    anchors: Vec<AnchorRecord>,
    last_anchor_age_hours: Option<i64>,
    total: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct AnchorRecord {
    created_at: String,
    height: Option<u32>,
    leaf_count: usize,
    root: String,
    txid: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpsReport {
    status: &'static str,
    protocol: String,
    version: String,
    network: String,
    scanner: ScannerSummary,
    anchors: AnchorSummary,
    queue: QueueSummary,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScannerSummary {
    operational: bool,
    rpc_reachable: bool,
    last_scanned_height: u32,
    chain_tip: u32,
    sync_lag: u32,
}

#[derive(Debug, Serialize)]
struct AnchorSummary {
    total_anchors: usize,
    total_leaves: usize,
    first_anchor_block: Option<u32>,
    last_anchor_block: Option<u32>,
    last_anchor_age_hours: Option<i64>,
    current_root: String,
    current_root_leaf_count: usize,
    unanchored_leaves: u32,
    needs_anchor: bool,
    recommendation: String,
    last_recorded_transaction_root: Option<String>,
    last_recorded_transaction_txid: Option<String>,
    last_recorded_transaction_height: Option<u32>,
    last_recorded_transaction_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueueSummary {
    pending_invoices: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;
    let protocol =
        load_json::<ProtocolInfo>(&cli.source, "protocol_info.json", "/protocol/info").await?;
    let health = load_json::<HealthResponse>(&cli.source, "health.json", "/health").await?;
    let stats = load_json::<StatsResponse>(&cli.source, "stats.json", "/stats").await?;
    let anchor_status =
        load_json::<AnchorStatusResponse>(&cli.source, "anchor_status.json", "/anchor/status")
            .await?;
    let anchor_history =
        load_json::<AnchorHistoryResponse>(&cli.source, "anchor_history.json", "/anchor/history")
            .await?;

    let report = evaluate(
        &protocol,
        &health,
        &stats,
        &anchor_status,
        &anchor_history,
        &cli,
    );
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text_report(&report);
    }

    if !report.errors.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut base_url = String::from("http://127.0.0.1:3080");
    let mut fixture_dir: Option<PathBuf> = None;
    let mut json = false;
    let mut max_sync_lag = 100;
    let mut max_anchor_age_hours = 72;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base-url" => {
                base_url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --base-url"))?;
            }
            "--from-dir" => {
                let dir = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --from-dir"))?;
                fixture_dir = Some(PathBuf::from(dir));
            }
            "--json" => json = true,
            "--max-sync-lag" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --max-sync-lag"))?;
                max_sync_lag = value.parse().context("invalid value for --max-sync-lag")?;
            }
            "--max-anchor-age-hours" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --max-anchor-age-hours"))?;
                max_anchor_age_hours = value
                    .parse()
                    .context("invalid value for --max-anchor-age-hours")?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    let source = match fixture_dir {
        Some(dir) => InputSource::FixtureDir { dir },
        None => InputSource::Live { base_url },
    };

    Ok(Cli {
        source,
        json,
        max_sync_lag,
        max_anchor_age_hours,
    })
}

async fn load_json<T>(source: &InputSource, fixture_name: &str, path: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    match source {
        InputSource::FixtureDir { dir } => {
            let raw = fs::read_to_string(dir.join(fixture_name)).with_context(|| {
                format!(
                    "failed to read fixture {}",
                    dir.join(fixture_name).display()
                )
            })?;
            serde_json::from_str(&raw)
                .with_context(|| format!("invalid fixture JSON: {fixture_name}"))
        }
        InputSource::Live { base_url } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .context("failed to build HTTP client")?;
            let raw = client
                .get(format!("{}{}", base_url.trim_end_matches('/'), path))
                .send()
                .await
                .with_context(|| format!("failed to fetch {path}"))?
                .error_for_status()
                .with_context(|| format!("non-success response for {path}"))?
                .text()
                .await
                .with_context(|| format!("failed to read response body for {path}"))?;
            serde_json::from_str(&raw).with_context(|| format!("invalid JSON at {path}"))
        }
    }
}

fn evaluate(
    protocol: &ProtocolInfo,
    health: &HealthResponse,
    stats: &StatsResponse,
    anchor_status: &AnchorStatusResponse,
    anchor_history: &AnchorHistoryResponse,
    cli: &Cli,
) -> OpsReport {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if protocol.protocol != "ZAP1" {
        errors.push(format!("protocol mismatch: {}", protocol.protocol));
    }

    if !health.rpc_reachable {
        errors.push("zebra rpc is unreachable".to_string());
    }

    if !health.scanner_operational {
        errors.push("scanner is not operational".to_string());
    }

    if health.sync_lag > cli.max_sync_lag {
        errors.push(format!(
            "scan lag {} exceeds threshold {}",
            health.sync_lag, cli.max_sync_lag
        ));
    }

    if anchor_history.total != anchor_history.anchors.len() {
        errors.push(format!(
            "anchor history count mismatch: total={} anchors={}",
            anchor_history.total,
            anchor_history.anchors.len()
        ));
    }

    if stats.total_anchors != anchor_history.total {
        errors.push(format!(
            "anchor total mismatch: stats={} history={}",
            stats.total_anchors, anchor_history.total
        ));
    }

    if anchor_status.leaf_count > stats.total_leaves {
        errors.push(format!(
            "current root leaf_count {} exceeds total leaves {}",
            anchor_status.leaf_count, stats.total_leaves
        ));
    }

    if let Some(last_anchor) = anchor_history.anchors.last() {
        if last_anchor.height != anchor_status.last_anchor_height {
            errors.push(format!(
                "latest anchor height mismatch: history={:?} status={:?}",
                last_anchor.height, anchor_status.last_anchor_height
            ));
        }
        if last_anchor.txid != anchor_status.last_anchor_txid {
            errors.push(format!(
                "latest anchor txid mismatch: history={:?} status={:?}",
                last_anchor.txid, anchor_status.last_anchor_txid
            ));
        }
        if last_anchor.height != stats.last_anchor_block {
            errors.push(format!(
                "last anchor block mismatch: history={:?} stats={:?}",
                last_anchor.height, stats.last_anchor_block
            ));
        }
        if last_anchor.leaf_count > stats.total_leaves {
            errors.push(format!(
                "latest anchored root leaf_count {} exceeds total leaves {}",
                last_anchor.leaf_count, stats.total_leaves
            ));
        }
    }

    if let Some(last_age) = anchor_history.last_anchor_age_hours {
        if last_age > cli.max_anchor_age_hours {
            let message = format!(
                "last anchor age {}h exceeds threshold {}h",
                last_age, cli.max_anchor_age_hours
            );
            if anchor_status.needs_anchor || anchor_status.unanchored_leaves > 0 {
                errors.push(message);
            } else {
                warnings.push(message);
            }
        }
    } else {
        warnings.push("last anchor age is unknown".to_string());
    }

    if anchor_status.unanchored_leaves > 0 {
        warnings.push(format!(
            "unanchored leaves pending: {}",
            anchor_status.unanchored_leaves
        ));
    }

    if anchor_status.needs_anchor {
        warnings.push(format!(
            "anchor action recommended: {}",
            anchor_status.recommendation
        ));
    }

    if health.pending_invoices > 0 {
        warnings.push(format!(
            "pending invoices in queue: {}",
            health.pending_invoices
        ));
    }

    let last_recorded_transaction = anchor_history
        .anchors
        .iter()
        .rev()
        .find(|anchor| anchor.txid.is_some() && anchor.height.is_some())
        .cloned();
    let status = if !errors.is_empty() {
        "critical"
    } else if !warnings.is_empty() {
        "warn"
    } else {
        "ok"
    };

    OpsReport {
        status,
        protocol: protocol.protocol.clone(),
        version: protocol.version.clone(),
        network: health.network.clone(),
        scanner: ScannerSummary {
            operational: health.scanner_operational,
            rpc_reachable: health.rpc_reachable,
            last_scanned_height: health.last_scanned_height,
            chain_tip: health.chain_tip,
            sync_lag: health.sync_lag,
        },
        anchors: AnchorSummary {
            total_anchors: stats.total_anchors,
            total_leaves: stats.total_leaves,
            first_anchor_block: stats.first_anchor_block,
            last_anchor_block: stats.last_anchor_block,
            last_anchor_age_hours: anchor_history.last_anchor_age_hours,
            current_root: anchor_status.current_root.clone(),
            current_root_leaf_count: anchor_status.leaf_count,
            unanchored_leaves: anchor_status.unanchored_leaves,
            needs_anchor: anchor_status.needs_anchor,
            recommendation: anchor_status.recommendation.clone(),
            last_recorded_transaction_root: last_recorded_transaction
                .as_ref()
                .map(|anchor| anchor.root.clone()),
            last_recorded_transaction_txid: last_recorded_transaction
                .as_ref()
                .and_then(|anchor| anchor.txid.clone()),
            last_recorded_transaction_height: last_recorded_transaction
                .as_ref()
                .and_then(|anchor| anchor.height),
            last_recorded_transaction_at: last_recorded_transaction
                .as_ref()
                .and_then(|anchor| parse_rfc3339_utc(&anchor.created_at)),
        },
        queue: QueueSummary {
            pending_invoices: health.pending_invoices,
        },
        warnings,
        errors,
    }
}

fn print_text_report(report: &OpsReport) {
    println!("status: {}", report.status);
    println!(
        "protocol: {} {} on {}",
        report.protocol, report.version, report.network
    );
    println!(
        "scanner: operational={} rpc_reachable={} lag={} last_scanned={} chain_tip={}",
        report.scanner.operational,
        report.scanner.rpc_reachable,
        report.scanner.sync_lag,
        report.scanner.last_scanned_height,
        report.scanner.chain_tip,
    );
    println!(
        "anchors: total={} leaves={} last_block={:?} last_age_hours={:?}",
        report.anchors.total_anchors,
        report.anchors.total_leaves,
        report.anchors.last_anchor_block,
        report.anchors.last_anchor_age_hours,
    );
    println!(
        "root: {} leaf_count={} unanchored={} needs_anchor={}",
        report.anchors.current_root,
        report.anchors.current_root_leaf_count,
        report.anchors.unanchored_leaves,
        report.anchors.needs_anchor,
    );
    println!(
        "last recorded transaction reference: root={} height={:?} txid={}",
        report
            .anchors
            .last_recorded_transaction_root
            .as_deref()
            .unwrap_or("none"),
        report.anchors.last_recorded_transaction_height,
        report
            .anchors
            .last_recorded_transaction_txid
            .as_deref()
            .unwrap_or("none"),
    );
    println!("queue: pending_invoices={}", report.queue.pending_invoices);

    if !report.warnings.is_empty() {
        println!("warnings:");
        for warning in &report.warnings {
            println!("- {}", warning);
        }
    }

    if !report.errors.is_empty() {
        println!("errors:");
        for error in &report.errors {
            println!("- {}", error);
        }
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc).to_rfc3339())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zap1_ops");
    eprintln!("  zap1_ops --json");
    eprintln!("  zap1_ops --base-url http://127.0.0.1:3080");
    eprintln!("  zap1_ops --from-dir examples/zap1_ops_fixture --json");
    eprintln!("  zap1_ops --max-sync-lag 100 --max-anchor-age-hours 72");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cli() -> Cli {
        Cli {
            source: InputSource::FixtureDir {
                dir: PathBuf::from("examples/zap1_ops_fixture"),
            },
            json: true,
            max_sync_lag: 100,
            max_anchor_age_hours: 72,
        }
    }

    fn base_protocol() -> ProtocolInfo {
        ProtocolInfo {
            protocol: "ZAP1".to_string(),
            version: "2.2.0".to_string(),
        }
    }

    fn base_health() -> HealthResponse {
        HealthResponse {
            last_scanned_height: 3290812,
            chain_tip: 3290812,
            sync_lag: 0,
            pending_invoices: 0,
            scanner_operational: true,
            network: "MainNetwork".to_string(),
            rpc_reachable: true,
        }
    }

    fn base_stats() -> StatsResponse {
        StatsResponse {
            total_anchors: 3,
            total_leaves: 12,
            first_anchor_block: Some(3286631),
            last_anchor_block: Some(3288022),
        }
    }

    fn base_anchor_status() -> AnchorStatusResponse {
        AnchorStatusResponse {
            current_root: "437e12dd66cfcb9e0277b231efabd3ebeb1cc8c0e612bb4ee97c04b93c1f1745"
                .to_string(),
            leaf_count: 12,
            unanchored_leaves: 0,
            last_anchor_txid: Some(
                "dfab64cd1114371ceb9e7a38fa9ea0ca880767fc71f7832b7c3873205659ff5c".to_string(),
            ),
            last_anchor_height: Some(3288022),
            needs_anchor: false,
            recommendation: "up to date".to_string(),
        }
    }

    fn base_anchor_history() -> AnchorHistoryResponse {
        AnchorHistoryResponse {
            anchors: vec![AnchorRecord {
                created_at: "2026-03-28T08:27:34.257951207+00:00".to_string(),
                height: Some(3288022),
                leaf_count: 12,
                root: "437e12dd66cfcb9e0277b231efabd3ebeb1cc8c0e612bb4ee97c04b93c1f1745"
                    .to_string(),
                txid: Some(
                    "dfab64cd1114371ceb9e7a38fa9ea0ca880767fc71f7832b7c3873205659ff5c".to_string(),
                ),
            }],
            last_anchor_age_hours: Some(24),
            total: 1,
        }
    }

    #[test]
    fn report_is_ok_when_inputs_match() {
        let cli = base_cli();
        let mut stats = base_stats();
        let history = base_anchor_history();
        stats.total_anchors = 1;
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &base_anchor_status(),
            &history,
            &cli,
        );
        assert_eq!(report.status, "ok");
        assert!(report.errors.is_empty());
        assert!(report.warnings.is_empty());
        assert_eq!(
            report.anchors.last_recorded_transaction_height,
            Some(3288022)
        );
    }

    #[test]
    fn report_warns_on_unanchored_work() {
        let cli = base_cli();
        let mut stats = base_stats();
        let mut status = base_anchor_status();
        let mut history = base_anchor_history();
        stats.total_anchors = 1;
        status.unanchored_leaves = 2;
        status.needs_anchor = true;
        status.recommendation = "anchor when convenient".to_string();
        history.last_anchor_age_hours = Some(12);
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &status,
            &history,
            &cli,
        );
        assert_eq!(report.status, "warn");
        assert!(report.errors.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|item| item.contains("unanchored leaves")));
    }

    #[test]
    fn report_handles_no_anchor_history() {
        let cli = base_cli();
        let stats = StatsResponse {
            total_anchors: 0,
            total_leaves: 0,
            first_anchor_block: None,
            last_anchor_block: None,
        };
        let status = AnchorStatusResponse {
            current_root: "none".to_string(),
            leaf_count: 0,
            unanchored_leaves: 0,
            last_anchor_txid: None,
            last_anchor_height: None,
            needs_anchor: false,
            recommendation: "up to date".to_string(),
        };
        let history = AnchorHistoryResponse {
            anchors: Vec::new(),
            last_anchor_age_hours: None,
            total: 0,
        };
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &status,
            &history,
            &cli,
        );
        assert_eq!(report.status, "warn");
        assert!(report.errors.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|item| item.contains("last anchor age is unknown")));
    }

    #[test]
    fn report_warns_when_anchor_is_old_but_queue_is_empty() {
        let cli = base_cli();
        let mut stats = base_stats();
        let mut history = base_anchor_history();
        stats.total_anchors = 1;
        history.last_anchor_age_hours = Some(96);
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &base_anchor_status(),
            &history,
            &cli,
        );
        assert_eq!(report.status, "warn");
        assert!(report.errors.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|item| item.contains("last anchor age 96h exceeds threshold 72h")));
    }

    #[test]
    fn report_is_critical_when_anchor_is_old_and_work_is_waiting() {
        let cli = base_cli();
        let mut stats = base_stats();
        let mut status = base_anchor_status();
        let mut history = base_anchor_history();
        stats.total_anchors = 1;
        status.unanchored_leaves = 3;
        status.needs_anchor = true;
        history.last_anchor_age_hours = Some(96);
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &status,
            &history,
            &cli,
        );
        assert_eq!(report.status, "critical");
        assert!(report
            .errors
            .iter()
            .any(|item| item.contains("last anchor age 96h exceeds threshold 72h")));
    }

    #[test]
    fn report_is_critical_on_protocol_mismatch() {
        let cli = base_cli();
        let mut stats = base_stats();
        let history = base_anchor_history();
        stats.total_anchors = 1;
        let protocol = ProtocolInfo {
            protocol: "NSM1".to_string(),
            version: "2.2.0".to_string(),
        };
        let report = evaluate(
            &protocol,
            &base_health(),
            &stats,
            &base_anchor_status(),
            &history,
            &cli,
        );
        assert_eq!(report.status, "critical");
        assert!(report
            .errors
            .iter()
            .any(|item| item.contains("protocol mismatch")));
    }

    #[test]
    fn report_is_critical_on_anchor_mismatch() {
        let cli = base_cli();
        let mut stats = base_stats();
        let mut status = base_anchor_status();
        let history = base_anchor_history();
        stats.total_anchors = 1;
        status.last_anchor_height = Some(1);
        let report = evaluate(
            &base_protocol(),
            &base_health(),
            &stats,
            &status,
            &history,
            &cli,
        );
        assert_eq!(report.status, "critical");
        assert!(report
            .errors
            .iter()
            .any(|item| item.contains("height mismatch")));
    }
}
