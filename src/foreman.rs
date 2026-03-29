//! Foreman API client for miner monitoring.
//! Pulls miner status from Foreman dashboard and serves it through
//! our privacy proxy - participants see their machine data without
//! needing a Foreman account or revealing their identity.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const FOREMAN_API: &str = "https://api.foreman.mn/api/v2";

#[derive(Debug, Clone)]
pub struct ForemanClient {
    client: reqwest::Client,
    api_key: String,
    client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerStatus {
    pub miner_id: u64,
    pub name: String,
    pub status: String,
    pub hashrate: f64,
    pub hashrate_unit: String,
    pub temp: Option<f64>,
    pub fan_speed: Option<u32>,
    pub pool: Option<String>,
    pub uptime: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ForemanMinersResponse {
    #[allow(dead_code)]
    total: u64,
    results: Vec<ForemanMiner>,
}

#[derive(Debug, Deserialize)]
struct ForemanMiner {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, rename = "hashrateAvg")]
    hashrate_avg: Option<f64>,
    #[serde(default, rename = "hashrateUnit")]
    hashrate_unit: Option<String>,
    #[serde(default, rename = "tempAvg")]
    temp_avg: Option<f64>,
    #[serde(default, rename = "fanSpeedAvg")]
    fan_speed_avg: Option<u32>,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default, rename = "lastSeen")]
    last_seen: Option<String>,
}

impl ForemanClient {
    pub fn new(api_key: &str, client_id: &str) -> Self {
        ForemanClient {
            client: reqwest::Client::new(),
            api_key: api_key.to_string(),
            client_id: client_id.to_string(),
        }
    }

    pub async fn get_all_miners(&self) -> Result<Vec<MinerStatus>> {
        let url = format!("{}/clients/{}/miners", FOREMAN_API, self.client_id);

        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Token {}", self.api_key))
            .send()
            .await
            .context("Foreman API request failed")?;

        let data: ForemanMinersResponse = resp.json().await
            .context("Foreman API parse failed")?;

        Ok(data.results.into_iter().map(|m| MinerStatus {
            miner_id: m.id,
            name: m.name.unwrap_or_else(|| format!("Miner-{}", m.id)),
            status: m.state.unwrap_or_else(|| "unknown".to_string()),
            hashrate: m.hashrate_avg.unwrap_or(0.0),
            hashrate_unit: m.hashrate_unit.unwrap_or_else(|| "KH/s".to_string()),
            temp: m.temp_avg,
            fan_speed: m.fan_speed_avg,
            pool: m.pool,
            uptime: None,
            last_seen: m.last_seen,
        }).collect())
    }

    pub async fn get_miner(&self, miner_id: u64) -> Result<Option<MinerStatus>> {
        let url = format!("{}/clients/{}/miners/{}", FOREMAN_API, self.client_id, miner_id);

        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Token {}", self.api_key))
            .send()
            .await
            .context("Foreman API request failed")?;

        if resp.status() == 404 {
            return Ok(None);
        }

        let m: ForemanMiner = resp.json().await
            .context("Foreman miner parse failed")?;

        Ok(Some(MinerStatus {
            miner_id: m.id,
            name: m.name.unwrap_or_else(|| format!("Miner-{}", m.id)),
            status: m.state.unwrap_or_else(|| "unknown".to_string()),
            hashrate: m.hashrate_avg.unwrap_or(0.0),
            hashrate_unit: m.hashrate_unit.unwrap_or_else(|| "KH/s".to_string()),
            temp: m.temp_avg,
            fan_speed: m.fan_speed_avg,
            pool: m.pool,
            uptime: None,
            last_seen: m.last_seen,
        }))
    }

    pub async fn reboot_miner(&self, miner_id: u64) -> Result<bool> {
        let url = format!("{}/actions/reboot/{}", FOREMAN_API, miner_id);

        let resp = self.client
            .post(&url)
            .header("Authorization", format!("Token {}", self.api_key))
            .send()
            .await
            .context("Foreman reboot failed")?;

        Ok(resp.status().is_success())
    }
}
