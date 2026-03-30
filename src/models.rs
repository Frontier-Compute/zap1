use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub diversifier_index: u32,
    pub address: String,
    pub amount_zat: u64,
    pub memo: Option<String>,
    pub invoice_type: String,
    pub wallet_hash: Option<String>,
    pub status: InvoiceStatus,
    pub received_zat: u64,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub paid_at: Option<String>,
    pub paid_txid: Option<String>,
    pub paid_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceStatus {
    Pending,
    Partial,
    Paid,
    Expired,
}

impl InvoiceStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Partial => "partial",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "partial" => Self::Partial,
            "paid" => Self::Paid,
            "expired" => Self::Expired,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateInvoiceRequest {
    pub amount_zec: f64,
    pub memo: Option<String>,
    pub expires_in_hours: Option<u64>,
    #[serde(default = "default_invoice_type")]
    pub invoice_type: String,
    pub wallet_hash: Option<String>,
}

fn default_invoice_type() -> String {
    "program".to_string()
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub last_scanned_height: u32,
    pub chain_tip: u32,
    pub sync_lag: u32,
    pub pending_invoices: usize,
    pub scanner_operational: bool,
    pub network: String,
    pub rpc_reachable: bool,
}
