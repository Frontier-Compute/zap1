use crate::config::Config;
use crate::models::Invoice;

/// Send a Signal message via signal-cli-rest-api on the VPS.
async fn send_signal(config: &Config, message: &str) {
    let Some(number) = &config.signal_number else {
        return;
    };
    let signal_url = config
        .signal_api_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8431");

    let payload = serde_json::json!({
        "message": message,
        "number": number,
        "recipients": [number]
    });

    let url = format!("{}/v2/send", signal_url);
    match reqwest::Client::new()
        .post(&url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                tracing::warn!("Signal send failed: HTTP {}", resp.status());
            }
        }
        Err(e) => {
            tracing::warn!("Signal send error: {}", e);
        }
    }
}

/// Notify on payment received.
pub async fn payment_received(config: &Config, invoice: &Invoice, amount_zat: u64, txid: &str) {
    let amount_zec = amount_zat as f64 / 100_000_000.0;
    let expected_zec = invoice.amount_zat as f64 / 100_000_000.0;

    let memo = invoice.memo.as_deref().unwrap_or("");

    let msg = format!(
        "Nordic Shield Payment\n\n\
         {:.4} ZEC received (invoice: {:.4} ZEC)\n\
         Status: {}\n\
         Memo: {}\n\
         Invoice: {}\n\
         Tx: {}",
        amount_zec,
        expected_zec,
        invoice.status.as_str(),
        memo,
        &invoice.id[..8],
        &txid[..16.min(txid.len())],
    );

    send_signal(config, &msg).await;

    // Also fire webhook if configured (n8n)
    if let Some(url) = &config.webhook_url {
        let payload = serde_json::json!({
            "event": "payment_received",
            "invoice_id": invoice.id,
            "amount_zec": amount_zec,
            "status": invoice.status.as_str(),
            "memo": memo,
            "txid": txid,
        });
        let _ = reqwest::Client::new().post(url).json(&payload).send().await;
    }
}

/// Notify on invoice created.
pub async fn invoice_created(config: &Config, invoice: &Invoice) {
    let amount_zec = invoice.amount_zat as f64 / 100_000_000.0;

    let memo = invoice.memo.as_deref().unwrap_or("");

    let msg = format!(
        "Nordic Shield Invoice Created\n\n\
         {:.4} ZEC\n\
         Memo: {}\n\
         Invoice: {}\n\
         Address: {}...{}",
        amount_zec,
        memo,
        &invoice.id[..8],
        &invoice.address[..20],
        &invoice.address[invoice.address.len().saturating_sub(8)..],
    );

    send_signal(config, &msg).await;

    if let Some(url) = &config.webhook_url {
        let payload = serde_json::json!({
            "event": "invoice_created",
            "invoice_id": invoice.id,
            "amount_zec": amount_zec,
            "address": invoice.address,
            "memo": memo,
        });
        let _ = reqwest::Client::new().post(url).json(&payload).send().await;
    }
}
