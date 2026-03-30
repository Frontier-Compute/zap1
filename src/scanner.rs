use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use zcash_client_backend::decrypt_transaction;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::config::Config;
use crate::db::Db;
use crate::models::InvoiceStatus;
use crate::node::NodeBackend;

/// The main scanning loop. Polls the node backend for new blocks and attempts
/// trial decryption of every transaction using the UFVK to detect incoming
/// Orchard payments.
///
/// The `backend` parameter abstracts over the chain data source  - either
/// Zebra JSON-RPC (default) or Zaino gRPC (set ZAINO_GRPC_URL to enable).
pub async fn scan_loop(
    config: Arc<Config>,
    db: Arc<Db>,
    ufvk: Arc<UnifiedFullViewingKey>,
    backend: Arc<dyn NodeBackend>,
) {
    // Build the UFVK map for decrypt_transaction
    let mut ufvks: HashMap<u32, UnifiedFullViewingKey> = HashMap::new();
    ufvks.insert(0u32, (*ufvk).clone());

    tracing::info!("Scanner starting");

    loop {
        if let Err(e) = scan_once(&*backend, &config, &db, &ufvks).await {
            tracing::warn!("Scan error: {:#}", e);
        }

        // Scan mempool for unconfirmed payments (faster detection)
        if let Err(e) = scan_mempool(&*backend, &config, &db, &ufvks).await {
            tracing::debug!("Mempool scan: {:#}", e);
        }

        if let Err(e) = db.expire_old_invoices() {
            tracing::warn!("Expiry error: {:#}", e);
        }

        sleep(Duration::from_secs(15)).await;
    }
}

async fn scan_once(
    backend: &dyn NodeBackend,
    config: &Config,
    db: &Db,
    ufvks: &HashMap<u32, UnifiedFullViewingKey>,
) -> Result<()> {
    let chain_height = backend.get_chain_height().await?;

    let (last_scanned, _) = db.get_scan_state()?;
    let start = if last_scanned == 0 {
        config.scan_from_height
    } else {
        last_scanned + 1
    };

    if start > chain_height {
        return Ok(());
    }

    // Get active invoices for address matching
    let active_invoices = db.get_active_invoices()?;
    if active_invoices.is_empty() {
        // No pending invoices  - advance by one batch max, don't skip to tip.
        // This prevents missing payments if an invoice is created between scans.
        let safe_height = start.saturating_add(500).min(chain_height);
        db.set_last_scanned_height(safe_height)?;
        return Ok(());
    }

    let blocks_to_scan = (chain_height - start + 1).min(500); // larger batch for faster catch-up
    let end = start + blocks_to_scan - 1;
    let program_entry_candidates = db
        .list_paid_program_invoices_without_entry()?
        .into_iter()
        .filter_map(|invoice| invoice.paid_txid.clone().map(|txid| (txid, invoice)))
        .collect::<HashMap<_, _>>();

    tracing::info!(
        "Scanning blocks {} to {} ({} active invoices)",
        start,
        end,
        active_invoices.len()
    );

    for height in start..=end {
        let txids = backend.get_block_txids(height).await?;

        for txid_str in &txids {
            let raw = match backend.get_raw_transaction(txid_str).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("Skip tx {}: {}", txid_str, e);
                    continue;
                }
            };

            // Determine branch ID for this height
            let block_height = BlockHeight::from_u32(height);
            let branch_id = BranchId::for_height(&config.network, block_height);

            // Parse the transaction
            let tx = match Transaction::read(&raw[..], branch_id) {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("Skip tx parse {}: {}", txid_str, e);
                    continue;
                }
            };

            // Trial decrypt with our UFVK
            let decrypted =
                decrypt_transaction(&config.network, Some(block_height), None, &tx, ufvks);

            // Check Orchard outputs
            for output in decrypted.orchard_outputs() {
                let value_zat = output.note_value().into_u64();

                // Get the recipient address from the note to match against invoices
                let recipient = output.note().recipient();

                // Try to match against active invoice addresses
                // We need to compare the Orchard address from the note against
                // our generated addresses
                for invoice in &active_invoices {
                    if let Ok(ua) =
                        crate::keys::unified_address_at(&ufvks[&0u32], invoice.diversifier_index)
                    {
                        if let Some(orchard_addr) = ua.orchard() {
                            if *orchard_addr == recipient {
                                tracing::info!(
                                    "Payment detected: {} zat for invoice {} (tx {})",
                                    value_zat,
                                    invoice.id,
                                    txid_str
                                );
                                let transitioned_to_paid = db.record_payment(
                                    &invoice.id,
                                    value_zat,
                                    txid_str,
                                    height,
                                    "block",
                                )?;

                                // Send Signal notification
                                if let Ok(Some(updated)) = db.get_invoice(&invoice.id) {
                                    if transitioned_to_paid && updated.status == InvoiceStatus::Paid
                                    {
                                        if let Some(wallet_hash) = updated.wallet_hash.as_deref() {
                                            create_lifecycle_leaf_for_invoice(
                                                db,
                                                &updated,
                                                wallet_hash,
                                            );
                                        }
                                    }

                                    let nc = config.clone();
                                    let txid_owned = txid_str.to_string();
                                    tokio::spawn(async move {
                                        crate::notify::payment_received(
                                            &nc,
                                            &updated,
                                            value_zat,
                                            &txid_owned,
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Also log Sapling outputs (primary matching is via Orchard address)
            for output in decrypted.sapling_outputs() {
                let value_zat = output.note_value().into_u64();
                tracing::info!(
                    "Sapling output detected: {} zat (tx {})  - manual matching needed",
                    value_zat,
                    txid_str
                );
            }

            if let Some(invoice) = program_entry_candidates.get(txid_str) {
                if let Some(wallet_hash) = invoice.wallet_hash.as_deref() {
                    let (leaf, root) = db.insert_program_entry_leaf(wallet_hash)?;
                    tracing::info!(
                        "Confirmed starter-pack payment committed to Merkle tree: invoice={} leaf={} root={}",
                        invoice.id,
                        leaf.leaf_hash,
                        root.root_hash
                    );
                }
            }
        }

        db.set_last_scanned_height(height)?;
    }

    Ok(())
}

/// Scan the mempool for unconfirmed transactions. Detects payments
/// before they're mined, giving ~75 seconds faster response.
async fn scan_mempool(
    backend: &dyn NodeBackend,
    config: &Config,
    db: &Db,
    ufvks: &HashMap<u32, UnifiedFullViewingKey>,
) -> Result<()> {
    let active_invoices = db.get_active_invoices()?;
    if active_invoices.is_empty() {
        return Ok(());
    }

    // Get mempool transaction IDs
    let txids = backend.get_mempool_txids().await?;

    if txids.is_empty() {
        return Ok(());
    }

    // Get chain tip for branch ID
    let chain_height = backend.get_chain_height().await?;
    let block_height = BlockHeight::from_u32(chain_height);
    let branch_id = BranchId::for_height(&config.network, block_height);

    for txid_str in &txids {
        let raw = match backend.get_raw_transaction(txid_str).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let tx = match Transaction::read(&raw[..], branch_id) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let decrypted = decrypt_transaction(&config.network, None, Some(block_height), &tx, ufvks);

        for output in decrypted.orchard_outputs() {
            let value_zat = output.note_value().into_u64();
            let recipient = output.note().recipient();

            for invoice in &active_invoices {
                if let Ok(ua) =
                    crate::keys::unified_address_at(&ufvks[&0u32], invoice.diversifier_index)
                {
                    if let Some(orchard_addr) = ua.orchard() {
                        if *orchard_addr == recipient {
                            tracing::info!(
                                "MEMPOOL payment detected: {} zat for invoice {} (tx {})",
                                value_zat,
                                invoice.id,
                                txid_str
                            );
                            // Record as payment (will be confirmed when block is mined)
                            let transitioned = db.record_payment(
                                &invoice.id,
                                value_zat,
                                txid_str,
                                chain_height,
                                "mempool",
                            )?;

                            if let Ok(Some(updated)) = db.get_invoice(&invoice.id) {
                                if transitioned
                                    && updated.status == crate::models::InvoiceStatus::Paid
                                {
                                    if let Some(wallet_hash) = updated.wallet_hash.as_deref() {
                                        create_lifecycle_leaf_for_invoice(
                                            db,
                                            &updated,
                                            wallet_hash,
                                        );
                                    }
                                }

                                let nc = config.clone();
                                let txid_owned = txid_str.to_string();
                                tokio::spawn(async move {
                                    crate::notify::payment_received(
                                        &nc,
                                        &updated,
                                        value_zat,
                                        &txid_owned,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Create the appropriate lifecycle Merkle leaf when an invoice is paid.
/// Maps invoice_type to the correct event type:
///   "program" | "initial" → PROGRAM_ENTRY
///   "hosting"             → HOSTING_PAYMENT (needs serial from miner_assignments)
///   "renewal"             → SHIELD_RENEWAL
fn create_lifecycle_leaf_for_invoice(db: &Db, invoice: &crate::models::Invoice, wallet_hash: &str) {
    let result = match invoice.invoice_type.as_str() {
        "program" | "initial" => db
            .insert_program_entry_leaf(wallet_hash)
            .map(|(leaf, root)| {
                tracing::info!(
                    "PROGRAM_ENTRY committed: leaf={} root={}",
                    leaf.leaf_hash,
                    root.root_hash
                );
            }),
        "hosting" => {
            // Parse month/year from memo (format: "NS-hosting-YYYY-MM-...")
            // or fall back to current date
            let (month, year) = parse_hosting_period(invoice.memo.as_deref());
            // Need a serial  - look up from miner_assignments
            match db.get_miner_by_wallet_hash(wallet_hash) {
                Ok(Some((_addr, serial, _fid))) => db
                    .insert_hosting_payment_leaf(wallet_hash, &serial, month, year)
                    .map(|(leaf, root)| {
                        tracing::info!(
                            "HOSTING_PAYMENT committed: leaf={} root={} serial={} period={}-{}",
                            leaf.leaf_hash,
                            root.root_hash,
                            serial,
                            year,
                            month
                        );
                    }),
                _ => {
                    tracing::warn!(
                        "Hosting payment for {} but no miner assignment found  - skipping leaf",
                        wallet_hash
                    );
                    Ok(())
                }
            }
        }
        "renewal" => {
            let year = parse_renewal_year(invoice.memo.as_deref());
            db.insert_shield_renewal_leaf(wallet_hash, year)
                .map(|(leaf, root)| {
                    tracing::info!(
                        "SHIELD_RENEWAL committed: leaf={} root={} year={}",
                        leaf.leaf_hash,
                        root.root_hash,
                        year
                    );
                })
        }
        _ => Ok(()),
    };

    if let Err(e) = result {
        tracing::warn!(
            "Failed to create lifecycle leaf for invoice {}: {}",
            invoice.id,
            e
        );
    }
}

/// Parse hosting period from memo like "NS-hosting-2026-07-..." → (7, 2026)
fn parse_hosting_period(memo: Option<&str>) -> (u32, u32) {
    if let Some(memo) = memo {
        let parts: Vec<&str> = memo.split('-').collect();
        // Expected: ["NS", "hosting", "2026", "07", ...]
        if parts.len() >= 4 {
            if let (Ok(year), Ok(month)) = (parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
                return (month, year);
            }
        }
    }
    let now = chrono::Utc::now();
    (
        now.format("%m").to_string().parse().unwrap_or(1),
        now.format("%Y").to_string().parse().unwrap_or(2026),
    )
}

/// Parse renewal year from memo like "NS-renewal-2027-..." → 2027
fn parse_renewal_year(memo: Option<&str>) -> u32 {
    if let Some(memo) = memo {
        let parts: Vec<&str> = memo.split('-').collect();
        if parts.len() >= 3 {
            if let Ok(year) = parts[2].parse::<u32>() {
                return year;
            }
        }
    }
    chrono::Utc::now()
        .format("%Y")
        .to_string()
        .parse()
        .unwrap_or(2026)
}

// Anchor automation is now in anchor.rs (spawned from main.rs)
