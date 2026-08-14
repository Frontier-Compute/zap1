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
use crate::node::NodeBackend;
use crate::wallet::AnchorWallet;

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
    wallet: Option<Arc<AnchorWallet>>,
) {
    // Build the UFVK map for decrypt_transaction
    let mut ufvks: HashMap<u32, UnifiedFullViewingKey> = HashMap::new();
    ufvks.insert(0u32, (*ufvk).clone());

    tracing::info!("Scanner starting");

    loop {
        if let Err(e) = scan_once(&*backend, &config, &db, &ufvks, wallet.as_deref()).await {
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
    wallet: Option<&AnchorWallet>,
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
        let mut block_raw_txs: Vec<(String, Vec<u8>)> = Vec::new();

        for txid_str in &txids {
            let raw = match backend.get_raw_transaction(txid_str).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("Skip tx {}: {}", txid_str, e);
                    continue;
                }
            };
            block_raw_txs.push((txid_str.clone(), raw.clone()));

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

            // A transaction can contain several outputs to one invoice. Record
            // the transaction once with the sum of all matching Orchard outputs.
            let mut matched_payments: HashMap<usize, u64> = HashMap::new();
            for output in decrypted.orchard_outputs() {
                let value_zat = output.note_value().into_u64();
                let recipient = output.note().recipient();

                for (invoice_index, invoice) in active_invoices.iter().enumerate() {
                    if let Ok(ua) =
                        crate::keys::unified_address_at(&ufvks[&0u32], invoice.diversifier_index)
                    {
                        if let Some(orchard_addr) = ua.orchard() {
                            if *orchard_addr == recipient {
                                accumulate_payment_value(
                                    &mut matched_payments,
                                    invoice_index,
                                    value_zat,
                                )?;
                            }
                        }
                    }
                }
            }

            for (invoice_index, value_zat) in matched_payments {
                let invoice = &active_invoices[invoice_index];
                tracing::info!(
                    "Confirmed payment detected: {} zat for invoice {} (tx {})",
                    value_zat,
                    invoice.id,
                    txid_str
                );
                let outcome =
                    db.record_confirmed_payment(&invoice.id, value_zat, txid_str, height)?;

                if outcome.lifecycle_leaf_created {
                    tracing::info!(
                        "Confirmed payment lifecycle leaf committed: invoice={} leaf={}",
                        invoice.id,
                        outcome.lifecycle_leaf_hash.as_deref().unwrap_or("unknown")
                    );
                }
                if outcome.newly_recorded {
                    let updated = db
                        .get_invoice(&invoice.id)?
                        .ok_or_else(|| anyhow::anyhow!("paid invoice disappeared"))?;
                    let nc = config.clone();
                    let txid_owned = txid_str.to_string();
                    tokio::spawn(async move {
                        crate::notify::payment_received(&nc, &updated, value_zat, &txid_owned)
                            .await;
                    });
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

        // Feed block transactions to anchor wallet for commitment tree + note detection
        if let Some(w) = wallet {
            if !block_raw_txs.is_empty() {
                if let Err(e) = w.process_block_commitments(height, &block_raw_txs, &config.network)
                {
                    tracing::debug!("Wallet block {} processing: {}", height, e);
                }
            }
        }

        db.set_last_scanned_height(height)?;
    }

    // Mark wallet recovery complete after catching up to chain tip
    if let Some(w) = wallet {
        if !w.recovery_done() {
            w.mark_recovery_done();
            tracing::info!(
                "Wallet recovery complete: balance {} zat,  {} notes",
                w.balance(),
                w.unspent_count()
            );
        }
    }

    Ok(())
}

/// Independent wallet recovery scan.  Runs once on startup.
/// Scans from seed height to chain tip,  feeding every block's raw TXs
/// to the wallet for commitment tree tracking and note detection.
/// This is separate from the main scanner because the main scanner's
/// last_scanned_height is already at tip and skips historical blocks.
pub async fn wallet_recovery_scan(
    backend: &dyn NodeBackend,
    config: &Config,
    wallet: &AnchorWallet,
) -> Result<()> {
    if wallet.recovery_done() {
        return Ok(());
    }

    let chain_height = backend.get_chain_height().await?;

    // Re-seed the tree at a recent height to avoid 14K+ block divergence.
    // The wallet only needs notes received recently.  Seeding near the tip
    // gives a valid tree root with minimal blocks to process.
    let reseed_height = chain_height.saturating_sub(1500);
    if reseed_height > config.scan_from_height {
        tracing::info!(
            "Wallet recovery: re-seeding tree at height {} (was {})",
            reseed_height,
            config.scan_from_height
        );
        wallet
            .init_from_zebra(&config.zebra_rpc_url, reseed_height + 1)
            .await?;
    }

    let start = if reseed_height > config.scan_from_height {
        reseed_height + 1
    } else {
        config.scan_from_height
    };

    if start >= chain_height {
        wallet.mark_recovery_done();
        return Ok(());
    }

    let total = chain_height - start;
    tracing::info!(
        "Wallet recovery: rescanning {} to {} for missed notes ({} blocks)",
        start,
        chain_height,
        total
    );

    let batch_size = 100u32;
    let mut current = start;

    while current <= chain_height {
        let end = (current + batch_size - 1).min(chain_height);

        for height in current..=end {
            let txids = match backend.get_block_txids(height).await {
                Ok(t) => t,
                Err(_) => continue,
            };

            let mut block_raw_txs: Vec<(String, Vec<u8>)> = Vec::new();
            for txid_str in &txids {
                if let Ok(raw) = backend.get_raw_transaction(txid_str).await {
                    block_raw_txs.push((txid_str.clone(), raw));
                }
            }

            if !block_raw_txs.is_empty() {
                if let Err(e) =
                    wallet.process_block_commitments(height, &block_raw_txs, &config.network)
                {
                    tracing::debug!("Wallet recovery block {}: {}", height, e);
                }
            }
        }

        current = end + 1;

        // Log progress every 1000 blocks
        if (current - start) % 1000 < batch_size {
            let progress = ((current - start) as f64 / total as f64 * 100.0).min(100.0);
            tracing::info!(
                "Wallet recovery: {:.1}% ({}/{}) balance {} zat",
                progress,
                current - start,
                total,
                wallet.balance()
            );
        }
    }

    wallet.mark_recovery_done();
    tracing::info!(
        "Wallet recovery complete: balance {} zat,  {} notes",
        wallet.balance(),
        wallet.unspent_count()
    );

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
                            db.observe_mempool_payment(&invoice.id, value_zat, txid_str)?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn accumulate_payment_value(
    matched_payments: &mut HashMap<usize, u64>,
    invoice_index: usize,
    value_zat: u64,
) -> Result<()> {
    let total = matched_payments.entry(invoice_index).or_default();
    *total = total
        .checked_add(value_zat)
        .ok_or_else(|| anyhow::anyhow!("payment value overflow"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::accumulate_payment_value;
    use crate::db::Db;
    use crate::models::{Invoice, InvoiceStatus};
    use std::collections::HashMap;

    fn invoice(
        id: &str,
        invoice_type: &str,
        wallet_hash: Option<&str>,
        amount_zat: u64,
    ) -> Invoice {
        Invoice {
            id: id.to_string(),
            diversifier_index: 1,
            address: "u1test".to_string(),
            amount_zat,
            memo: None,
            invoice_type: invoice_type.to_string(),
            wallet_hash: wallet_hash.map(str::to_string),
            status: InvoiceStatus::Pending,
            received_zat: 0,
            created_at: "2026-08-13T00:00:00Z".to_string(),
            expires_at: None,
            paid_at: None,
            paid_txid: None,
            paid_height: None,
        }
    }

    #[test]
    fn mempool_only_then_eviction_leaves_invoice_pending_without_evidence() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-mempool",
            "program",
            Some("wallet-mempool"),
            50_000,
        ))
        .unwrap();

        db.observe_mempool_payment("invoice-mempool", 50_000, "mempool-tx")
            .unwrap();

        let stored = db.get_invoice("invoice-mempool").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Pending);
        assert_eq!(stored.received_zat, 0);
        assert_eq!(
            db.payment_state_counts("invoice-mempool").unwrap(),
            (0, 0, 0)
        );
    }

    #[test]
    fn several_outputs_in_one_transaction_are_recorded_as_one_payment() {
        let mut matches = HashMap::new();
        accumulate_payment_value(&mut matches, 4, 20_000).unwrap();
        accumulate_payment_value(&mut matches, 4, 30_000).unwrap();
        assert_eq!(matches, HashMap::from([(4, 50_000)]));
    }

    #[test]
    fn failed_lifecycle_materialization_rolls_back_and_retry_converges_once() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-hosting",
            "hosting",
            Some("wallet-hosting"),
            75_000,
        ))
        .unwrap();

        let first = db.record_confirmed_payment(
            "invoice-hosting",
            75_000,
            "confirmed-hosting-tx",
            3_400_001,
        );
        assert!(first.is_err());
        let stored = db.get_invoice("invoice-hosting").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Pending);
        assert_eq!(stored.received_zat, 0);
        assert_eq!(
            db.payment_state_counts("invoice-hosting").unwrap(),
            (0, 0, 0)
        );

        db.assign_miner("wallet-hosting", "u1hosting", "serial-hosting", None)
            .unwrap();
        let retried = db
            .record_confirmed_payment("invoice-hosting", 75_000, "confirmed-hosting-tx", 3_400_001)
            .unwrap();
        assert!(retried.newly_recorded);
        assert!(retried.transitioned_to_paid);
        assert!(retried.lifecycle_leaf_created);

        let replayed = db
            .record_confirmed_payment("invoice-hosting", 75_000, "confirmed-hosting-tx", 3_400_001)
            .unwrap();
        assert!(!replayed.newly_recorded);
        assert!(!replayed.transitioned_to_paid);
        assert!(!replayed.lifecycle_leaf_created);
        assert_eq!(
            db.payment_state_counts("invoice-hosting").unwrap(),
            (1, 1, 1)
        );
    }

    #[test]
    fn confirmed_partial_payments_sum_before_one_paid_transition() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-partial",
            "program",
            Some("wallet-partial"),
            100_000,
        ))
        .unwrap();

        let partial = db
            .record_confirmed_payment("invoice-partial", 60_000, "confirmed-partial-a", 3_400_010)
            .unwrap();
        assert!(partial.newly_recorded);
        assert!(!partial.transitioned_to_paid);
        assert!(partial.lifecycle_leaf_hash.is_none());
        let stored = db.get_invoice("invoice-partial").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Partial);
        assert_eq!(stored.received_zat, 60_000);

        let paid = db
            .record_confirmed_payment("invoice-partial", 40_000, "confirmed-partial-b", 3_400_011)
            .unwrap();
        assert!(paid.newly_recorded);
        assert!(paid.transitioned_to_paid);
        assert!(paid.lifecycle_leaf_created);
        let stored = db.get_invoice("invoice-partial").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Paid);
        assert_eq!(stored.received_zat, 100_000);
        assert_eq!(
            db.payment_state_counts("invoice-partial").unwrap(),
            (2, 1, 1)
        );
    }

    #[test]
    fn confirmed_payment_commits_one_transition_and_one_leaf() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-program",
            "program",
            Some("wallet-program"),
            100_000,
        ))
        .unwrap();

        let confirmed = db
            .record_confirmed_payment(
                "invoice-program",
                100_000,
                "confirmed-program-tx",
                3_400_002,
            )
            .unwrap();
        assert!(confirmed.newly_recorded);
        assert!(confirmed.transitioned_to_paid);
        assert!(confirmed.lifecycle_leaf_created);

        let stored = db.get_invoice("invoice-program").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Paid);
        assert_eq!(stored.received_zat, 100_000);
        assert_eq!(stored.paid_txid.as_deref(), Some("confirmed-program-tx"));
        assert_eq!(stored.paid_height, Some(3_400_002));
        assert_eq!(
            db.payment_state_counts("invoice-program").unwrap(),
            (1, 1, 1)
        );

        let overpayment = db
            .record_confirmed_payment(
                "invoice-program",
                20_000,
                "confirmed-overpayment-tx",
                3_400_003,
            )
            .unwrap();
        assert!(overpayment.newly_recorded);
        assert!(!overpayment.transitioned_to_paid);
        assert!(!overpayment.lifecycle_leaf_created);
        let stored = db.get_invoice("invoice-program").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Paid);
        assert_eq!(stored.received_zat, 120_000);
        assert_eq!(stored.paid_txid.as_deref(), Some("confirmed-program-tx"));
        assert_eq!(
            db.payment_state_counts("invoice-program").unwrap(),
            (2, 1, 1)
        );
    }

    #[test]
    fn legacy_mempool_row_promotes_atomically_on_confirmation() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-legacy",
            "program",
            Some("wallet-legacy"),
            25_000,
        ))
        .unwrap();
        db.insert_legacy_mempool_payment_for_test("invoice-legacy", 25_000, "legacy-mempool-tx")
            .unwrap();

        let promoted = db
            .record_confirmed_payment("invoice-legacy", 25_000, "legacy-mempool-tx", 3_400_003)
            .unwrap();
        assert!(!promoted.newly_recorded);
        assert!(promoted.transitioned_to_paid);
        assert!(promoted.lifecycle_leaf_created);

        let stored = db.get_invoice("invoice-legacy").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Paid);
        assert_eq!(stored.received_zat, 25_000);
        assert_eq!(stored.paid_height, Some(3_400_003));
        assert_eq!(
            db.payment_state_counts("invoice-legacy").unwrap(),
            (1, 1, 1)
        );
    }

    #[test]
    fn stranded_block_row_reconciles_on_retry() {
        let db = Db::open(":memory:").unwrap();
        db.create_invoice(&invoice(
            "invoice-stranded",
            "program",
            Some("wallet-stranded"),
            30_000,
        ))
        .unwrap();
        db.insert_legacy_block_payment_for_test(
            "invoice-stranded",
            30_000,
            "stranded-block-tx",
            3_400_004,
        )
        .unwrap();

        let repaired = db
            .record_confirmed_payment("invoice-stranded", 30_000, "stranded-block-tx", 3_400_004)
            .unwrap();
        assert!(!repaired.newly_recorded);
        assert!(repaired.transitioned_to_paid);
        assert!(repaired.lifecycle_leaf_created);

        let stored = db.get_invoice("invoice-stranded").unwrap().unwrap();
        assert_eq!(stored.status, InvoiceStatus::Paid);
        assert_eq!(stored.received_zat, 30_000);
        assert_eq!(
            db.payment_state_counts("invoice-stranded").unwrap(),
            (1, 1, 1)
        );
    }
}

// Anchor automation is now in anchor.rs (spawned from main.rs)
