use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;

use crate::memo::{
    hash_contract_anchor, hash_deployment, hash_exit, hash_hosting_payment, hash_ownership_attest,
    hash_program_entry, hash_shield_renewal, hash_transfer, MemoType,
};
use crate::merkle::{
    compute_root, decode_hash, generate_proof, MerkleLeafRecord, MerkleRootRecord,
    VerificationBundle,
};
use crate::models::{Invoice, InvoiceStatus};

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))
    }

    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open database")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .context("Failed to set pragmas")?;

        let schema = include_str!("../migrations/001_init.sql");
        conn.execute_batch(schema)
            .context("Failed to initialize schema")?;

        // Migrate existing invoices table if needed (add new columns)
        let has_invoice_type: bool = conn
            .prepare("SELECT invoice_type FROM invoices LIMIT 0")
            .is_ok();
        if !has_invoice_type {
            conn.execute_batch(
                "ALTER TABLE invoices ADD COLUMN invoice_type TEXT NOT NULL DEFAULT 'program';
                 ALTER TABLE invoices ADD COLUMN wallet_hash TEXT;",
            )
            .context("Failed to migrate invoices table")?;
        }

        // Ensure scan_state row exists
        conn.execute(
            "INSERT OR IGNORE INTO scan_state (id, last_scanned_height, next_diversifier_index) VALUES (1, 0, 1)",
            [],
        )?;

        // Clamp impossible historical root metadata. A root cannot cover more
        // leaves than currently exist in the Merkle leaf table.
        conn.execute(
            "UPDATE merkle_roots
             SET leaf_count = (SELECT COUNT(*) FROM merkle_leaves)
             WHERE leaf_count > (SELECT COUNT(*) FROM merkle_leaves)",
            [],
        )?;

        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_scan_state(&self) -> Result<(u32, u32)> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT last_scanned_height, next_diversifier_index FROM scan_state WHERE id = 1",
        )?;
        let (height, next_idx) =
            stmt.query_row([], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)))?;
        Ok((height, next_idx))
    }

    pub fn set_last_scanned_height(&self, height: u32) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scan_state SET last_scanned_height = ?1 WHERE id = 1",
            params![height],
        )?;
        Ok(())
    }

    pub fn allocate_diversifier_index(&self) -> Result<u32> {
        let conn = self.conn()?;
        let idx: u32 = conn.query_row(
            "SELECT next_diversifier_index FROM scan_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        conn.execute(
            "UPDATE scan_state SET next_diversifier_index = ?1 WHERE id = 1",
            params![idx + 1],
        )?;
        Ok(idx)
    }

    pub fn create_invoice(&self, invoice: &Invoice) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO invoices (id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                invoice.id,
                invoice.diversifier_index,
                invoice.address,
                invoice.amount_zat as i64,
                invoice.memo,
                invoice.invoice_type,
                invoice.wallet_hash,
                invoice.status.as_str(),
                invoice.received_zat as i64,
                invoice.created_at,
                invoice.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_invoice(&self, id: &str) -> Result<Option<Invoice>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height
             FROM invoices WHERE id = ?1",
        )?;
        let result = stmt.query_row(params![id], |row| {
            Ok(Invoice {
                id: row.get(0)?,
                diversifier_index: row.get(1)?,
                address: row.get(2)?,
                amount_zat: row.get::<_, i64>(3)? as u64,
                memo: row.get(4)?,
                invoice_type: row.get(5)?,
                wallet_hash: row.get(6)?,
                status: InvoiceStatus::from_str(&row.get::<_, String>(7)?),
                received_zat: row.get::<_, i64>(8)? as u64,
                created_at: row.get(9)?,
                expires_at: row.get(10)?,
                paid_at: row.get(11)?,
                paid_txid: row.get(12)?,
                paid_height: row.get(13)?,
            })
        });
        match result {
            Ok(inv) => Ok(Some(inv)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_invoices(&self, status_filter: Option<&str>) -> Result<Vec<Invoice>> {
        let conn = self.conn()?;
        let sql = match status_filter {
            Some(_) => "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height FROM invoices WHERE status = ?1 ORDER BY created_at DESC",
            None => "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height FROM invoices ORDER BY created_at DESC",
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = if let Some(status) = status_filter {
            stmt.query_map(params![status], row_to_invoice)?
        } else {
            stmt.query_map([], row_to_invoice)?
        };
        let mut invoices = Vec::new();
        for row in rows {
            invoices.push(row?);
        }
        Ok(invoices)
    }

    /// Get all pending/partial invoices with their addresses for payment matching.
    pub fn get_active_invoices(&self) -> Result<Vec<Invoice>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height
             FROM invoices WHERE status IN ('pending', 'partial')",
        )?;
        let rows = stmt.query_map([], row_to_invoice)?;
        let mut invoices = Vec::new();
        for row in rows {
            invoices.push(row?);
        }
        Ok(invoices)
    }

    /// Record a payment against an invoice. Deduplicates by (invoice_id, txid).
    /// Returns true if this payment transitioned the invoice to "paid" status.
    pub fn record_payment(
        &self,
        invoice_id: &str,
        received_zat: u64,
        txid: &str,
        height: u32,
        source: &str,
    ) -> Result<bool> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();

        // Dedup: skip if this (invoice_id, txid) was already recorded
        let already_recorded: bool = conn
            .prepare("SELECT 1 FROM payment_records WHERE invoice_id = ?1 AND txid = ?2 LIMIT 1")?
            .query_row(params![invoice_id, txid], |_| Ok(true))
            .unwrap_or(false);

        if already_recorded {
            // Update height if we now have a confirmed block height
            if source == "block" {
                conn.execute(
                    "UPDATE payment_records SET height = ?1, source = 'block' WHERE invoice_id = ?2 AND txid = ?3",
                    params![height as i64, invoice_id, txid],
                )?;
                conn.execute(
                    "UPDATE invoices SET paid_height = ?1 WHERE id = ?2 AND (paid_txid = ?3 OR paid_height IS NULL)",
                    params![height as i64, invoice_id, txid],
                )?;
            }
            return Ok(false);
        }

        // Record this payment
        conn.execute(
            "INSERT INTO payment_records (invoice_id, txid, value_zat, height, source, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![invoice_id, txid, received_zat as i64, height as i64, source, now],
        )?;

        // Get current invoice state
        let (current_received, amount_zat): (i64, i64) = conn.query_row(
            "SELECT received_zat, amount_zat FROM invoices WHERE id = ?1",
            params![invoice_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let new_received = current_received + received_zat as i64;
        let new_status = if new_received >= amount_zat {
            "paid"
        } else {
            "partial"
        };
        let transitioned_to_paid = current_received < amount_zat && new_received >= amount_zat;

        conn.execute(
            "UPDATE invoices SET received_zat = ?1, status = ?2, paid_at = ?3, paid_txid = ?4, paid_height = ?5 WHERE id = ?6",
            params![new_received, new_status, now, txid, height as i64, invoice_id],
        )?;
        Ok(transitioned_to_paid)
    }

    /// Expire invoices past their expiry time.
    pub fn expire_old_invoices(&self) -> Result<usize> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE invoices SET status = 'expired' WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < ?1",
            params![now],
        )?;
        Ok(changed)
    }

    pub fn count_pending(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM invoices WHERE status IN ('pending', 'partial')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // Miner assignments

    pub fn assign_miner(
        &self,
        wallet_hash: &str,
        wallet_address: &str,
        serial_number: &str,
        foreman_miner_id: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO miner_assignments (wallet_hash, wallet_address, serial_number, foreman_miner_id, assigned_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![wallet_hash, wallet_address, serial_number, foreman_miner_id.map(|id| id as i64), now],
        )?;
        Ok(())
    }

    pub fn get_miner_by_wallet_hash(
        &self,
        wallet_hash: &str,
    ) -> Result<Option<(String, String, Option<u64>)>> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT wallet_address, serial_number, foreman_miner_id FROM miner_assignments WHERE wallet_hash = ?1 LIMIT 1",
            params![wallet_hash],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?.map(|id| id as u64),
            )),
        );
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get ALL miners for a wallet hash (multi-miner support)
    pub fn get_miners_by_wallet_hash(
        &self,
        wallet_hash: &str,
    ) -> Result<Vec<(String, String, Option<u64>)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT wallet_address, serial_number, foreman_miner_id FROM miner_assignments WHERE wallet_hash = ?1"
        )?;
        let rows = stmt.query_map(params![wallet_hash], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?.map(|id| id as u64),
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get invoices for a specific wallet hash
    pub fn get_invoices_by_wallet(&self, wallet_hash: &str) -> Result<Vec<Invoice>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height
             FROM invoices WHERE wallet_hash = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![wallet_hash], row_to_invoice)?;
        let mut invoices = Vec::new();
        for row in rows {
            invoices.push(row?);
        }
        Ok(invoices)
    }

    /// Check if a hosting invoice already exists for this wallet/month/year
    pub fn has_hosting_invoice(&self, wallet_hash: &str, month: u32, year: u32) -> Result<bool> {
        let conn = self.conn()?;
        let memo_pattern = format!("NS-hosting-{}-{:02}-{}", year, month, wallet_hash);
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM invoices WHERE wallet_hash = ?1 AND memo LIKE ?2 AND invoice_type = 'hosting')",
            params![wallet_hash, format!("{}%", memo_pattern)],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    /// Get count of active miners
    pub fn count_active_miners(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: usize = conn.query_row(
            "SELECT COUNT(DISTINCT wallet_hash) FROM miner_assignments",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get total machines
    pub fn count_total_machines(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: usize = conn.query_row("SELECT COUNT(*) FROM miner_assignments", [], |row| {
            row.get(0)
        })?;
        Ok(count)
    }

    pub fn list_miner_assignments(&self) -> Result<Vec<(String, String, String, Option<u64>)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT wallet_hash, wallet_address, serial_number, foreman_miner_id FROM miner_assignments"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?.map(|id| id as u64),
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn list_paid_program_invoices_without_entry(&self) -> Result<Vec<Invoice>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height
             FROM invoices
             WHERE status = 'paid'
               AND wallet_hash IS NOT NULL
               AND invoice_type IN ('program', 'initial')
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], row_to_invoice)?;
        let mut invoices = Vec::new();
        for row in rows {
            let invoice = row?;
            if let Some(wallet_hash) = invoice.wallet_hash.as_deref() {
                if !has_merkle_leaf(&conn, MemoType::ProgramEntry, wallet_hash, None)? {
                    invoices.push(invoice);
                }
            }
        }
        Ok(invoices)
    }

    pub fn insert_program_entry_leaf(
        &self,
        wallet_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        self.insert_merkle_leaf(MemoType::ProgramEntry, wallet_hash, None)
    }

    pub fn insert_ownership_leaf(
        &self,
        wallet_hash: &str,
        serial_number: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        self.insert_merkle_leaf(MemoType::OwnershipAttest, wallet_hash, Some(serial_number))
    }

    /// 0x03 CONTRACT_ANCHOR: hash(serial_number || contract_sha256)
    pub fn insert_contract_anchor_leaf(
        &self,
        wallet_hash: &str,
        serial_number: &str,
        contract_sha256: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_contract_anchor(serial_number, contract_sha256));
        self.insert_leaf_raw(
            MemoType::ContractAnchor,
            &leaf_hash,
            wallet_hash,
            Some(serial_number),
        )
    }

    /// 0x04 DEPLOYMENT: hash(serial_number || facility_id || timestamp)
    pub fn insert_deployment_leaf(
        &self,
        wallet_hash: &str,
        serial_number: &str,
        facility_id: &str,
        timestamp: u64,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_deployment(serial_number, facility_id, timestamp));
        self.insert_leaf_raw(
            MemoType::Deployment,
            &leaf_hash,
            wallet_hash,
            Some(serial_number),
        )
    }

    /// 0x05 HOSTING_PAYMENT: hash(serial_number || month || year)
    pub fn insert_hosting_payment_leaf(
        &self,
        wallet_hash: &str,
        serial_number: &str,
        month: u32,
        year: u32,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_hosting_payment(serial_number, month, year));
        self.insert_leaf_raw(
            MemoType::HostingPayment,
            &leaf_hash,
            wallet_hash,
            Some(serial_number),
        )
    }

    /// 0x06 SHIELD_RENEWAL: hash(wallet_hash || year)
    pub fn insert_shield_renewal_leaf(
        &self,
        wallet_hash: &str,
        year: u32,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_shield_renewal(wallet_hash, year));
        self.insert_leaf_raw(MemoType::ShieldRenewal, &leaf_hash, wallet_hash, None)
    }

    /// 0x07 TRANSFER: hash(old_wallet || new_wallet || serial_number)
    pub fn insert_transfer_leaf(
        &self,
        old_wallet_hash: &str,
        new_wallet_hash: &str,
        serial_number: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_transfer(
            old_wallet_hash,
            new_wallet_hash,
            serial_number,
        ));
        self.insert_leaf_raw(
            MemoType::Transfer,
            &leaf_hash,
            old_wallet_hash,
            Some(serial_number),
        )
    }

    /// 0x08 EXIT: hash(wallet_hash || serial_number || timestamp)
    pub fn insert_exit_leaf(
        &self,
        wallet_hash: &str,
        serial_number: &str,
        timestamp: u64,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_exit(wallet_hash, serial_number, timestamp));
        self.insert_leaf_raw(MemoType::Exit, &leaf_hash, wallet_hash, Some(serial_number))
    }

    /// Get all Merkle leaves for a wallet hash (lifecycle timeline).
    pub fn get_leaves_by_wallet(&self, wallet_hash: &str) -> Result<Vec<MerkleLeafRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT leaf_hash, event_type, wallet_hash, serial_number, created_at
             FROM merkle_leaves
             WHERE wallet_hash = ?1
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![wallet_hash], |row| {
            let event_type_raw: i64 = row.get(1)?;
            let event_type = MemoType::from_u8(event_type_raw as u8)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(MerkleLeafRecord {
                leaf_hash: row.get(0)?,
                event_type,
                wallet_hash: row.get(2)?,
                serial_number: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        let mut leaves = Vec::new();
        for row in rows {
            leaves.push(row?);
        }
        Ok(leaves)
    }

    /// Get aggregate stats for the /stats endpoint.
    pub fn get_stats(&self) -> Result<(usize, usize, Option<u32>, Option<u32>)> {
        let conn = self.conn()?;
        let total_leaves: usize =
            conn.query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))?;
        let total_anchors: usize = conn.query_row(
            "SELECT COUNT(*) FROM merkle_roots WHERE anchor_txid IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let last_anchor_height: Option<i64> = conn.query_row(
            "SELECT MAX(anchor_height) FROM merkle_roots WHERE anchor_txid IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let first_anchor_height: Option<i64> = conn.query_row(
            "SELECT MIN(anchor_height) FROM merkle_roots WHERE anchor_txid IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok((
            total_leaves,
            total_anchors,
            first_anchor_height.map(|h| h as u32),
            last_anchor_height.map(|h| h as u32),
        ))
    }

    /// Find the anchor root that covers a given leaf (for lifecycle timeline).
    pub fn get_root_covering_leaf(&self, leaf_id_approx: &str) -> Result<Option<MerkleRootRecord>> {
        let conn = self.conn()?;
        // Get the leaf's position
        let leaf_pos: Option<i64> = conn
            .query_row(
                "SELECT id FROM merkle_leaves WHERE leaf_hash = ?1",
                params![leaf_id_approx],
                |row| row.get(0),
            )
            .ok();
        let Some(pos) = leaf_pos else {
            return Ok(None);
        };
        // Find the smallest root whose leaf_count >= this leaf's position
        let result = conn.query_row(
            "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
             FROM merkle_roots
             WHERE leaf_count >= ?1 AND anchor_txid IS NOT NULL
             ORDER BY id ASC
             LIMIT 1",
            params![pos],
            |row| {
                Ok(MerkleRootRecord {
                    root_hash: row.get(0)?,
                    leaf_count: row.get::<_, i64>(1)? as usize,
                    anchor_txid: row.get(2)?,
                    anchor_height: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                    created_at: row.get(4)?,
                })
            },
        );
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn current_merkle_root(&self) -> Result<Option<MerkleRootRecord>> {
        let conn = self.conn()?;
        current_root(&conn)
    }

    /// Count leaves added since the last anchored root.
    pub fn unanchored_leaf_count(&self) -> Result<u32> {
        let conn = self.conn()?;
        // Find the leaf count at the last anchored root
        let last_anchored: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(leaf_count), 0) FROM merkle_roots WHERE anchor_txid IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))
            .unwrap_or(0);
        Ok((total - last_anchored).max(0) as u32)
    }

    pub fn record_merkle_anchor(
        &self,
        root_hash: &str,
        txid: &str,
        height: Option<u32>,
    ) -> Result<()> {
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE merkle_roots
             SET anchor_txid = ?1, anchor_height = ?2
             WHERE id = (
                 SELECT id FROM merkle_roots
                 WHERE root_hash = ?3
                 ORDER BY id DESC
                 LIMIT 1
             )",
            params![txid, height.map(|value| value as i64), root_hash],
        )?;

        anyhow::ensure!(updated > 0, "no Merkle root record found for {root_hash}");
        Ok(())
    }

    pub fn record_merkle_anchor_height(&self, txid: &str, height: u32) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE merkle_roots SET anchor_height = ?1 WHERE anchor_txid = ?2",
            params![height as i64, txid],
        )?;
        Ok(())
    }

    // Webhook management

    pub fn create_webhooks_table(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        )?;
        Ok(())
    }

    pub fn register_webhook(&self, id: &str, url: &str, secret: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO webhooks (id, url, secret) VALUES (?1, ?2, ?3)",
            params![id, url, secret],
        )?;
        Ok(())
    }

    pub fn list_webhooks(&self) -> Result<Vec<crate::webhook::WebhookRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, url, secret FROM webhooks")?;
        let hooks = stmt
            .query_map([], |row| {
                Ok(crate::webhook::WebhookRecord {
                    id: row.get(0)?,
                    url: row.get(1)?,
                    secret: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(hooks)
    }

    pub fn delete_webhook(&self, id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let deleted = conn.execute("DELETE FROM webhooks WHERE id = ?1", params![id])?;
        Ok(deleted > 0)
    }

    pub fn leaf_counts_by_type(&self) -> Result<Vec<(i32, i64)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) FROM merkle_leaves GROUP BY event_type ORDER BY event_type"
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn total_leaf_count(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    pub fn all_anchored_roots(&self) -> Result<Vec<crate::merkle::MerkleRootRecord>> {
        let conn = self.conn()?;
        let total_leaves = total_leaf_count_conn(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
             FROM merkle_roots ORDER BY id ASC",
        )?;
        let roots = stmt
            .query_map([], |row| {
                let leaf_count =
                    normalize_root_leaf_count(row.get::<_, i64>(1)? as usize, total_leaves);
                Ok(crate::merkle::MerkleRootRecord {
                    root_hash: row.get(0)?,
                    leaf_count,
                    anchor_txid: row.get(2)?,
                    anchor_height: row.get::<_, Option<i64>>(3)?.map(|h| h as u32),
                    created_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(roots)
    }

    pub fn get_verification_bundle(&self, leaf_hash: &str) -> Result<Option<VerificationBundle>> {
        let conn = self.conn()?;
        let all_leaves = merkle_leaves(&conn)?;
        let Some(index) = all_leaves
            .iter()
            .position(|leaf| leaf.leaf_hash == leaf_hash)
        else {
            return Ok(None);
        };

        // Find the smallest anchored root that covers this leaf (stable proof)
        let leaf_position = index + 1; // 1-based leaf count
        let covering_root = conn.query_row(
            "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
             FROM merkle_roots
             WHERE leaf_count >= ?1 AND anchor_txid IS NOT NULL
             ORDER BY leaf_count ASC
             LIMIT 1",
            params![leaf_position as i64],
            |row| {
                Ok(MerkleRootRecord {
                    root_hash: row.get(0)?,
                    leaf_count: row.get::<_, i64>(1)? as usize,
                    anchor_txid: row.get(2)?,
                    anchor_height: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                    created_at: row.get(4)?,
                })
            },
        );

        // Use covering anchored root if available, otherwise fall back to current root
        let (root, leaf_set_size) = match covering_root {
            Ok(r) => {
                let size = r.leaf_count;
                (r, size)
            }
            Err(_) => {
                // No anchored root covers this leaf yet - use current root
                match current_root(&conn)? {
                    Some(r) => {
                        let size = r.leaf_count;
                        (r, size)
                    }
                    None => return Ok(None),
                }
            }
        };

        // Generate proof using only the leaves covered by this root
        let leaves_for_proof: Vec<&MerkleLeafRecord> =
            all_leaves.iter().take(leaf_set_size).collect();
        let leaf_bytes: Vec<[u8; 32]> = leaves_for_proof
            .iter()
            .map(|leaf| decode_hash(&leaf.leaf_hash))
            .collect::<Result<Vec<_>>>()?;

        let proof = generate_proof(&leaf_bytes, index);
        Ok(Some(VerificationBundle {
            leaf: all_leaves[index].clone(),
            proof,
            root,
        }))
    }

    /// Insert a leaf with a pre-computed hash (for new event types 0x03-0x08).
    /// Uses BEGIN IMMEDIATE transaction to prevent race conditions on concurrent inserts.
    fn insert_leaf_raw(
        &self,
        event_type: MemoType,
        leaf_hash: &str,
        wallet_hash: &str,
        serial_number: Option<&str>,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let conn = self.conn()?;
        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
            let created_at = chrono::Utc::now().to_rfc3339();
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO merkle_leaves (leaf_hash, event_type, wallet_hash, serial_number, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    leaf_hash,
                    event_type.as_u8() as i64,
                    wallet_hash,
                    serial_number,
                    created_at,
                ],
            )?;

            if inserted > 0 {
                let leaves = merkle_leaves(&conn)?;
                let leaf_hashes: Vec<[u8; 32]> = leaves
                    .iter()
                    .map(|leaf| decode_hash(&leaf.leaf_hash))
                    .collect::<Result<Vec<_>>>()?;
                let root_hash = hex::encode(compute_root(&leaf_hashes));
                conn.execute(
                    "INSERT INTO merkle_roots (root_hash, leaf_count, created_at) VALUES (?1, ?2, ?3)",
                    params![root_hash, leaves.len() as i64, chrono::Utc::now().to_rfc3339()],
                )?;
            }

            let leaf = merkle_leaf_by_hash(&conn, leaf_hash)?
                .context("Merkle leaf insert/query failed")?;
            let root = current_root(&conn)?.context("Merkle root missing after leaf insert")?;
            Ok((leaf, root))
        })();

        match &result {
            Ok(_) => {
                conn.execute("COMMIT", [])?;
            }
            Err(_) => {
                let _ = conn.execute("ROLLBACK", []);
            }
        }
        result
    }

    fn insert_merkle_leaf(
        &self,
        event_type: MemoType,
        wallet_hash: &str,
        serial_number: Option<&str>,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let conn = self.conn()?;
        let leaf_hash = match event_type {
            MemoType::ProgramEntry => hex::encode(hash_program_entry(wallet_hash)),
            MemoType::OwnershipAttest => {
                let serial_number =
                    serial_number.context("serial number required for ownership leaf")?;
                hex::encode(hash_ownership_attest(wallet_hash, serial_number))
            }
            MemoType::MerkleRoot => anyhow::bail!("Merkle root records are not stored as leaves"),
            _ => anyhow::bail!("Use the dedicated insert method for {:?}", event_type),
        };

        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| -> Result<()> {
            let created_at = chrono::Utc::now().to_rfc3339();
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO merkle_leaves (leaf_hash, event_type, wallet_hash, serial_number, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    leaf_hash,
                    event_type.as_u8() as i64,
                    wallet_hash,
                    serial_number,
                    created_at,
                ],
            )?;

            if inserted > 0 {
                let leaves = merkle_leaves(&conn)?;
                let leaf_hashes: Vec<[u8; 32]> = leaves
                    .iter()
                    .map(|leaf| decode_hash(&leaf.leaf_hash))
                    .collect::<Result<Vec<_>>>()?;
                let root_hash = hex::encode(compute_root(&leaf_hashes));
                conn.execute(
                    "INSERT INTO merkle_roots (root_hash, leaf_count, created_at) VALUES (?1, ?2, ?3)",
                    params![root_hash, leaves.len() as i64, chrono::Utc::now().to_rfc3339()],
                )?;
            }
            Ok(())
        })();

        match &result {
            Ok(_) => {
                conn.execute("COMMIT", [])?;
            }
            Err(_) => {
                let _ = conn.execute("ROLLBACK", []);
            }
        }
        result?;

        let leaf =
            merkle_leaf_by_hash(&conn, &leaf_hash)?.context("Merkle leaf insert/query failed")?;
        let root = current_root(&conn)?.context("Merkle root missing after leaf insert")?;

        Ok((leaf, root))
    }
}

fn row_to_invoice(row: &rusqlite::Row) -> rusqlite::Result<Invoice> {
    Ok(Invoice {
        id: row.get(0)?,
        diversifier_index: row.get(1)?,
        address: row.get(2)?,
        amount_zat: row.get::<_, i64>(3)? as u64,
        memo: row.get(4)?,
        invoice_type: row.get(5)?,
        wallet_hash: row.get(6)?,
        status: InvoiceStatus::from_str(&row.get::<_, String>(7)?),
        received_zat: row.get::<_, i64>(8)? as u64,
        created_at: row.get(9)?,
        expires_at: row.get(10)?,
        paid_at: row.get(11)?,
        paid_txid: row.get(12)?,
        paid_height: row.get(13)?,
    })
}

fn has_merkle_leaf(
    conn: &Connection,
    event_type: MemoType,
    wallet_hash: &str,
    serial_number: Option<&str>,
) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT 1
         FROM merkle_leaves
         WHERE event_type = ?1 AND wallet_hash = ?2 AND COALESCE(serial_number, '') = COALESCE(?3, '')
         LIMIT 1",
    )?;
    let result = stmt.query_row(
        params![event_type.as_u8() as i64, wallet_hash, serial_number],
        |_| Ok(()),
    );
    match result {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn merkle_leaves(conn: &Connection) -> Result<Vec<MerkleLeafRecord>> {
    let mut stmt = conn.prepare(
        "SELECT leaf_hash, event_type, wallet_hash, serial_number, created_at
         FROM merkle_leaves
         ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        let event_type_raw: i64 = row.get(1)?;
        let event_type =
            MemoType::from_u8(event_type_raw as u8).map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(MerkleLeafRecord {
            leaf_hash: row.get(0)?,
            event_type,
            wallet_hash: row.get(2)?,
            serial_number: row.get(3)?,
            created_at: row.get(4)?,
        })
    })?;

    let mut leaves = Vec::new();
    for row in rows {
        leaves.push(row?);
    }
    Ok(leaves)
}

fn merkle_leaf_by_hash(conn: &Connection, leaf_hash: &str) -> Result<Option<MerkleLeafRecord>> {
    let mut stmt = conn.prepare(
        "SELECT leaf_hash, event_type, wallet_hash, serial_number, created_at
         FROM merkle_leaves
         WHERE leaf_hash = ?1
         LIMIT 1",
    )?;
    let result = stmt.query_row(params![leaf_hash], |row| {
        let event_type_raw: i64 = row.get(1)?;
        let event_type =
            MemoType::from_u8(event_type_raw as u8).map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(MerkleLeafRecord {
            leaf_hash: row.get(0)?,
            event_type,
            wallet_hash: row.get(2)?,
            serial_number: row.get(3)?,
            created_at: row.get(4)?,
        })
    });
    match result {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn current_root(conn: &Connection) -> Result<Option<MerkleRootRecord>> {
    let total_leaves = total_leaf_count_conn(conn)?;
    let mut stmt = conn.prepare(
        "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
         FROM merkle_roots
         ORDER BY id DESC
         LIMIT 1",
    )?;
    let result = stmt.query_row([], |row| {
        let leaf_count = normalize_root_leaf_count(row.get::<_, i64>(1)? as usize, total_leaves);
        Ok(MerkleRootRecord {
            root_hash: row.get(0)?,
            leaf_count,
            anchor_txid: row.get(2)?,
            anchor_height: row.get::<_, Option<i64>>(3)?.map(|value| value as u32),
            created_at: row.get(4)?,
        })
    });
    match result {
        Ok(root) => Ok(Some(root)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn total_leaf_count_conn(conn: &Connection) -> Result<usize> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))?;
    Ok(count as usize)
}

fn normalize_root_leaf_count(leaf_count: usize, total_leaves: usize) -> usize {
    leaf_count.min(total_leaves)
}

#[cfg(test)]
mod tests {
    use super::normalize_root_leaf_count;

    #[test]
    fn normalize_root_leaf_count_preserves_valid_count() {
        assert_eq!(normalize_root_leaf_count(12, 12), 12);
        assert_eq!(normalize_root_leaf_count(2, 12), 2);
    }

    #[test]
    fn normalize_root_leaf_count_clamps_impossible_count() {
        assert_eq!(normalize_root_leaf_count(13, 12), 12);
    }
}
