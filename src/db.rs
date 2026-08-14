use anyhow::{Context, Result};
use chrono::Datelike;
use rusqlite::{params, Connection, TransactionBehavior};
use std::fmt;
use std::sync::Mutex;

use crate::memo::{
    hash_contract_anchor, hash_deployment, hash_exit, hash_governance_proposal,
    hash_governance_result, hash_governance_vote, hash_hosting_payment, hash_ownership_attest,
    hash_program_entry, hash_shield_renewal, hash_staking_deposit, hash_staking_reward,
    hash_staking_withdraw, hash_transfer, MemoType,
};
use crate::merkle::{
    compute_legacy_root, compute_root, decode_hash, generate_legacy_proof, generate_proof,
    MerkleLeafRecord, MerkleRootRecord, VerificationBundle,
};
use crate::models::{Invoice, InvoiceStatus};

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBroadcastIntent {
    pub txid: String,
    pub root_hash: String,
    pub leaf_count: usize,
    pub raw_tx_hex: String,
    pub spent_position: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorConfirmation {
    pub txid: String,
    pub root_hash: String,
    pub confirmation_attempts: u32,
}

#[derive(Debug)]
pub(crate) struct AnchorRecordConflict(String);

impl fmt::Display for AnchorRecordConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AnchorRecordConflict {}

fn anchor_record_conflict(message: impl Into<String>) -> anyhow::Error {
    AnchorRecordConflict(message.into()).into()
}

impl AnchorBroadcastIntent {
    fn canonicalized(&self) -> Result<Self> {
        validate_anchor_identity(&self.txid, &self.root_hash)?;
        anyhow::ensure!(self.leaf_count > 0, "anchor leaf count must be positive");
        i64::try_from(self.leaf_count).context("anchor leaf count exceeds SQLite range")?;
        i64::try_from(self.spent_position).context("spent position exceeds SQLite range")?;
        anyhow::ensure!(
            !self.raw_tx_hex.is_empty()
                && self.raw_tx_hex.len() % 2 == 0
                && self.raw_tx_hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "raw anchor transaction must be non-empty, even-length hexadecimal"
        );
        Ok(Self {
            txid: self.txid.to_ascii_lowercase(),
            root_hash: self.root_hash.to_ascii_lowercase(),
            leaf_count: self.leaf_count,
            raw_tx_hex: self.raw_tx_hex.to_ascii_lowercase(),
            spent_position: self.spent_position,
        })
    }
}

fn validate_anchor_identity(txid: &str, root_hash: &str) -> Result<()> {
    canonical_anchor_hex(txid, "txid")?;
    canonical_anchor_hex(root_hash, "root hash")?;
    Ok(())
}

pub(crate) fn canonical_anchor_hex(value: &str, label: &str) -> Result<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{label} must be exactly 64 hexadecimal characters");
    }
    Ok(value.to_ascii_lowercase())
}

fn add_anchor_confirmation_columns(conn: &Connection) -> Result<()> {
    if conn
        .prepare("SELECT confirmation_attempts FROM anchor_broadcasts LIMIT 0")
        .is_err()
    {
        conn.execute_batch(
            "ALTER TABLE anchor_broadcasts
             ADD COLUMN confirmation_attempts INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    let columns = [
        "next_confirmation_at",
        "last_confirmation_at",
        "confirmed_at",
    ];
    for column in columns {
        ensure_anchor_text_column(conn, column)?;
    }
    Ok(())
}

pub struct ConfirmedPaymentOutcome {
    pub newly_recorded: bool,
    pub transitioned_to_paid: bool,
    pub lifecycle_leaf_hash: Option<String>,
    pub lifecycle_leaf_created: bool,
}

fn ensure_anchor_text_column(conn: &Connection, column: &str) -> Result<()> {
    let query = format!("SELECT {column} FROM anchor_broadcasts LIMIT 0");
    if conn.prepare(&query).is_err() {
        let migration = format!("ALTER TABLE anchor_broadcasts ADD COLUMN {column} TEXT;");
        conn.execute_batch(&migration)?;
    }
    Ok(())
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

        // Migrate: api_keys table for trial key support
        conn.execute_batch(include_str!("../migrations/003_api_keys.sql"))
            .context("Failed to create api_keys table")?;
        if conn
            .prepare("SELECT expires_at FROM api_keys LIMIT 0")
            .is_err()
        {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN expires_at TEXT;")
                .context("Failed to add api-key expiry column")?;
        }
        conn.execute_batch(include_str!("../migrations/004_anchor_broadcasts.sql"))
            .context("Failed to create immutable anchor-broadcast journal")?;

        add_anchor_confirmation_columns(&conn)?;
        conn.execute(
            "UPDATE anchor_broadcasts
             SET txid = lower(txid), root_hash = lower(root_hash)
             WHERE txid <> lower(txid) OR root_hash <> lower(root_hash)",
            [],
        )
        .context("Failed to canonicalize anchor journal identities")?;
        conn.execute(
            "UPDATE merkle_roots
             SET root_hash = lower(root_hash), anchor_txid = lower(anchor_txid)
             WHERE root_hash <> lower(root_hash)
                OR (anchor_txid IS NOT NULL AND anchor_txid <> lower(anchor_txid))",
            [],
        )
        .context("Failed to canonicalize Merkle anchor identities")?;
        let invalid_anchor_identities: i64 = conn.query_row(
            "SELECT
                 (SELECT COUNT(*) FROM anchor_broadcasts
                  WHERE length(txid) <> 64 OR txid GLOB '*[^0-9a-f]*'
                     OR length(root_hash) <> 64 OR root_hash GLOB '*[^0-9a-f]*')
               + (SELECT COUNT(*) FROM merkle_roots
                  WHERE length(root_hash) <> 64 OR root_hash GLOB '*[^0-9a-f]*'
                     OR (anchor_txid IS NOT NULL AND
                         (length(anchor_txid) <> 64 OR anchor_txid GLOB '*[^0-9a-f]*')))",
            [],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            invalid_anchor_identities == 0,
            "database contains a non-canonical anchor transaction or Merkle root identity"
        );
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_anchor_broadcast_confirmation_due
             ON anchor_broadcasts(status, confirmed_at, next_confirmation_at);",
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

    /// Atomically record a block-confirmed payment.
    /// Returns whether the confirmed payment transitioned the invoice to "paid".
    pub fn record_confirmed_payment(
        &self,
        invoice_id: &str,
        received_zat: u64,
        txid: &str,
        height: u32,
    ) -> Result<ConfirmedPaymentOutcome> {
        let mut conn = self.conn()?;
        record_confirmed_payment_transaction(&mut conn, invoice_id, received_zat, txid, height)
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

    /// Return a mempool match to callers without persisting payment state.
    pub fn observe_mempool_payment(
        &self,
        invoice_id: &str,
        received_zat: u64,
        txid: &str,
    ) -> Result<()> {
        anyhow::ensure!(!txid.is_empty(), "mempool transaction id is empty");
        let invoice = self
            .get_invoice(invoice_id)?
            .with_context(|| format!("mempool payment invoice not found: {invoice_id}"))?;
        anyhow::ensure!(
            matches!(
                invoice.status,
                InvoiceStatus::Pending | InvoiceStatus::Partial
            ),
            "mempool payment targets a non-active invoice"
        );
        anyhow::ensure!(received_zat > 0, "mempool payment value is zero");
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_legacy_mempool_payment_for_test(
        &self,
        invoice_id: &str,
        received_zat: u64,
        txid: &str,
    ) -> Result<()> {
        let received_zat =
            i64::try_from(received_zat).context("test payment exceeds SQLite integer range")?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO payment_records
             (invoice_id, txid, value_zat, height, source, created_at)
             VALUES (?1, ?2, ?3, NULL, 'mempool', ?4)",
            params![
                invoice_id,
                txid,
                received_zat,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_legacy_block_payment_for_test(
        &self,
        invoice_id: &str,
        received_zat: u64,
        txid: &str,
        height: u32,
    ) -> Result<()> {
        let received_zat =
            i64::try_from(received_zat).context("test payment exceeds SQLite integer range")?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO payment_records
             (invoice_id, txid, value_zat, height, source, created_at)
             VALUES (?1, ?2, ?3, ?4, 'block', ?5)",
            params![
                invoice_id,
                txid,
                received_zat,
                i64::from(height),
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn payment_state_counts(&self, invoice_id: &str) -> Result<(i64, i64, i64)> {
        let conn = self.conn()?;
        let payment_count = conn.query_row(
            "SELECT COUNT(*) FROM payment_records WHERE invoice_id = ?1",
            params![invoice_id],
            |row| row.get(0),
        )?;
        let leaf_count =
            conn.query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))?;
        let root_count =
            conn.query_row("SELECT COUNT(*) FROM merkle_roots", [], |row| row.get(0))?;
        Ok((payment_count, leaf_count, root_count))
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

    pub fn insert_staking_deposit_leaf(
        &self,
        wallet_hash: &str,
        amount_zat: u64,
        validator_id: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_staking_deposit(wallet_hash, amount_zat, validator_id));
        self.insert_leaf_raw(
            MemoType::StakingDeposit,
            &leaf_hash,
            wallet_hash,
            Some(validator_id),
        )
    }

    pub fn insert_staking_withdraw_leaf(
        &self,
        wallet_hash: &str,
        amount_zat: u64,
        validator_id: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_staking_withdraw(wallet_hash, amount_zat, validator_id));
        self.insert_leaf_raw(
            MemoType::StakingWithdraw,
            &leaf_hash,
            wallet_hash,
            Some(validator_id),
        )
    }

    pub fn insert_staking_reward_leaf(
        &self,
        wallet_hash: &str,
        amount_zat: u64,
        epoch: u32,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_staking_reward(wallet_hash, amount_zat, epoch));
        self.insert_leaf_raw(MemoType::StakingReward, &leaf_hash, wallet_hash, None)
    }

    pub fn insert_governance_proposal_leaf(
        &self,
        wallet_hash: &str,
        proposal_id: &str,
        proposal_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_governance_proposal(
            wallet_hash,
            proposal_id,
            proposal_hash,
        ));
        self.insert_leaf_raw(
            MemoType::GovernanceProposal,
            &leaf_hash,
            wallet_hash,
            Some(proposal_id),
        )
    }

    pub fn insert_governance_vote_leaf(
        &self,
        wallet_hash: &str,
        proposal_id: &str,
        vote_commitment: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_governance_vote(
            wallet_hash,
            proposal_id,
            vote_commitment,
        ));
        self.insert_leaf_raw(
            MemoType::GovernanceVote,
            &leaf_hash,
            wallet_hash,
            Some(proposal_id),
        )
    }

    pub fn insert_governance_result_leaf(
        &self,
        wallet_hash: &str,
        proposal_id: &str,
        result_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(hash_governance_result(
            wallet_hash,
            proposal_id,
            result_hash,
        ));
        self.insert_leaf_raw(
            MemoType::GovernanceResult,
            &leaf_hash,
            wallet_hash,
            Some(proposal_id),
        )
    }

    pub fn insert_agent_register_leaf(
        &self,
        agent_id: &str,
        pubkey_hash: &str,
        model_hash: &str,
        policy_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(crate::memo::hash_agent_register(
            agent_id,
            pubkey_hash,
            model_hash,
            policy_hash,
        ));
        self.insert_leaf_raw(MemoType::AgentRegister, &leaf_hash, agent_id, None)
    }

    pub fn insert_agent_policy_leaf(
        &self,
        agent_id: &str,
        policy_version: u32,
        rules_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(crate::memo::hash_agent_policy(
            agent_id,
            policy_version,
            rules_hash,
        ));
        self.insert_leaf_raw(MemoType::AgentPolicy, &leaf_hash, agent_id, None)
    }

    pub fn insert_agent_action_leaf(
        &self,
        agent_id: &str,
        action_type: &str,
        input_hash: &str,
        output_hash: &str,
    ) -> Result<(MerkleLeafRecord, MerkleRootRecord)> {
        let leaf_hash = hex::encode(crate::memo::hash_agent_action(
            agent_id,
            action_type,
            input_hash,
            output_hash,
        ));
        self.insert_leaf_raw(
            MemoType::AgentAction,
            &leaf_hash,
            agent_id,
            Some(action_type),
        )
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

    pub fn list_recent_leaves(&self, limit: usize) -> Result<Vec<MerkleLeafRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT leaf_hash, event_type, wallet_hash, serial_number, created_at
             FROM merkle_leaves
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
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
        let last_anchored: i64 = conn.query_row(
            "SELECT COALESCE(MAX(leaf_count), 0) FROM merkle_roots WHERE anchor_txid IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let total: i64 =
            conn.query_row("SELECT COUNT(*) FROM merkle_leaves", [], |row| row.get(0))?;
        Ok((total - last_anchored).max(0) as u32)
    }

    pub fn anchor_interval_reference_created_at(&self) -> Result<Option<String>> {
        let conn = self.conn()?;
        let recorded = conn.query_row(
            "SELECT created_at FROM merkle_roots
             WHERE anchor_txid IS NOT NULL
             ORDER BY leaf_count DESC, id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        );
        match recorded {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let first = conn.query_row(
                    "SELECT created_at FROM merkle_roots ORDER BY id ASC LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                );
                match first {
                    Ok(value) => Ok(Some(value)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(error) => Err(error.into()),
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn prepare_anchor_broadcast(&self, intent: &AnchorBroadcastIntent) -> Result<()> {
        let intent = intent.canonicalized()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let root_exists: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM merkle_roots
                 WHERE root_hash = ?1 AND leaf_count = ?2 AND anchor_txid IS NULL
             )",
            params![intent.root_hash, intent.leaf_count as i64],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            root_exists,
            "cannot prepare broadcast: exact unrecorded Merkle root is absent"
        );

        tx.execute(
            "INSERT OR IGNORE INTO anchor_broadcasts
             (txid, root_hash, leaf_count, raw_tx_hex, spent_position, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
            params![
                intent.txid,
                intent.root_hash,
                intent.leaf_count as i64,
                intent.raw_tx_hex,
                intent.spent_position as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;

        let stored = tx.query_row(
            "SELECT txid, root_hash, leaf_count, raw_tx_hex, spent_position
             FROM anchor_broadcasts WHERE root_hash = ?1 AND leaf_count = ?2",
            params![intent.root_hash, intent.leaf_count as i64],
            |row| {
                Ok(AnchorBroadcastIntent {
                    txid: row.get(0)?,
                    root_hash: row.get(1)?,
                    leaf_count: row.get::<_, i64>(2)? as usize,
                    raw_tx_hex: row.get(3)?,
                    spent_position: row.get::<_, i64>(4)? as u64,
                })
            },
        )?;
        anyhow::ensure!(
            stored == intent,
            "a different transaction is already journaled for this Merkle root"
        );
        tx.commit()?;
        Ok(())
    }

    pub fn pending_anchor_broadcast(&self) -> Result<Option<AnchorBroadcastIntent>> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT txid, root_hash, leaf_count, raw_tx_hex, spent_position
             FROM anchor_broadcasts WHERE status = 'prepared' LIMIT 1",
            [],
            |row| {
                Ok(AnchorBroadcastIntent {
                    txid: row.get(0)?,
                    root_hash: row.get(1)?,
                    leaf_count: row.get::<_, i64>(2)? as usize,
                    raw_tx_hex: row.get(3)?,
                    spent_position: row.get::<_, i64>(4)? as u64,
                })
            },
        );
        match result {
            Ok(intent) => Ok(Some(intent.canonicalized()?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn record_anchor_broadcast_error(&self, txid: &str, error: &str) -> Result<()> {
        let txid = canonical_anchor_hex(txid, "txid")?;
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE anchor_broadcasts SET last_error = ?1
             WHERE txid = ?2 AND status = 'prepared'",
            params![error, txid],
        )?;
        anyhow::ensure!(updated == 1, "prepared anchor broadcast not found");
        Ok(())
    }

    pub fn finalize_anchor_broadcast(&self, txid: &str) -> Result<()> {
        let txid = canonical_anchor_hex(txid, "txid")?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (root_hash, leaf_count, status): (String, i64, String) = tx.query_row(
            "SELECT root_hash, leaf_count, status FROM anchor_broadcasts WHERE txid = ?1",
            params![txid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        anyhow::ensure!(
            status == "prepared" || status == "recorded",
            "anchor journal has an invalid finalization state"
        );

        let mapped_txid: Option<String> = tx.query_row(
            "SELECT anchor_txid FROM merkle_roots
             WHERE root_hash = ?1 AND leaf_count = ?2
             ORDER BY id DESC LIMIT 1",
            params![root_hash, leaf_count],
            |row| row.get(0),
        )?;
        match mapped_txid {
            None => {
                let updated = tx.execute(
                    "UPDATE merkle_roots SET anchor_txid = ?1
                     WHERE root_hash = ?2 AND leaf_count = ?3 AND anchor_txid IS NULL",
                    params![txid, root_hash, leaf_count],
                )?;
                anyhow::ensure!(
                    updated == 1,
                    "exact Merkle root disappeared during finalization"
                );
            }
            Some(existing) if existing == txid => {}
            Some(_) => {
                return Err(anchor_record_conflict(
                    "exact Merkle root is mapped to a different transaction",
                ));
            }
        }

        let now = chrono::Utc::now().to_rfc3339();
        let journal_updated = tx.execute(
            "UPDATE anchor_broadcasts
             SET status = 'recorded',
                 recorded_at = COALESCE(recorded_at, ?1),
                 next_confirmation_at = CASE
                     WHEN confirmed_at IS NULL THEN COALESCE(next_confirmation_at, ?1)
                     ELSE NULL
                 END,
                 last_error = NULL
             WHERE txid = ?2",
            params![now, txid],
        )?;
        anyhow::ensure!(journal_updated == 1, "anchor journal finalization failed");
        tx.commit()?;
        Ok(())
    }

    pub fn due_anchor_confirmations(&self, limit: u32) -> Result<Vec<AnchorConfirmation>> {
        anyhow::ensure!(
            limit > 0 && limit <= 100,
            "confirmation query limit is out of range"
        );
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT txid, root_hash, confirmation_attempts
             FROM anchor_broadcasts
             WHERE status = 'recorded'
               AND confirmed_at IS NULL
               AND (next_confirmation_at IS NULL
                    OR julianday(next_confirmation_at) IS NULL
                    OR julianday(next_confirmation_at) <= julianday(?1))
             ORDER BY recorded_at ASC, txid ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now, i64::from(limit)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut confirmations = Vec::new();
        for row in rows {
            let (txid, root_hash, attempts) = row?;
            confirmations.push(AnchorConfirmation {
                txid: canonical_anchor_hex(&txid, "journal txid")?,
                root_hash: canonical_anchor_hex(&root_hash, "journal root hash")?,
                confirmation_attempts: u32::try_from(attempts)
                    .context("anchor confirmation attempts are out of range")?,
            });
        }
        Ok(confirmations)
    }

    pub fn record_anchor_confirmation_retry(
        &self,
        txid: &str,
        error: &str,
        retry_after_seconds: u64,
    ) -> Result<()> {
        let txid = canonical_anchor_hex(txid, "txid")?;
        anyhow::ensure!(
            retry_after_seconds > 0,
            "confirmation retry must be delayed"
        );
        let retry_seconds = i64::try_from(retry_after_seconds)
            .context("confirmation retry delay exceeds supported range")?;
        let now = chrono::Utc::now();
        let next = now
            .checked_add_signed(chrono::Duration::seconds(retry_seconds))
            .context("confirmation retry timestamp overflow")?;
        let bounded_error: String = error.chars().take(2048).collect();
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE anchor_broadcasts
             SET confirmation_attempts = confirmation_attempts + 1,
                 last_confirmation_at = ?1,
                 next_confirmation_at = ?2,
                 last_error = ?3
             WHERE txid = ?4 AND status = 'recorded' AND confirmed_at IS NULL",
            params![now.to_rfc3339(), next.to_rfc3339(), bounded_error, txid],
        )?;
        anyhow::ensure!(
            updated == 1,
            "unconfirmed recorded anchor journal row not found"
        );
        Ok(())
    }

    pub fn confirm_anchor_broadcast(&self, txid: &str, height: u32) -> Result<()> {
        let txid = canonical_anchor_hex(txid, "txid")?;
        anyhow::ensure!(height > 0, "anchor height must be positive");
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (root_hash, status, confirmed_at): (String, String, Option<String>) = tx.query_row(
            "SELECT root_hash, status, confirmed_at FROM anchor_broadcasts WHERE txid = ?1",
            params![txid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        anyhow::ensure!(
            status == "recorded",
            "anchor broadcast is not in recorded state"
        );
        record_anchor_reference_in_tx(&tx, &root_hash, &txid, Some(height))?;
        if confirmed_at.is_none() {
            let now = chrono::Utc::now().to_rfc3339();
            let updated = tx.execute(
                "UPDATE anchor_broadcasts
                 SET confirmation_attempts = confirmation_attempts + 1,
                     last_confirmation_at = ?1,
                     confirmed_at = ?1,
                     next_confirmation_at = NULL,
                     last_error = NULL
                 WHERE txid = ?2 AND status = 'recorded' AND confirmed_at IS NULL",
                params![now, txid],
            )?;
            anyhow::ensure!(
                updated == 1,
                "anchor confirmation journal update lost its row"
            );
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_merkle_anchor(
        &self,
        root_hash: &str,
        txid: &str,
        height: Option<u32>,
    ) -> Result<()> {
        let root_hash = canonical_anchor_hex(root_hash, "root hash")?;
        let txid = canonical_anchor_hex(txid, "txid")?;
        if let Some(height) = height {
            anyhow::ensure!(height > 0, "anchor height must be positive");
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if prepared_anchor_identity(&tx)?.is_some() {
            return Err(anchor_record_conflict(
                "manual mapping is blocked while a prepared anchor broadcast exists",
            ));
        }
        record_anchor_reference_in_tx(&tx, &root_hash, &txid, height)?;
        tx.commit()?;
        Ok(())
    }

    /// Record a configured-node-confirmed transaction reference. This proves
    /// transaction existence and height only. It does not prove encrypted memo
    /// contents or independently bind the memo to the supplied Merkle root.
    ///
    /// Returns true when the reference exactly reconciled a prepared broadcast.
    /// In that case the journal remains prepared until the embedded wallet state
    /// is durably finalized by the automatic recovery path.
    pub fn record_confirmed_manual_anchor_reference(
        &self,
        root_hash: &str,
        txid: &str,
        height: u32,
    ) -> Result<bool> {
        let root_hash = canonical_anchor_hex(root_hash, "root hash")?;
        let txid = canonical_anchor_hex(txid, "txid")?;
        anyhow::ensure!(height > 0, "anchor height must be positive");

        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reconciled_prepared = match prepared_anchor_identity(&tx)? {
            Some((prepared_txid, prepared_root, _leaf_count)) => {
                if prepared_txid != txid || prepared_root != root_hash {
                    return Err(anchor_record_conflict(
                        "confirmed transaction does not exactly match the prepared anchor broadcast",
                    ));
                }
                true
            }
            None => false,
        };

        record_anchor_reference_in_tx(&tx, &root_hash, &txid, Some(height))?;
        if reconciled_prepared {
            let now = chrono::Utc::now().to_rfc3339();
            let updated = tx.execute(
                "UPDATE anchor_broadcasts
                 SET confirmation_attempts = confirmation_attempts + 1,
                     last_confirmation_at = ?1,
                     confirmed_at = COALESCE(confirmed_at, ?1),
                     next_confirmation_at = NULL,
                     last_error = NULL
                 WHERE txid = ?2 AND status = 'prepared'",
                params![now, txid],
            )?;
            anyhow::ensure!(
                updated == 1,
                "prepared anchor reconciliation lost its journal row"
            );
        }
        tx.commit()?;
        Ok(reconciled_prepared)
    }

    pub fn record_merkle_anchor_height(&self, txid: &str, height: u32) -> Result<()> {
        let txid = canonical_anchor_hex(txid, "txid")?;
        anyhow::ensure!(height > 0, "anchor height must be positive");
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE merkle_roots SET anchor_height = ?1
             WHERE anchor_txid = ?2 AND (anchor_height IS NULL OR anchor_height = ?1)",
            params![height as i64, txid],
        )?;
        anyhow::ensure!(
            updated == 1,
            "exact anchor transaction record not found or height conflicts"
        );
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

        let leaf_position = index + 1; // 1-based leaf count
        let all_leaf_bytes = all_leaves
            .iter()
            .map(|leaf| decode_hash(&leaf.leaf_hash))
            .collect::<Result<Vec<_>>>()?;

        // Prefer the smallest anchored count-bound root covering this leaf.
        // Fall back to a legacy-shaped root only when no safe anchored root covers it.
        let mut stmt = conn.prepare(
            "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
             FROM merkle_roots
             WHERE leaf_count >= ?1 AND anchor_txid IS NOT NULL
             ORDER BY leaf_count ASC, id ASC",
        )?;
        let covering_roots = stmt
            .query_map(params![leaf_position as i64], |row| {
                Ok(MerkleRootRecord {
                    root_hash: row.get(0)?,
                    leaf_count: row.get::<_, i64>(1)? as usize,
                    anchor_txid: row.get(2)?,
                    anchor_height: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                    created_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let (root, leaf_set_size) =
            match select_covering_root(&covering_roots, &all_leaf_bytes, leaf_position) {
                Some(root) => root,
                None => {
                    // No anchored root covers this leaf yet - use current root.
                    match current_root(&conn)? {
                        Some(r) => {
                            let size = r.leaf_count;
                            (r, size)
                        }
                        None => return Ok(None),
                    }
                }
            };

        if leaf_set_size > all_leaf_bytes.len() || index >= leaf_set_size {
            return Ok(None);
        }

        let leaf_bytes = &all_leaf_bytes[..leaf_set_size];
        let root_bytes = decode_hash(&root.root_hash)?;
        let new_root = compute_root(leaf_bytes);
        let legacy_root = compute_legacy_root(leaf_bytes);
        let proof = if legacy_root == root_bytes && new_root != root_bytes {
            generate_legacy_proof(leaf_bytes, index)
        } else {
            generate_proof(leaf_bytes, index)
        };
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

    // --- API key management ---

    pub fn create_api_keys_table(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(include_str!("../migrations/003_api_keys.sql"))?;
        if conn
            .prepare("SELECT expires_at FROM api_keys LIMIT 0")
            .is_err()
        {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN expires_at TEXT;")?;
        }
        Ok(())
    }

    pub fn insert_api_key(
        &self,
        id: &str,
        key_hash: &str,
        tier: &str,
        quota: i64,
        expires_at: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO api_keys (id, name, key_hash, tier, leaves_limit, leaves_used, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
            params![
                id,
                format!("trial-{}", &id[..8.min(id.len())]),
                key_hash,
                tier,
                quota,
                now,
                expires_at
            ],
        )?;
        Ok(())
    }

    pub fn consume_api_key_quota(&self, key_hash: &str) -> Result<bool> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        let updated = conn.execute(
            "UPDATE api_keys
             SET leaves_used = leaves_used + 1, last_used_at = ?2
             WHERE key_hash = ?1
               AND (leaves_limit < 0 OR leaves_used < leaves_limit)
               AND expires_at IS NOT NULL
               AND julianday(expires_at) > julianday(?2)",
            params![key_hash, now],
        )?;
        Ok(updated == 1)
    }
}

fn record_confirmed_payment_transaction(
    conn: &mut Connection,
    invoice_id: &str,
    received_zat: u64,
    txid: &str,
    height: u32,
) -> Result<ConfirmedPaymentOutcome> {
    anyhow::ensure!(received_zat > 0, "confirmed payment value is zero");
    anyhow::ensure!(!txid.is_empty(), "confirmed transaction id is empty");
    let received_zat_i64 =
        i64::try_from(received_zat).context("confirmed payment exceeds SQLite integer range")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = chrono::Utc::now().to_rfc3339();
    let mut invoice = tx
        .query_row(
            "SELECT id, diversifier_index, address, amount_zat, memo, invoice_type, wallet_hash, status, received_zat, created_at, expires_at, paid_at, paid_txid, paid_height
             FROM invoices WHERE id = ?1",
            params![invoice_id],
            row_to_invoice,
        )
        .with_context(|| format!("confirmed payment invoice not found: {invoice_id}"))?;

    let existing = tx.query_row(
        "SELECT value_zat, source FROM payment_records
         WHERE invoice_id = ?1 AND txid = ?2 LIMIT 1",
        params![invoice_id, txid],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    );

    match existing {
        Ok((stored_value, source)) => {
            anyhow::ensure!(
                stored_value == received_zat_i64,
                "existing payment has a conflicting value"
            );
            anyhow::ensure!(
                source == "block" || source == "mempool",
                "existing payment has an unsupported source"
            );
            let promoted = tx.execute(
                "UPDATE payment_records SET height = ?1, source = 'block'
                 WHERE invoice_id = ?2 AND txid = ?3",
                params![i64::from(height), invoice_id, txid],
            )?;
            anyhow::ensure!(promoted == 1, "confirmed payment promotion failed");
            if invoice.status == InvoiceStatus::Paid && invoice.paid_txid.as_deref() == Some(txid) {
                tx.execute(
                    "UPDATE invoices SET paid_height = ?1 WHERE id = ?2",
                    params![i64::from(height), invoice_id],
                )?;
                invoice.paid_height = Some(height);
            }
            let (transitioned_to_paid, lifecycle) =
                apply_confirmed_total(&tx, &mut invoice, txid, height, &now)?;
            tx.commit()?;
            return Ok(ConfirmedPaymentOutcome {
                newly_recorded: false,
                transitioned_to_paid,
                lifecycle_leaf_hash: lifecycle.as_ref().map(|(hash, _)| hash.clone()),
                lifecycle_leaf_created: lifecycle.map(|(_, created)| created).unwrap_or(false),
            });
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(error) => return Err(error.into()),
    }

    anyhow::ensure!(
        !matches!(invoice.status, InvoiceStatus::Expired),
        "new payment targets an expired invoice"
    );

    tx.execute(
        "INSERT INTO payment_records
         (invoice_id, txid, value_zat, height, source, created_at)
         VALUES (?1, ?2, ?3, ?4, 'block', ?5)",
        params![invoice_id, txid, received_zat_i64, i64::from(height), now],
    )?;

    let (transitioned_to_paid, lifecycle) =
        apply_confirmed_total(&tx, &mut invoice, txid, height, &now)?;
    tx.commit()?;

    Ok(ConfirmedPaymentOutcome {
        newly_recorded: true,
        transitioned_to_paid,
        lifecycle_leaf_hash: lifecycle.as_ref().map(|(hash, _)| hash.clone()),
        lifecycle_leaf_created: lifecycle.map(|(_, created)| created).unwrap_or(false),
    })
}

fn apply_confirmed_total(
    tx: &rusqlite::Transaction<'_>,
    invoice: &mut Invoice,
    txid: &str,
    height: u32,
    now: &str,
) -> Result<(bool, Option<(String, bool)>)> {
    let confirmed_total_i64: i64 = tx.query_row(
        "SELECT COALESCE(SUM(value_zat), 0) FROM payment_records
         WHERE invoice_id = ?1 AND source = 'block'",
        params![invoice.id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        confirmed_total_i64 >= 0,
        "confirmed payment total is negative"
    );
    let confirmed_total = confirmed_total_i64 as u64;

    if invoice.status == InvoiceStatus::Paid {
        anyhow::ensure!(
            confirmed_total >= invoice.amount_zat,
            "paid invoice lacks sufficient confirmed payments"
        );
        let updated = tx.execute(
            "UPDATE invoices SET received_zat = ?1 WHERE id = ?2 AND status = 'paid'",
            params![confirmed_total_i64, invoice.id],
        )?;
        anyhow::ensure!(updated == 1, "confirmed paid invoice update raced");
        invoice.received_zat = confirmed_total;
        let lifecycle = ensure_invoice_lifecycle_leaf(tx, invoice)?;
        return Ok((false, lifecycle));
    }

    anyhow::ensure!(
        matches!(
            invoice.status,
            InvoiceStatus::Pending | InvoiceStatus::Partial
        ),
        "confirmed payment targets an unsupported invoice state"
    );
    let transitioned_to_paid = matches!(
        invoice.status,
        InvoiceStatus::Pending | InvoiceStatus::Partial
    ) && confirmed_total >= invoice.amount_zat;

    if transitioned_to_paid {
        let updated = tx.execute(
            "UPDATE invoices
             SET received_zat = ?1, status = 'paid', paid_at = ?2,
                 paid_txid = ?3, paid_height = ?4
             WHERE id = ?5 AND status IN ('pending', 'partial')",
            params![
                confirmed_total_i64,
                now,
                txid,
                i64::from(height),
                invoice.id
            ],
        )?;
        anyhow::ensure!(updated == 1, "confirmed payment invoice transition raced");
        invoice.status = InvoiceStatus::Paid;
        invoice.paid_at = Some(now.to_string());
        invoice.paid_txid = Some(txid.to_string());
        invoice.paid_height = Some(height);
    } else {
        let updated = tx.execute(
            "UPDATE invoices
             SET received_zat = ?1, status = 'partial',
                 paid_at = NULL, paid_txid = NULL, paid_height = NULL
             WHERE id = ?2 AND status IN ('pending', 'partial')",
            params![confirmed_total_i64, invoice.id],
        )?;
        anyhow::ensure!(updated == 1, "confirmed payment invoice update raced");
        invoice.status = InvoiceStatus::Partial;
    }
    invoice.received_zat = confirmed_total;

    let lifecycle = if transitioned_to_paid {
        ensure_invoice_lifecycle_leaf(tx, invoice)?
    } else {
        None
    };
    Ok((transitioned_to_paid, lifecycle))
}

fn ensure_invoice_lifecycle_leaf(
    tx: &rusqlite::Transaction<'_>,
    invoice: &Invoice,
) -> Result<Option<(String, bool)>> {
    let Some(wallet_hash) = invoice.wallet_hash.as_deref() else {
        return Ok(None);
    };

    let (event_type, leaf_hash, serial_number) = match invoice.invoice_type.as_str() {
        "program" | "initial" => (
            MemoType::ProgramEntry,
            hex::encode(hash_program_entry(wallet_hash)),
            None,
        ),
        "hosting" => {
            let (month, year) = hosting_period(invoice.memo.as_deref(), &invoice.created_at);
            let serial = tx
                .query_row(
                    "SELECT serial_number FROM miner_assignments
                     WHERE wallet_hash = ?1 ORDER BY id ASC LIMIT 1",
                    params![wallet_hash],
                    |row| row.get::<_, String>(0),
                )
                .context("hosting payment has no miner assignment")?;
            (
                MemoType::HostingPayment,
                hex::encode(hash_hosting_payment(&serial, month, year)),
                Some(serial),
            )
        }
        "renewal" => {
            let year = renewal_year(invoice.memo.as_deref(), &invoice.created_at);
            (
                MemoType::ShieldRenewal,
                hex::encode(hash_shield_renewal(wallet_hash, year)),
                None,
            )
        }
        _ => return Ok(None),
    };

    let created = insert_lifecycle_leaf_transaction(
        tx,
        event_type,
        &leaf_hash,
        wallet_hash,
        serial_number.as_deref(),
    )?;
    Ok(Some((leaf_hash, created)))
}

fn insert_lifecycle_leaf_transaction(
    tx: &rusqlite::Transaction<'_>,
    event_type: MemoType,
    leaf_hash: &str,
    wallet_hash: &str,
    serial_number: Option<&str>,
) -> Result<bool> {
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO merkle_leaves
         (leaf_hash, event_type, wallet_hash, serial_number, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            leaf_hash,
            i64::from(event_type.as_u8()),
            wallet_hash,
            serial_number,
            chrono::Utc::now().to_rfc3339()
        ],
    )?;

    let stored = merkle_leaf_by_hash(tx, leaf_hash)?.context("lifecycle leaf is missing")?;
    anyhow::ensure!(
        stored.event_type == event_type
            && stored.wallet_hash == wallet_hash
            && stored.serial_number.as_deref() == serial_number,
        "lifecycle leaf hash is bound to different metadata"
    );

    if inserted == 1 {
        let leaves = merkle_leaves(tx)?;
        let leaf_hashes = leaves
            .iter()
            .map(|leaf| decode_hash(&leaf.leaf_hash))
            .collect::<Result<Vec<_>>>()?;
        tx.execute(
            "INSERT INTO merkle_roots (root_hash, leaf_count, created_at)
             VALUES (?1, ?2, ?3)",
            params![
                hex::encode(compute_root(&leaf_hashes)),
                leaves.len() as i64,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
    }
    current_root(tx)?.context("Merkle root is missing after lifecycle insert")?;
    Ok(inserted == 1)
}

fn hosting_period(memo: Option<&str>, created_at: &str) -> (u32, u32) {
    if let Some(parts) = memo.map(|value| value.split('-').collect::<Vec<_>>()) {
        if parts.len() >= 4 {
            if let (Ok(year), Ok(month)) = (parts[2].parse(), parts[3].parse()) {
                return (month, year);
            }
        }
    }
    chrono::DateTime::parse_from_rfc3339(created_at)
        .map(|created| (created.month(), created.year() as u32))
        .unwrap_or((1, 2026))
}

fn renewal_year(memo: Option<&str>, created_at: &str) -> u32 {
    if let Some(parts) = memo.map(|value| value.split('-').collect::<Vec<_>>()) {
        if parts.len() >= 3 {
            if let Ok(year) = parts[2].parse() {
                return year;
            }
        }
    }
    chrono::DateTime::parse_from_rfc3339(created_at)
        .map(|created| created.year() as u32)
        .unwrap_or(2026)
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

fn select_covering_root(
    roots: &[MerkleRootRecord],
    leaf_hashes: &[[u8; 32]],
    leaf_position: usize,
) -> Option<(MerkleRootRecord, usize)> {
    let mut legacy_fallback = None;

    for root in roots {
        let size = root.leaf_count;
        if size < leaf_position || size > leaf_hashes.len() {
            continue;
        }

        let leaves = &leaf_hashes[..size];
        if root.root_hash == hex::encode(compute_root(leaves)) {
            return Some((root.clone(), size));
        }

        if legacy_fallback.is_none() && root.root_hash == hex::encode(compute_legacy_root(leaves)) {
            legacy_fallback = Some((root.clone(), size));
        }
    }

    legacy_fallback
}

fn current_root(conn: &Connection) -> Result<Option<MerkleRootRecord>> {
    let total_leaves = total_leaf_count_conn(conn)?;
    if total_leaves == 0 {
        return Ok(None);
    }

    let leaf_hashes = merkle_leaves(conn)?
        .iter()
        .map(|leaf| decode_hash(&leaf.leaf_hash))
        .collect::<Result<Vec<_>>>()?;
    let canonical_root_hash = hex::encode(compute_root(&leaf_hashes));

    if let Some(root) = root_by_hash_and_count(conn, &canonical_root_hash, total_leaves)? {
        return Ok(Some(root));
    }

    let latest = latest_root(conn, total_leaves)?;
    if latest
        .as_ref()
        .map(|root| root.root_hash == canonical_root_hash && root.leaf_count == total_leaves)
        .unwrap_or(false)
    {
        return Ok(latest);
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO merkle_roots (root_hash, leaf_count, created_at) VALUES (?1, ?2, ?3)",
        params![canonical_root_hash, total_leaves as i64, created_at],
    )?;
    latest_root(conn, total_leaves)
}

fn root_by_hash_and_count(
    conn: &Connection,
    root_hash: &str,
    leaf_count: usize,
) -> Result<Option<MerkleRootRecord>> {
    let mut stmt = conn.prepare(
        "SELECT root_hash, leaf_count, anchor_txid, anchor_height, created_at
         FROM merkle_roots
         WHERE root_hash = ?1 AND leaf_count = ?2
         ORDER BY id DESC
         LIMIT 1",
    )?;
    let result = stmt.query_row(params![root_hash, leaf_count as i64], |row| {
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

fn latest_root(conn: &Connection, total_leaves: usize) -> Result<Option<MerkleRootRecord>> {
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

fn prepared_anchor_identity(
    tx: &rusqlite::Transaction<'_>,
) -> Result<Option<(String, String, i64)>> {
    let result = tx.query_row(
        "SELECT txid, root_hash, leaf_count
         FROM anchor_broadcasts WHERE status = 'prepared' LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    );
    match result {
        Ok((txid, root_hash, leaf_count)) => {
            anyhow::ensure!(leaf_count > 0, "prepared anchor leaf count is invalid");
            Ok(Some((
                canonical_anchor_hex(&txid, "prepared txid")?,
                canonical_anchor_hex(&root_hash, "prepared root hash")?,
                leaf_count,
            )))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn record_anchor_reference_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_hash: &str,
    txid: &str,
    height: Option<u32>,
) -> Result<()> {
    let existing = tx.query_row(
        "SELECT id, anchor_txid, anchor_height
         FROM merkle_roots WHERE root_hash = ?1
         ORDER BY id DESC LIMIT 1",
        params![root_hash],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
    );
    let (root_id, mapped_txid, existing_height) = match existing {
        Ok(record) => record,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(anchor_record_conflict(format!(
                "no Merkle root record found for {root_hash}"
            )));
        }
        Err(error) => return Err(error.into()),
    };

    match mapped_txid {
        None => {
            let updated = tx.execute(
                "UPDATE merkle_roots
                 SET anchor_txid = ?1, anchor_height = ?2
                 WHERE id = ?3 AND anchor_txid IS NULL",
                params![txid, height.map(i64::from), root_id],
            )?;
            anyhow::ensure!(
                updated == 1,
                "Merkle root mapping lost an immediate transaction race"
            );
        }
        Some(existing_txid) if existing_txid == txid => match (existing_height, height) {
            (Some(existing), Some(claimed)) if existing != i64::from(claimed) => {
                return Err(anchor_record_conflict(
                    "anchor transaction is already recorded at a different height",
                ));
            }
            (None, Some(claimed)) => {
                let updated = tx.execute(
                    "UPDATE merkle_roots SET anchor_height = ?1
                     WHERE id = ?2 AND anchor_txid = ?3 AND anchor_height IS NULL",
                    params![i64::from(claimed), root_id, txid],
                )?;
                anyhow::ensure!(
                    updated == 1,
                    "anchor height update lost an immediate transaction race"
                );
            }
            _ => {}
        },
        Some(_) => {
            return Err(anchor_record_conflict(
                "Merkle root is already mapped to a different transaction",
            ));
        }
    }
    Ok(())
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
    use super::{
        current_root, normalize_root_leaf_count, select_covering_root, AnchorBroadcastIntent, Db,
    };
    use crate::memo::hash_program_entry;
    use crate::merkle::{compute_legacy_root, compute_root, MerkleRootRecord};
    use rusqlite::{params, Connection};

    #[test]
    fn normalize_root_leaf_count_preserves_valid_count() {
        assert_eq!(normalize_root_leaf_count(12, 12), 12);
        assert_eq!(normalize_root_leaf_count(2, 12), 2);
    }

    #[test]
    fn normalize_root_leaf_count_clamps_impossible_count() {
        assert_eq!(normalize_root_leaf_count(13, 12), 12);
    }

    #[test]
    fn current_root_materializes_count_bound_root_over_latest_legacy_root() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/001_init.sql"))
            .unwrap();

        let leaves = [
            hash_program_entry("wallet_a"),
            hash_program_entry("wallet_b"),
        ];
        for (index, leaf) in leaves.iter().enumerate() {
            conn.execute(
                "INSERT INTO merkle_leaves (leaf_hash, event_type, wallet_hash, serial_number, created_at)
                 VALUES (?1, 1, ?2, NULL, ?3)",
                params![
                    hex::encode(leaf),
                    format!("wallet_{}", index),
                    "2026-06-12T00:00:00Z"
                ],
            )
            .unwrap();
        }

        let legacy_root = hex::encode(compute_legacy_root(&leaves));
        let count_bound_root = hex::encode(compute_root(&leaves));
        assert_ne!(legacy_root, count_bound_root);

        conn.execute(
            "INSERT INTO merkle_roots (root_hash, leaf_count, created_at)
             VALUES (?1, 2, '2026-06-12T00:00:01Z')",
            params![legacy_root],
        )
        .unwrap();

        let root = current_root(&conn).unwrap().unwrap();
        assert_eq!(root.root_hash, count_bound_root);
        assert_eq!(root.leaf_count, 2);
        assert!(root.anchor_txid.is_none());

        let row_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM merkle_roots WHERE root_hash = ?1 AND leaf_count = 2",
                params![count_bound_root],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row_count, 1);
    }

    #[test]
    fn anchor_broadcast_journal_is_exact_idempotent_and_immutable() {
        let db = Db::open(":memory:").unwrap();
        let (_, root) = db.insert_program_entry_leaf("wallet_a").unwrap();
        let intent = AnchorBroadcastIntent {
            txid: "a".repeat(64),
            root_hash: root.root_hash.clone(),
            leaf_count: root.leaf_count,
            raw_tx_hex: "deadbeef".to_string(),
            spent_position: 7,
        };
        db.prepare_anchor_broadcast(&intent).unwrap();
        db.prepare_anchor_broadcast(&intent).unwrap();
        assert_eq!(db.pending_anchor_broadcast().unwrap(), Some(intent.clone()));

        let mut different = intent.clone();
        different.raw_tx_hex = "cafebabe".to_string();
        assert!(db.prepare_anchor_broadcast(&different).is_err());

        db.finalize_anchor_broadcast(&intent.txid).unwrap();
        assert!(db.pending_anchor_broadcast().unwrap().is_none());
        assert_eq!(
            db.current_merkle_root()
                .unwrap()
                .unwrap()
                .anchor_txid
                .as_deref(),
            Some(intent.txid.as_str())
        );
        assert!(db
            .record_merkle_anchor(&root.root_hash, &"b".repeat(64), None)
            .is_err());
    }

    #[test]
    fn anchor_height_update_requires_one_exact_transaction() {
        let db = Db::open(":memory:").unwrap();
        assert!(db.record_merkle_anchor_height(&"a".repeat(64), 1).is_err());
    }

    #[test]
    fn anchor_identities_are_canonicalized_before_storage_and_lookup() {
        let db = Db::open(":memory:").unwrap();
        let (_, root) = db.insert_program_entry_leaf("wallet_a").unwrap();
        let intent = AnchorBroadcastIntent {
            txid: "AB".repeat(32),
            root_hash: root.root_hash.to_ascii_uppercase(),
            leaf_count: root.leaf_count,
            raw_tx_hex: "DEADBEEF".to_string(),
            spent_position: 7,
        };
        db.prepare_anchor_broadcast(&intent).unwrap();
        let pending = db.pending_anchor_broadcast().unwrap().unwrap();
        assert_eq!(pending.txid, "ab".repeat(32));
        assert_eq!(pending.root_hash, root.root_hash);
        assert_eq!(pending.raw_tx_hex, "deadbeef");
        db.record_anchor_broadcast_error(&"AB".repeat(32), "retry")
            .unwrap();

        let mut invalid = intent;
        invalid.txid = "g".repeat(64);
        assert!(db.prepare_anchor_broadcast(&invalid).is_err());
    }

    #[test]
    fn manual_anchor_requires_exact_confirmed_reconciliation_during_prepared_broadcast() {
        let db = Db::open(":memory:").unwrap();
        let (_, root) = db.insert_program_entry_leaf("wallet_a").unwrap();
        let intent = AnchorBroadcastIntent {
            txid: "a".repeat(64),
            root_hash: root.root_hash.clone(),
            leaf_count: root.leaf_count,
            raw_tx_hex: "deadbeef".to_string(),
            spent_position: 7,
        };
        db.prepare_anchor_broadcast(&intent).unwrap();

        assert!(db
            .record_merkle_anchor(&root.root_hash, &intent.txid, Some(100))
            .is_err());
        assert!(db
            .record_confirmed_manual_anchor_reference(&root.root_hash, &"b".repeat(64), 100)
            .is_err());
        assert!(db
            .current_merkle_root()
            .unwrap()
            .unwrap()
            .anchor_txid
            .is_none());

        assert!(db
            .record_confirmed_manual_anchor_reference(
                &root.root_hash.to_ascii_uppercase(),
                &intent.txid.to_ascii_uppercase(),
                100,
            )
            .unwrap());
        let recorded = db.current_merkle_root().unwrap().unwrap();
        assert_eq!(recorded.anchor_txid.as_deref(), Some(intent.txid.as_str()));
        assert_eq!(recorded.anchor_height, Some(100));
        assert!(db.pending_anchor_broadcast().unwrap().is_some());
        assert!(db.due_anchor_confirmations(8).unwrap().is_empty());

        db.finalize_anchor_broadcast(&intent.txid.to_ascii_uppercase())
            .unwrap();
        assert!(db.pending_anchor_broadcast().unwrap().is_none());
        assert!(db.due_anchor_confirmations(8).unwrap().is_empty());
    }

    #[test]
    fn confirmation_retry_is_durable_and_never_becomes_a_terminal_give_up() {
        let db = Db::open(":memory:").unwrap();
        let (_, root) = db.insert_program_entry_leaf("wallet_a").unwrap();
        let intent = AnchorBroadcastIntent {
            txid: "c".repeat(64),
            root_hash: root.root_hash,
            leaf_count: root.leaf_count,
            raw_tx_hex: "deadbeef".to_string(),
            spent_position: 7,
        };
        db.prepare_anchor_broadcast(&intent).unwrap();
        db.finalize_anchor_broadcast(&intent.txid).unwrap();

        let due = db.due_anchor_confirmations(8).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].confirmation_attempts, 0);
        db.record_anchor_confirmation_retry(&intent.txid, "not confirmed", 60)
            .unwrap();
        assert!(db.due_anchor_confirmations(8).unwrap().is_empty());

        db.conn()
            .unwrap()
            .execute(
                "UPDATE anchor_broadcasts
                 SET next_confirmation_at = '1970-01-01T00:00:00Z'
                 WHERE txid = ?1",
                params![intent.txid],
            )
            .unwrap();
        let retried = db.due_anchor_confirmations(8).unwrap();
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].confirmation_attempts, 1);

        db.confirm_anchor_broadcast(&intent.txid.to_ascii_uppercase(), 321)
            .unwrap();
        assert!(db.due_anchor_confirmations(8).unwrap().is_empty());
        assert_eq!(
            db.current_merkle_root().unwrap().unwrap().anchor_height,
            Some(321)
        );
        db.confirm_anchor_broadcast(&intent.txid, 321).unwrap();
        assert!(db.confirm_anchor_broadcast(&intent.txid, 322).is_err());
    }

    #[test]
    fn unanchored_leaf_count_propagates_database_errors() {
        let db = Db::open(":memory:").unwrap();
        db.conn()
            .unwrap()
            .execute_batch("DROP TABLE merkle_leaves;")
            .unwrap();
        assert!(db.unanchored_leaf_count().is_err());
    }

    #[test]
    fn select_covering_root_prefers_count_bound_root_over_earlier_legacy_root() {
        let leaves = [
            hash_program_entry("wallet_a"),
            hash_program_entry("wallet_b"),
        ];
        let legacy_root = MerkleRootRecord {
            root_hash: hex::encode(compute_legacy_root(&leaves[..1])),
            leaf_count: 1,
            anchor_txid: Some("legacy".to_string()),
            anchor_height: Some(3_286_631),
            created_at: "2026-06-12T00:00:00Z".to_string(),
        };
        let count_bound_root = MerkleRootRecord {
            root_hash: hex::encode(compute_root(&leaves)),
            leaf_count: 2,
            anchor_txid: Some("v2".to_string()),
            anchor_height: Some(3_317_134),
            created_at: "2026-06-12T00:00:01Z".to_string(),
        };

        let (selected, leaf_count) =
            select_covering_root(&[legacy_root, count_bound_root.clone()], &leaves, 1).unwrap();

        assert_eq!(selected.root_hash, count_bound_root.root_hash);
        assert_eq!(leaf_count, 2);
    }

    #[test]
    fn select_covering_root_falls_back_to_legacy_when_no_count_bound_root_covers_leaf() {
        let leaves = [
            hash_program_entry("wallet_a"),
            hash_program_entry("wallet_b"),
        ];
        let legacy_root = MerkleRootRecord {
            root_hash: hex::encode(compute_legacy_root(&leaves)),
            leaf_count: 2,
            anchor_txid: Some("legacy".to_string()),
            anchor_height: Some(3_286_631),
            created_at: "2026-06-12T00:00:00Z".to_string(),
        };

        let (selected, leaf_count) =
            select_covering_root(std::slice::from_ref(&legacy_root), &leaves, 2).unwrap();

        assert_eq!(selected.root_hash, legacy_root.root_hash);
        assert_eq!(leaf_count, 2);
    }
}
