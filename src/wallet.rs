//! Embedded anchor wallet.
//!
//! Minimal shielded wallet for automated Merkle root anchoring.
//! Seeds the Orchard commitment tree from Zebra's z_gettreestate frontier,
//! then tracks new commitments via the scanner. Detects notes sent to the
//! anchor address and builds anchor transactions using
//! zcash_primitives::transaction::builder.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use incrementalmerkletree::{Position, Retention};
use orchard::keys::{
    FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
};
use orchard::tree::MerkleHashOrchard;
use orchard::Note;
use shardtree::store::memory::MemoryShardStore;
use shardtree::ShardTree;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::merkle_tree::read_commitment_tree;
use zcash_primitives::transaction::builder::{BuildConfig, Builder as TxBuilder};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::builder::TransparentSigningSet;

use crate::config::Config;
use crate::db::Db;
use crate::frost_signer::{FrostSigner, SigningMode};
use crate::memo::merkle_root_memo;
use crate::merkle::decode_hash;

/// No-op Sapling spend prover (anchor txs never have Sapling spends).
pub struct NoopSpendProver;
impl sapling_crypto::prover::SpendProver for NoopSpendProver {
    type Proof = sapling_crypto::bundle::GrothProofBytes;

    fn prepare_circuit(
        _: sapling_crypto::ProofGenerationKey,
        _: sapling_crypto::Diversifier,
        _: sapling_crypto::Rseed,
        _: sapling_crypto::value::NoteValue,
        _: jubjub::Fr,
        _: sapling_crypto::value::ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: sapling_crypto::MerklePath,
    ) -> Option<sapling_crypto::circuit::Spend> {
        unreachable!("No Sapling spends in anchor transactions")
    }

    fn create_proof<R: rand_core::RngCore>(
        &self,
        _: sapling_crypto::circuit::Spend,
        _: &mut R,
    ) -> Self::Proof {
        unreachable!("No Sapling spends in anchor transactions")
    }

    fn encode_proof(proof: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        proof
    }
}

/// No-op Sapling output prover (anchor txs never have Sapling outputs).
pub struct NoopOutputProver;
impl sapling_crypto::prover::OutputProver for NoopOutputProver {
    type Proof = sapling_crypto::bundle::GrothProofBytes;

    fn prepare_circuit(
        _: &sapling_crypto::keys::EphemeralSecretKey,
        _: sapling_crypto::PaymentAddress,
        _: jubjub::Fr,
        _: sapling_crypto::value::NoteValue,
        _: sapling_crypto::value::ValueCommitTrapdoor,
    ) -> sapling_crypto::circuit::Output {
        unreachable!("No Sapling outputs in anchor transactions")
    }

    fn create_proof<R: rand_core::RngCore>(
        &self,
        _: sapling_crypto::circuit::Output,
        _: &mut R,
    ) -> Self::Proof {
        unreachable!("No Sapling outputs in anchor transactions")
    }

    fn encode_proof(proof: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        proof
    }
}

const MAX_CHECKPOINTS: usize = 100;

type OrchardShardStore = MemoryShardStore<MerkleHashOrchard, BlockHeight>;
type OrchardTree = ShardTree<OrchardShardStore, 32, 16>;

#[derive(Debug, Clone)]
pub struct TrackedNote {
    pub note: Note,
    pub nullifier: [u8; 32],
    pub position: Position,
    pub height: u32,
    pub spent: bool,
}

pub struct AnchorWallet {
    #[allow(dead_code)]
    usk: UnifiedSpendingKey,
    fvk: FullViewingKey,
    sk: SpendingKey,
    tree: Mutex<OrchardTree>,
    notes: Mutex<Vec<TrackedNote>>,
    next_position: Mutex<u64>,
    seeded: AtomicBool,
    recovery_complete: AtomicBool,
    frost_signer: Option<FrostSigner>,
    signing_mode: SigningMode,
}

impl AnchorWallet {
    pub fn new<P: Parameters>(params: &P, seed_hex: &str) -> Result<Self> {
        let usk = crate::keys::spending_key_from_seed(params, seed_hex)?;
        let seed_bytes = hex::decode(seed_hex)?;

        let coin_type = match params.network_type() {
            zcash_protocol::consensus::NetworkType::Main => 133,
            zcash_protocol::consensus::NetworkType::Test => 1,
            zcash_protocol::consensus::NetworkType::Regtest => 1,
        };

        let orchard_sk =
            SpendingKey::from_zip32_seed(&seed_bytes, coin_type, zip32::AccountId::ZERO)
                .map_err(|_| anyhow::anyhow!("Failed to derive Orchard spending key"))?;
        let fvk = FullViewingKey::from(&orchard_sk);

        let store = MemoryShardStore::empty();
        let tree = ShardTree::new(store, MAX_CHECKPOINTS);

        Ok(Self {
            usk,
            fvk,
            sk: orchard_sk,
            tree: Mutex::new(tree),
            notes: Mutex::new(Vec::new()),
            next_position: Mutex::new(0),
            seeded: AtomicBool::new(false),
            recovery_complete: AtomicBool::new(false),
            frost_signer: None,
            signing_mode: SigningMode::SingleKey,
        })
    }

    /// Configure FROST threshold signing mode.
    pub fn set_frost_signer(&mut self, signer: FrostSigner) {
        self.frost_signer = Some(signer);
        self.signing_mode = SigningMode::FrostThreshold;
        tracing::info!("Anchor wallet: FROST threshold signing enabled");
    }

    /// Current signing mode.
    pub fn signing_mode(&self) -> &SigningMode {
        &self.signing_mode
    }

    /// Initialize the commitment tree from Zebra's z_gettreestate.
    /// Loads the full Orchard frontier (leaf + ommers + subtree roots)
    /// so the wallet can compute valid Merkle witnesses for spending.
    pub async fn init_from_zebra(&self, zebra_url: &str, height: u32) -> Result<()> {
        if self.seeded.load(Ordering::SeqCst) {
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // Get the tree state at scan_from_height - 1 (the state BEFORE we start scanning)
        let prior_height = height.saturating_sub(1);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "z_gettreestate",
            "params": [prior_height.to_string()],
        });
        let resp: serde_json::Value = client
            .post(zebra_url)
            .json(&body)
            .send()
            .await
            .context("z_gettreestate request failed")?
            .json()
            .await
            .context("z_gettreestate response parse failed")?;

        let final_state_hex = resp["result"]["orchard"]["commitments"]["finalState"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No orchard finalState in z_gettreestate response"))?;

        let state_bytes =
            hex::decode(final_state_hex).context("Failed to hex-decode orchard finalState")?;

        // Deserialize the legacy CommitmentTree and convert to Frontier
        let commitment_tree = read_commitment_tree::<
            MerkleHashOrchard,
            _,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >(&state_bytes[..])
        .context("Failed to deserialize Orchard commitment tree")?;

        let frontier = commitment_tree.to_frontier();

        // Get the frontier position (= next_position - 1, since frontier points at last leaf)
        let frontier_position = frontier.value().map(|f| u64::from(f.position()));

        // Insert frontier into ShardTree. This seeds:
        // - The current shard with the frontier leaf and sub-shard ommers
        // - The cap with ommer nodes at levels >= shard height (subtree roots)
        // This gives the tree all the hash data needed to compute witnesses.
        {
            let mut tree = self.tree.lock().unwrap();
            let checkpoint_id = BlockHeight::from_u32(prior_height);
            tree.insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: checkpoint_id,
                    marking: incrementalmerkletree::Marking::None,
                },
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert frontier into ShardTree: {:?}", e))?;
        }

        // Scanner will process blocks starting at `height`, so our next position
        // is one past the frontier's last leaf
        let next_pos_val = frontier_position.map(|p| p + 1).unwrap_or(0);
        {
            let mut next_pos = self.next_position.lock().unwrap();
            *next_pos = next_pos_val;
        }
        self.seeded.store(true, Ordering::SeqCst);

        tracing::info!(
            "Anchor wallet: tree seeded from z_gettreestate at height {}, frontier position {:?}, next_position {}",
            prior_height,
            frontier_position,
            next_pos_val,
        );

        Ok(())
    }

    /// Process a block's Orchard commitments into the ShardTree.
    pub fn process_block_commitments(
        &self,
        height: u32,
        raw_txs: &[(String, Vec<u8>)],
        network: &impl Parameters,
    ) -> Result<()> {
        let block_height = BlockHeight::from_u32(height);
        let branch_id = BranchId::for_height(network, block_height);

        let mut all_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = Vec::new();
        let mut our_notes: Vec<(Note, usize)> = Vec::new();
        let mut spent_nullifiers: Vec<[u8; 32]> = Vec::new();
        let external_ivk = self.fvk.to_ivk(Scope::External);
        let prepared_external_ivk = PreparedIncomingViewingKey::new(&external_ivk);
        let internal_ivk = self.fvk.to_ivk(Scope::Internal);
        let prepared_internal_ivk = PreparedIncomingViewingKey::new(&internal_ivk);

        for (_txid, raw) in raw_txs {
            let tx = match Transaction::read(&raw[..], branch_id) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let Some(bundle) = tx.orchard_bundle() else {
                continue;
            };

            for action in bundle.actions() {
                spent_nullifiers.push(action.nullifier().to_bytes());
                let cmx = *action.cmx();
                let idx = all_commitments.len();

                // Trial decrypt using full note decryption
                let domain = orchard::note_encryption::OrchardDomain::for_action(action);
                let decrypted = zcash_note_encryption::try_note_decryption(
                    &domain,
                    &prepared_external_ivk,
                    action,
                )
                .or_else(|| {
                    zcash_note_encryption::try_note_decryption(
                        &domain,
                        &prepared_internal_ivk,
                        action,
                    )
                });

                let retention = if let Some((note, _addr, _memo)) = decrypted {
                    our_notes.push((note, idx));
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };

                all_commitments.push((MerkleHashOrchard::from_cmx(&cmx), retention));
            }
        }

        let mut next_pos = self.next_position.lock().unwrap();

        if all_commitments.is_empty() {
            let mut tree = self.tree.lock().unwrap();
            tree.checkpoint(block_height)
                .map_err(|e| anyhow::anyhow!("Checkpoint failed: {:?}", e))?;
            return Ok(());
        }

        let start_pos = Position::from(*next_pos);
        let count = all_commitments.len() as u64;

        let mut tree = self.tree.lock().unwrap();
        tree.batch_insert(start_pos, all_commitments.into_iter())
            .map_err(|e| anyhow::anyhow!("Batch insert failed: {:?}", e))?;
        tree.checkpoint(block_height)
            .map_err(|e| anyhow::anyhow!("Checkpoint failed: {:?}", e))?;

        let mut notes = self.notes.lock().unwrap();
        for nullifier in spent_nullifiers {
            if let Some(tracked) = notes
                .iter_mut()
                .find(|n| !n.spent && n.nullifier == nullifier)
            {
                tracked.spent = true;
                tracing::info!(
                    "Anchor wallet: note at position {} marked spent at height {}",
                    u64::from(tracked.position),
                    height
                );
            }
        }
        for (note, idx) in our_notes {
            let position = Position::from(*next_pos + idx as u64);
            let nullifier = note.nullifier(&self.fvk).to_bytes();
            tracing::info!(
                "Anchor wallet: note {} zat at position {} height {}",
                note.value().inner(),
                u64::from(position),
                height
            );
            notes.push(TrackedNote {
                note,
                nullifier,
                position,
                height,
                spent: false,
            });
        }

        *next_pos += count;
        Ok(())
    }

    pub fn balance(&self) -> u64 {
        let notes = self.notes.lock().unwrap();
        notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.note.value().inner())
            .sum()
    }

    pub fn unspent_count(&self) -> usize {
        let notes = self.notes.lock().unwrap();
        notes.iter().filter(|n| !n.spent).count()
    }

    pub fn is_seeded(&self) -> bool {
        self.seeded.load(Ordering::SeqCst)
    }

    pub fn recovery_done(&self) -> bool {
        self.recovery_complete.load(Ordering::SeqCst)
    }

    pub fn mark_recovery_done(&self) {
        self.recovery_complete.store(true, Ordering::SeqCst);
    }

    /// Current next_position value (for diagnostics/testing).
    pub fn next_position_value(&self) -> u64 {
        *self.next_position.lock().unwrap()
    }

    /// External Orchard address for this wallet.
    pub fn fvk_address(&self) -> orchard::Address {
        self.fvk.address_at(0u64, Scope::External)
    }

    /// Compute the current tree root. Returns Err on tree errors, Ok(None) if empty.
    pub fn tree_root(&self) -> Result<Option<[u8; 32]>> {
        let tree = self.tree.lock().unwrap();
        match tree.root_at_checkpoint_depth(Some(0)) {
            Ok(Some(root)) => Ok(Some(root.to_bytes())),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Tree root computation failed: {:?}", e)),
        }
    }

    /// Try to compute a witness for the first unspent note (for testing).
    pub fn try_witness_first_note(&self) -> Result<()> {
        let notes = self.notes.lock().unwrap();
        let tracked = notes
            .iter()
            .find(|n| !n.spent)
            .ok_or_else(|| anyhow::anyhow!("No unspent notes"))?;
        let position = tracked.position;
        drop(notes);

        let tree = self.tree.lock().unwrap();
        let witness = tree
            .witness_at_checkpoint_depth(position, 0)
            .map_err(|e| anyhow::anyhow!("Witness computation failed: {:?}", e))?;
        match witness {
            Some(path) => {
                assert_eq!(
                    path.path_elems().len(),
                    32,
                    "Orchard witness must have 32 levels"
                );
                Ok(())
            }
            None => Err(anyhow::anyhow!(
                "No witness available at checkpoint depth 0"
            )),
        }
    }

    /// Build a complete signed anchor transaction.
    /// Returns (raw_tx_hex, txid_hex).
    pub fn build_anchor_tx<P: Parameters>(
        &self,
        params: &P,
        config: &Config,
        db: &Db,
        target_height: u32,
    ) -> Result<(String, String, Position)> {
        let root = db
            .current_merkle_root()?
            .ok_or_else(|| anyhow::anyhow!("No Merkle root to anchor"))?;
        let root_bytes = decode_hash(&root.root_hash)?;
        let memo_str = merkle_root_memo(&root_bytes).encode();
        let memo = MemoBytes::from_bytes(memo_str.as_bytes())
            .map_err(|_| anyhow::anyhow!("Memo too long"))?;

        // Select unspent note (must cover amount + fee)
        let fee_estimate = 10_000u64;
        let min_value = config.anchor_amount_zat + fee_estimate;
        let (note, note_value, position) = {
            let notes = self.notes.lock().unwrap();
            let note_idx = notes
                .iter()
                .position(|n| !n.spent && n.note.value().inner() >= min_value)
                .ok_or_else(|| {
                    let total: u64 = notes
                        .iter()
                        .filter(|n| !n.spent)
                        .map(|n| n.note.value().inner())
                        .sum();
                    anyhow::anyhow!(
                        "Insufficient anchor wallet balance (need {} zat, have {} zat)",
                        min_value,
                        total
                    )
                })?;
            let tracked = &notes[note_idx];
            (tracked.note, tracked.note.value().inner(), tracked.position)
        }; // notes lock dropped before tree lock to prevent deadlock

        // Get witness and anchor from commitment tree
        let tree = self.tree.lock().unwrap();
        let witness = tree
            .witness_at_checkpoint_depth(position, 0)
            .map_err(|e| anyhow::anyhow!("Witness computation failed: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("No witness for position {}", u64::from(position)))?;

        let tree_root = tree
            .root_at_checkpoint_depth(Some(0))
            .map_err(|e| anyhow::anyhow!("Tree root failed: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("No tree root"))?;
        let orchard_anchor = orchard::Anchor::from(tree_root);
        drop(tree);

        // Build the MerklePath from the witness
        let auth_path: [MerkleHashOrchard; 32] = witness
            .path_elems()
            .to_vec()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Witness path wrong length"))?;
        let merkle_path =
            orchard::tree::MerklePath::from_parts(u64::from(position) as u32, auth_path);

        // Build the transaction using zcash_primitives builder
        let target = BlockHeight::from_u32(target_height);
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor),
        };
        let mut builder = TxBuilder::new(params.clone(), target, build_config);

        // Add Orchard spend (our note)
        builder
            .add_orchard_spend::<FeeRule>(self.fvk.clone(), note, merkle_path)
            .map_err(|e| anyhow::anyhow!("Add orchard spend: {:?}", e))?;

        // Add Orchard output (anchor address with memo)
        let anchor_addr = self.fvk.address_at(0u64, Scope::External);
        let amount = Zatoshis::from_u64(config.anchor_amount_zat)
            .map_err(|_| anyhow::anyhow!("Invalid anchor amount"))?;
        builder
            .add_orchard_output::<FeeRule>(None, anchor_addr, amount, memo)
            .map_err(|e| anyhow::anyhow!("Add orchard output: {:?}", e))?;

        // Add change output (fee_estimate already set during note selection)
        let change = note_value
            .saturating_sub(config.anchor_amount_zat)
            .saturating_sub(fee_estimate);
        if change > 0 {
            let change_addr = self.fvk.address_at(0u64, Scope::Internal);
            let change_amount =
                Zatoshis::from_u64(change).map_err(|_| anyhow::anyhow!("Invalid change amount"))?;
            let empty_memo = MemoBytes::empty();
            builder
                .add_orchard_output::<FeeRule>(None, change_addr, change_amount, empty_memo)
                .map_err(|e| anyhow::anyhow!("Add change output: {:?}", e))?;
        }

        // Build, prove, and sign
        let rng = rand_core::OsRng;
        let transparent_signing = TransparentSigningSet::new();
        let fee_rule = FeeRule::standard();

        // Both signing modes use the single-key path for now.
        // FROST threshold signing produces a standalone authorization
        // signature over the sighash. Full FROST-in-bundle signing
        // requires the PCZT flow (orchard::pczt) to access alpha.
        let sak = SpendAuthorizingKey::from(&self.sk);
        let result = builder
            .build(
                &transparent_signing,
                &[],    // no Sapling keys
                &[sak], // Orchard signing key
                rng,
                &NoopSpendProver,
                &NoopOutputProver,
                &fee_rule,
            )
            .map_err(|e| anyhow::anyhow!("Transaction build failed: {:?}", e))?;

        // If FROST mode, also produce a threshold signature as proof of
        // multi-party authorization. This is logged and can be verified
        // independently against the FROST group public key.
        if self.signing_mode == SigningMode::FrostThreshold {
            if let Some(ref frost) = self.frost_signer {
                let sighash = result.transaction().txid().as_ref().to_vec();
                match frost.sign_raw(&sighash) {
                    Ok(sig) => {
                        let sig_hex = hex::encode(<[u8; 64]>::from(sig));
                        tracing::info!("FROST threshold signature: {}", &sig_hex[..32],);
                    }
                    Err(e) => {
                        tracing::error!("FROST signing failed: {}", e);
                    }
                }
            }
        }

        let tx = result.transaction();
        let txid = tx.txid().to_string();

        // Serialize
        let mut raw = Vec::new();
        tx.write(&mut raw)
            .map_err(|e| anyhow::anyhow!("Transaction serialize: {:?}", e))?;
        let tx_hex = hex::encode(&raw);

        tracing::info!(
            "Anchor tx built: txid={} ({} zat output)",
            txid.get(..16).unwrap_or(&txid),
            config.anchor_amount_zat,
        );

        Ok((tx_hex, txid, position))
    }

    /// Build a signed payout transaction to an external Orchard address.
    /// Returns (raw_tx_hex, txid_hex, spent_position).
    pub fn build_payout_tx<P: Parameters>(
        &self,
        params: &P,
        recipient: orchard::Address,
        amount_zat: u64,
        memo: MemoBytes,
        target_height: u32,
    ) -> Result<(String, String, Position)> {
        let fee_estimate = 10_000u64;
        let min_value = amount_zat + fee_estimate;
        let (note, note_value, position) = {
            let notes = self.notes.lock().unwrap();
            let note_idx = notes
                .iter()
                .position(|n| !n.spent && n.note.value().inner() >= min_value)
                .ok_or_else(|| {
                    let total: u64 = notes
                        .iter()
                        .filter(|n| !n.spent)
                        .map(|n| n.note.value().inner())
                        .sum();
                    anyhow::anyhow!(
                        "Insufficient pool wallet balance (need {} zat, have {} zat)",
                        min_value,
                        total
                    )
                })?;
            let tracked = &notes[note_idx];
            (tracked.note, tracked.note.value().inner(), tracked.position)
        };

        let tree = self.tree.lock().unwrap();
        let witness = tree
            .witness_at_checkpoint_depth(position, 0)
            .map_err(|e| anyhow::anyhow!("Witness computation failed: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("No witness for position {}", u64::from(position)))?;

        let tree_root = tree
            .root_at_checkpoint_depth(Some(0))
            .map_err(|e| anyhow::anyhow!("Tree root failed: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("No tree root"))?;
        let orchard_anchor = orchard::Anchor::from(tree_root);
        drop(tree);

        let auth_path: [MerkleHashOrchard; 32] = witness
            .path_elems()
            .to_vec()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Witness path wrong length"))?;
        let merkle_path =
            orchard::tree::MerklePath::from_parts(u64::from(position) as u32, auth_path);

        let target = BlockHeight::from_u32(target_height);
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor),
        };
        let mut builder = TxBuilder::new(params.clone(), target, build_config);

        builder
            .add_orchard_spend::<FeeRule>(self.fvk.clone(), note, merkle_path)
            .map_err(|e| anyhow::anyhow!("Add orchard spend: {:?}", e))?;

        let amount =
            Zatoshis::from_u64(amount_zat).map_err(|_| anyhow::anyhow!("Invalid payout amount"))?;
        builder
            .add_orchard_output::<FeeRule>(None, recipient, amount, memo)
            .map_err(|e| anyhow::anyhow!("Add orchard output: {:?}", e))?;

        let change = note_value
            .saturating_sub(amount_zat)
            .saturating_sub(fee_estimate);
        if change > 0 {
            let change_addr = self.fvk.address_at(0u64, Scope::Internal);
            let change_amount =
                Zatoshis::from_u64(change).map_err(|_| anyhow::anyhow!("Invalid change amount"))?;
            let empty_memo = MemoBytes::empty();
            builder
                .add_orchard_output::<FeeRule>(None, change_addr, change_amount, empty_memo)
                .map_err(|e| anyhow::anyhow!("Add change output: {:?}", e))?;
        }

        let rng = rand_core::OsRng;
        let sak = SpendAuthorizingKey::from(&self.sk);
        let transparent_signing = TransparentSigningSet::new();
        let fee_rule = FeeRule::standard();

        let result = builder
            .build(
                &transparent_signing,
                &[],
                &[sak],
                rng,
                &NoopSpendProver,
                &NoopOutputProver,
                &fee_rule,
            )
            .map_err(|e| anyhow::anyhow!("Transaction build failed: {:?}", e))?;

        let tx = result.transaction();
        let txid = tx.txid().to_string();

        let mut raw = Vec::new();
        tx.write(&mut raw)
            .map_err(|e| anyhow::anyhow!("Transaction serialize: {:?}", e))?;
        let tx_hex = hex::encode(&raw);

        tracing::info!(
            "Payout tx built: txid={} ({} zat to external)",
            txid.get(..16).unwrap_or(&txid),
            amount_zat,
        );

        Ok((tx_hex, txid, position))
    }

    pub fn mark_spent_at_position(&self, position: Position) -> Result<()> {
        let mut notes = self.notes.lock().unwrap();
        let tracked = notes
            .iter_mut()
            .find(|n| !n.spent && n.position == position)
            .ok_or_else(|| {
                anyhow::anyhow!("No unspent note at position {}", u64::from(position))
            })?;
        tracked.spent = true;
        Ok(())
    }
}
