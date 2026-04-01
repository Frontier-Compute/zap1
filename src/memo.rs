use anyhow::{anyhow, Result};
use blake2b_simd::Params;

const MEMO_PREFIX: &str = "ZAP1";
/// Legacy prefix accepted during decoding for backward compatibility.
const LEGACY_MEMO_PREFIX: &str = "NSM1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoType {
    ProgramEntry = 0x01,
    OwnershipAttest = 0x02,
    ContractAnchor = 0x03,
    Deployment = 0x04,
    HostingPayment = 0x05,
    ShieldRenewal = 0x06,
    Transfer = 0x07,
    Exit = 0x08,
    MerkleRoot = 0x09,
    StakingDeposit = 0x0A,
    StakingWithdraw = 0x0B,
    StakingReward = 0x0C,
}

impl MemoType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::ProgramEntry),
            0x02 => Ok(Self::OwnershipAttest),
            0x03 => Ok(Self::ContractAnchor),
            0x04 => Ok(Self::Deployment),
            0x05 => Ok(Self::HostingPayment),
            0x06 => Ok(Self::ShieldRenewal),
            0x07 => Ok(Self::Transfer),
            0x08 => Ok(Self::Exit),
            0x09 => Ok(Self::MerkleRoot),
            0x0A => Ok(Self::StakingDeposit),
            0x0B => Ok(Self::StakingWithdraw),
            0x0C => Ok(Self::StakingReward),
            _ => Err(anyhow!("unknown memo type: 0x{value:02x}")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ProgramEntry => "PROGRAM_ENTRY",
            Self::OwnershipAttest => "OWNERSHIP_ATTEST",
            Self::ContractAnchor => "CONTRACT_ANCHOR",
            Self::Deployment => "DEPLOYMENT",
            Self::HostingPayment => "HOSTING_PAYMENT",
            Self::ShieldRenewal => "SHIELD_RENEWAL",
            Self::Transfer => "TRANSFER",
            Self::Exit => "EXIT",
            Self::MerkleRoot => "MERKLE_ROOT",
            Self::StakingDeposit => "STAKING_DEPOSIT",
            Self::StakingWithdraw => "STAKING_WITHDRAW",
            Self::StakingReward => "STAKING_REWARD",
        }
    }

    /// Parse from label string (e.g. "HOSTING_PAYMENT" -> HostingPayment)
    pub fn from_label(s: &str) -> Result<Self> {
        match s {
            "PROGRAM_ENTRY" => Ok(Self::ProgramEntry),
            "OWNERSHIP_ATTEST" => Ok(Self::OwnershipAttest),
            "CONTRACT_ANCHOR" => Ok(Self::ContractAnchor),
            "DEPLOYMENT" => Ok(Self::Deployment),
            "HOSTING_PAYMENT" => Ok(Self::HostingPayment),
            "SHIELD_RENEWAL" => Ok(Self::ShieldRenewal),
            "TRANSFER" => Ok(Self::Transfer),
            "EXIT" => Ok(Self::Exit),
            "MERKLE_ROOT" => Ok(Self::MerkleRoot),
            "STAKING_DEPOSIT" => Ok(Self::StakingDeposit),
            "STAKING_WITHDRAW" => Ok(Self::StakingWithdraw),
            "STAKING_REWARD" => Ok(Self::StakingReward),
            _ => Err(anyhow!("unknown memo label: {s}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StructuredMemo {
    pub memo_type: MemoType,
    pub payload: [u8; 32],
}

impl StructuredMemo {
    pub fn encode(&self) -> String {
        format!(
            "{MEMO_PREFIX}:{:02x}:{}",
            self.memo_type.as_u8(),
            hex::encode(self.payload)
        )
    }

    pub fn decode(input: &str) -> Result<Self> {
        let mut parts = input.split(':');
        let prefix = parts.next().ok_or_else(|| anyhow!("missing memo prefix"))?;
        if prefix != MEMO_PREFIX && prefix != LEGACY_MEMO_PREFIX {
            return Err(anyhow!("unexpected memo prefix: {prefix}"));
        }

        let memo_type_hex = parts.next().ok_or_else(|| anyhow!("missing memo type"))?;
        let memo_type = MemoType::from_u8(u8::from_str_radix(memo_type_hex, 16)?)?;
        let payload_hex = parts
            .next()
            .ok_or_else(|| anyhow!("missing memo payload"))?;
        if parts.next().is_some() {
            return Err(anyhow!("unexpected extra memo fields"));
        }

        let payload_bytes = hex::decode(payload_hex)?;
        if payload_bytes.len() != 32 {
            return Err(anyhow!("memo payload must be exactly 32 bytes"));
        }

        let mut payload = [0u8; 32];
        payload.copy_from_slice(&payload_bytes);

        Ok(Self { memo_type, payload })
    }
}

pub fn hash_program_entry(wallet_hash: &str) -> [u8; 32] {
    hash_payload(MemoType::ProgramEntry, wallet_hash.as_bytes())
}

pub fn hash_ownership_attest(wallet_hash: &str, serial_number: &str) -> [u8; 32] {
    let mut payload = Vec::with_capacity(wallet_hash.len() + serial_number.len() + 4);
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    hash_payload(MemoType::OwnershipAttest, &payload)
}

/// 0x03 CONTRACT_ANCHOR: hash(serial_number || contract_sha256)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_contract_anchor(serial_number: &str, contract_sha256: &str) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    payload.extend_from_slice(&(contract_sha256.len() as u16).to_be_bytes());
    payload.extend_from_slice(contract_sha256.as_bytes());
    hash_payload(MemoType::ContractAnchor, &payload)
}

/// 0x04 DEPLOYMENT: hash(serial_number || facility_id || timestamp_be)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_deployment(serial_number: &str, facility_id: &str, timestamp: u64) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    payload.extend_from_slice(&(facility_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(facility_id.as_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    hash_payload(MemoType::Deployment, &payload)
}

/// 0x05 HOSTING_PAYMENT: hash(serial_number || month_be || year_be)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_hosting_payment(serial_number: &str, month: u32, year: u32) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    payload.extend_from_slice(&month.to_be_bytes());
    payload.extend_from_slice(&year.to_be_bytes());
    hash_payload(MemoType::HostingPayment, &payload)
}

/// 0x06 SHIELD_RENEWAL: hash(wallet_hash || year_be)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_shield_renewal(wallet_hash: &str, year: u32) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&year.to_be_bytes());
    hash_payload(MemoType::ShieldRenewal, &payload)
}

/// 0x07 TRANSFER: hash(old_wallet || new_wallet || serial_number)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_transfer(
    old_wallet_hash: &str,
    new_wallet_hash: &str,
    serial_number: &str,
) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(old_wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(old_wallet_hash.as_bytes());
    payload.extend_from_slice(&(new_wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(new_wallet_hash.as_bytes());
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    hash_payload(MemoType::Transfer, &payload)
}

/// 0x08 EXIT: hash(wallet_hash || serial_number || timestamp_be)
/// Per ONCHAIN_PROTOCOL.md Section 3
pub fn hash_exit(wallet_hash: &str, serial_number: &str, timestamp: u64) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&(serial_number.len() as u16).to_be_bytes());
    payload.extend_from_slice(serial_number.as_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    hash_payload(MemoType::Exit, &payload)
}

pub fn hash_staking_deposit(wallet_hash: &str, amount_zat: u64, validator_id: &str) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&amount_zat.to_be_bytes());
    payload.extend_from_slice(&(validator_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(validator_id.as_bytes());
    hash_payload(MemoType::StakingDeposit, &payload)
}

pub fn hash_staking_withdraw(wallet_hash: &str, amount_zat: u64, validator_id: &str) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&amount_zat.to_be_bytes());
    payload.extend_from_slice(&(validator_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(validator_id.as_bytes());
    hash_payload(MemoType::StakingWithdraw, &payload)
}

pub fn hash_staking_reward(wallet_hash: &str, amount_zat: u64, epoch: u32) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(wallet_hash.len() as u16).to_be_bytes());
    payload.extend_from_slice(wallet_hash.as_bytes());
    payload.extend_from_slice(&amount_zat.to_be_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    hash_payload(MemoType::StakingReward, &payload)
}

pub fn merkle_root_memo(root_hash: &[u8; 32]) -> StructuredMemo {
    StructuredMemo {
        memo_type: MemoType::MerkleRoot,
        payload: *root_hash,
    }
}

fn hash_payload(memo_type: MemoType, payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + payload.len());
    input.push(memo_type.as_u8());
    input.extend_from_slice(payload);

    let hash = Params::new()
        .hash_length(32)
        .personal(&personalization())
        .hash(&input);

    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

fn personalization() -> [u8; 16] {
    let mut personal = [0u8; 16];
    personal[..13].copy_from_slice(b"NordicShield_");
    personal
}
