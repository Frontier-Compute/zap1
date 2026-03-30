//! FROST_SIGNING_PROTOCOL.rs
//!
//! Sanitized reference code for the ZAP1 anchor-signing flow using
//! FROST(Pallas, BLAKE2b-512). This document preserves the protocol logic
//! while omitting any real key share values or deployment-specific file paths.

use frost_core::{frost, Ciphersuite, VerifyingKey};
use reddsa::frost::redpallas::{keys, round1, Identifier, PallasBlake2b512};
use std::collections::{BTreeMap, HashMap};

/// Public verifying key produced by the completed 2-of-3 Pallas key ceremony.
pub const GROUP_VERIFYING_KEY_HEX: &str =
    "5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90";

/// Minimal signer input required by the coordinator.
///
/// Real applications obtain `KeyPackage`s from a verified dealer share or DKG
/// output. That acquisition step is intentionally omitted here.
pub struct SignerInput {
    pub identifier: Identifier,
    pub key_package: keys::KeyPackage,
}

/// Round output that can be logged or exported as a test vector.
pub struct SigningRoundReport {
    pub aggregate_signature_hex: String,
    pub signer_commitments: Vec<(String, String, String)>,
}

/// Execute a plain (non-rerandomized) 2-of-3 FROST signing round.
pub fn sign_anchor_message(
    signers: &[SignerInput],
    message: &[u8],
) -> Result<SigningRoundReport, String> {
    if signers.len() != 2 {
        return Err("ZAP1 anchor signing requires exactly two participants in a 2-of-3 round".into());
    }

    let group_verifying_key = {
        let bytes: [u8; 32] = hex::decode(GROUP_VERIFYING_KEY_HEX)
            .map_err(|e| format!("invalid group key hex: {e}"))?
            .try_into()
            .map_err(|_| "invalid group key length".to_string())?;
        VerifyingKey::<PallasBlake2b512>::deserialize(bytes)
            .map_err(|e| format!("invalid group key encoding: {e}"))?
    };

    let mut rng = rand::thread_rng();
    let mut signer_pubkeys = HashMap::new();
    let mut nonces = HashMap::new();
    let mut commitments = BTreeMap::new();
    let mut key_packages = HashMap::new();

    for signer in signers {
        if signer.key_package.group_public().serialize() != group_verifying_key.serialize() {
            return Err(format!(
                "signer {} does not belong to the expected FROST group",
                hex::encode(signer.identifier.serialize())
            ));
        }

        signer_pubkeys.insert(signer.identifier, *signer.key_package.public());

        let (signing_nonces, signing_commitments) =
            round1::commit(signer.key_package.secret_share(), &mut rng);
        nonces.insert(signer.identifier, signing_nonces);
        commitments.insert(signer.identifier, signing_commitments);
        key_packages.insert(signer.identifier, signer.key_package.clone());
    }

    let public_key_package =
        frost::keys::PublicKeyPackage::<PallasBlake2b512>::new(signer_pubkeys, group_verifying_key);
    let signing_package = frost::SigningPackage::<PallasBlake2b512>::new(commitments.clone(), message);

    let mut signature_shares = HashMap::new();
    let mut signer_commitments = Vec::new();

    for (identifier, signing_commitments) in &commitments {
        let signature_share = frost::round2::sign(
            &signing_package,
            nonces
                .get(identifier)
                .ok_or_else(|| "missing signing nonces".to_string())?,
            key_packages
                .get(identifier)
                .ok_or_else(|| "missing key package".to_string())?,
        )
        .map_err(|e| format!("signing failed for {}: {e}", hex::encode(identifier.serialize())))?;

        signature_shares.insert(*identifier, signature_share);
        signer_commitments.push((
            hex::encode(identifier.serialize()),
            hex::encode(signing_commitments.hiding().serialize()),
            hex::encode(signing_commitments.binding().serialize()),
        ));
    }

    let aggregate_signature =
        frost::aggregate(&signing_package, &signature_shares, &public_key_package)
            .map_err(|e| format!("signature aggregation failed: {e}"))?;

    public_key_package
        .group_public()
        .verify(message, &aggregate_signature)
        .map_err(|e| format!("aggregate verification failed: {e}"))?;

    Ok(SigningRoundReport {
        aggregate_signature_hex: hex::encode(aggregate_signature.serialize()),
        signer_commitments,
    })
}
