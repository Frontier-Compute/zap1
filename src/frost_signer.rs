//! FROST threshold signing for Orchard spend authorization.
//!
//! Implements 2-of-3 threshold signing using FROST(Pallas, BLAKE2b-512)
//! via the reddsa crate's frost module. Holds shares 2 and 3 locally,
//! runs both signing rounds in-process to produce a valid RedPallas
//! SpendAuth signature.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use pasta_curves::pallas;
use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage};
use reddsa::frost::redpallas::{self, round1, round2, Identifier, PallasBlake2b512};

use frost_rerandomized::frost_core::frost;
use frost_rerandomized::frost_core::{Ciphersuite, Group};
use frost_rerandomized::RandomizedParams;

/// JSON format matching the ceremony output.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ShareJson {
    ciphersuite: String,
    identifier: String,
    signing_share: String,
    verifying_share: String,
    group_verifying_key: String,
    commitment: Vec<String>,
    threshold: u16,
    max_signers: u16,
}

/// FROST threshold signer holding two key packages for local 2-of-2 signing.
pub struct FrostSigner {
    key_pkg_2: KeyPackage,
    key_pkg_3: KeyPackage,
    pub_key_pkg: PublicKeyPackage,
}

impl FrostSigner {
    /// Load from two JSON share files on disk.
    pub fn from_files(path_2: &Path, path_3: &Path) -> Result<Self> {
        let share_2 = Self::load_share(path_2)?;
        let share_3 = Self::load_share(path_3)?;

        // Verify both shares reference the same group key
        let gvk_2_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
            &share_2.group_public().to_element(),
        );
        let gvk_3_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
            &share_3.group_public().to_element(),
        );
        if gvk_2_bytes != gvk_3_bytes {
            anyhow::bail!("FROST shares reference different group keys");
        }

        // Build PublicKeyPackage from the two shares
        let mut signer_pubkeys = std::collections::HashMap::new();
        signer_pubkeys.insert(*share_2.identifier(), *share_2.public());
        signer_pubkeys.insert(*share_3.identifier(), *share_3.public());
        let pub_key_pkg = PublicKeyPackage::new(signer_pubkeys, *share_2.group_public());

        Ok(Self {
            key_pkg_2: share_2,
            key_pkg_3: share_3,
            pub_key_pkg,
        })
    }

    /// Load a single share from JSON and construct a KeyPackage.
    fn load_share(path: &Path) -> Result<KeyPackage> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading FROST share from {}", path.display()))?;
        let json: ShareJson = serde_json::from_str(&data).context("parsing FROST share JSON")?;

        if json.ciphersuite != "FROST(Pallas, BLAKE2b-512)" {
            anyhow::bail!(
                "wrong ciphersuite: expected FROST(Pallas, BLAKE2b-512), got {}",
                json.ciphersuite
            );
        }

        // Deserialize identifier (32-byte LE scalar)
        let id_bytes: [u8; 32] = hex::decode(&json.identifier)
            .context("hex-decode identifier")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("identifier must be 32 bytes"))?;
        let identifier = Identifier::deserialize(&id_bytes)
            .map_err(|e| anyhow::anyhow!("bad identifier: {}", e))?;

        // Deserialize signing share
        let ss_bytes: [u8; 32] = hex::decode(&json.signing_share)
            .context("hex-decode signing_share")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing_share must be 32 bytes"))?;
        let signing_share = frost::keys::SigningShare::<PallasBlake2b512>::deserialize(ss_bytes)
            .map_err(|e| anyhow::anyhow!("bad signing_share: {}", e))?;

        // Deserialize verifying share (point)
        let vs_bytes: [u8; 32] = hex::decode(&json.verifying_share)
            .context("hex-decode verifying_share")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("verifying_share must be 32 bytes"))?;
        let verifying_share =
            frost::keys::VerifyingShare::<PallasBlake2b512>::deserialize(vs_bytes)
                .map_err(|e| anyhow::anyhow!("bad verifying_share: {}", e))?;

        // Deserialize group verifying key
        let gvk_bytes: [u8; 32] = hex::decode(&json.group_verifying_key)
            .context("hex-decode group_verifying_key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("group_verifying_key must be 32 bytes"))?;
        let group_public =
            frost_rerandomized::frost_core::VerifyingKey::<PallasBlake2b512>::deserialize(
                gvk_bytes,
            )
            .map_err(|e| anyhow::anyhow!("bad group_verifying_key: {}", e))?;

        Ok(KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            group_public,
        ))
    }

    /// The FROST group verifying key (the group public key on Pallas).
    pub fn group_verifying_key(
        &self,
    ) -> &frost_rerandomized::frost_core::VerifyingKey<PallasBlake2b512> {
        self.pub_key_pkg.group_public()
    }

    /// Sign a message using both shares locally (2-of-3 threshold).
    ///
    /// Runs FROST round 1 for both signers, round 2 for both, then
    /// aggregates into a final rerandomized Schnorr signature.
    ///
    /// `randomizer` is the Orchard spend-auth randomizer (alpha). For
    /// non-rerandomized signing, pass the zero scalar.
    pub fn sign(
        &self,
        msg: &[u8],
        randomizer: pallas::Scalar,
    ) -> Result<reddsa::Signature<reddsa::orchard::SpendAuth>> {
        let mut rng = rand::rngs::OsRng;

        // Round 1: both signers generate nonces and commitments
        let (nonces_2, commitments_2) = round1::commit(self.key_pkg_2.secret_share(), &mut rng);
        let (nonces_3, commitments_3) = round1::commit(self.key_pkg_3.secret_share(), &mut rng);

        // Build the signing package (commitments + message)
        let mut commitment_map = BTreeMap::new();
        commitment_map.insert(*self.key_pkg_2.identifier(), commitments_2);
        commitment_map.insert(*self.key_pkg_3.identifier(), commitments_3);

        let signing_package = frost::SigningPackage::new(commitment_map, msg);

        // Compute the randomizer point for rerandomized FROST
        let randomized_params = RandomizedParams::from_randomizer(&self.pub_key_pkg, randomizer);

        // Round 2: both signers produce signature shares
        let sig_share_2 = round2::sign(
            &signing_package,
            &nonces_2,
            &self.key_pkg_2,
            randomized_params.randomizer_point(),
        )
        .map_err(|e| anyhow::anyhow!("FROST round2 signer 2: {}", e))?;

        let sig_share_3 = round2::sign(
            &signing_package,
            &nonces_3,
            &self.key_pkg_3,
            randomized_params.randomizer_point(),
        )
        .map_err(|e| anyhow::anyhow!("FROST round2 signer 3: {}", e))?;

        // Aggregate
        let mut shares = std::collections::HashMap::new();
        shares.insert(*self.key_pkg_2.identifier(), sig_share_2);
        shares.insert(*self.key_pkg_3.identifier(), sig_share_3);

        let group_sig = redpallas::aggregate(
            &signing_package,
            &shares,
            &self.pub_key_pkg,
            &randomized_params,
        )
        .map_err(|e| anyhow::anyhow!("FROST aggregate: {}", e))?;

        // Convert frost signature to reddsa signature
        let sig_ser: [u8; 64] = group_sig.serialize();
        Ok(reddsa::Signature::from(sig_ser))
    }

    /// Sign without rerandomization (for testing or standalone proofs).
    pub fn sign_raw(&self, msg: &[u8]) -> Result<reddsa::Signature<reddsa::orchard::SpendAuth>> {
        self.sign(msg, pallas::Scalar::zero())
    }

    /// Verify a signature against the group public key (for testing).
    pub fn verify(
        &self,
        msg: &[u8],
        sig: &reddsa::Signature<reddsa::orchard::SpendAuth>,
    ) -> Result<()> {
        let vk_ser: [u8; 32] = self.group_verifying_key().serialize();
        let vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(
            reddsa::VerificationKeyBytes::from(vk_ser),
        )
        .map_err(|e| anyhow::anyhow!("bad verification key: {}", e))?;
        vk.verify(msg, sig)
            .map_err(|e| anyhow::anyhow!("signature verification failed: {}", e))
    }
}

/// Signing mode for the anchor wallet.
#[derive(Debug, Clone, PartialEq)]
pub enum SigningMode {
    /// Standard single-key signing via SpendAuthorizingKey.
    SingleKey,
    /// FROST 2-of-3 threshold signing.
    FrostThreshold,
}

impl SigningMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "frost" | "frost_threshold" | "threshold" => Self::FrostThreshold,
            _ => Self::SingleKey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_rerandomized::frost_core::frost::keys::IdentifierList;
    use pasta_curves::group::ff::Field;
    use reddsa::frost::redpallas::keys;

    #[test]
    fn test_frost_sign_verify_roundtrip() {
        let mut rng = rand::rngs::OsRng;

        // Generate a 2-of-3 key set with dealer
        let (shares, pub_key_pkg) =
            keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng)
                .expect("dealer keygen");

        // Extract shares 2 and 3
        let id_2 = Identifier::try_from(2u16).unwrap();
        let id_3 = Identifier::try_from(3u16).unwrap();

        let key_pkg_2: KeyPackage = shares[&id_2].clone().try_into().unwrap();
        let key_pkg_3: KeyPackage = shares[&id_3].clone().try_into().unwrap();

        let mut signer_pubkeys = std::collections::HashMap::new();
        signer_pubkeys.insert(*key_pkg_2.identifier(), *key_pkg_2.public());
        signer_pubkeys.insert(*key_pkg_3.identifier(), *key_pkg_3.public());

        let pub_pkg = PublicKeyPackage::new(signer_pubkeys, *pub_key_pkg.group_public());

        let signer = FrostSigner {
            key_pkg_2,
            key_pkg_3,
            pub_key_pkg: pub_pkg,
        };

        let msg = b"zap1 anchor merkle root test";
        let sig = signer.sign_raw(msg).expect("signing");
        signer.verify(msg, &sig).expect("verification");
    }

    #[test]
    fn test_frost_rerandomized_sign_verify() {
        let mut rng = rand::rngs::OsRng;

        let (shares, pub_key_pkg) =
            keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng)
                .expect("dealer keygen");

        let id_2 = Identifier::try_from(2u16).unwrap();
        let id_3 = Identifier::try_from(3u16).unwrap();

        let key_pkg_2: KeyPackage = shares[&id_2].clone().try_into().unwrap();
        let key_pkg_3: KeyPackage = shares[&id_3].clone().try_into().unwrap();

        let mut signer_pubkeys = std::collections::HashMap::new();
        signer_pubkeys.insert(*key_pkg_2.identifier(), *key_pkg_2.public());
        signer_pubkeys.insert(*key_pkg_3.identifier(), *key_pkg_3.public());

        let pub_pkg = PublicKeyPackage::new(signer_pubkeys, *pub_key_pkg.group_public());

        let signer = FrostSigner {
            key_pkg_2,
            key_pkg_3,
            pub_key_pkg: pub_pkg,
        };

        // Test with rerandomization (simulating Orchard alpha)
        let alpha = pallas::Scalar::random(&mut rng);
        let msg = b"sighash test with rerandomization";
        let sig = signer.sign(msg, alpha).expect("rerandomized signing");

        // Verify against the rerandomized public key
        let group_point = pub_key_pkg.group_public().to_element();
        let randomizer_point =
            <<PallasBlake2b512 as Ciphersuite>::Group as Group>::generator() * alpha;
        let rk_point = group_point + randomizer_point;
        let rk_bytes: [u8; 32] =
            <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(&rk_point);
        let rk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(
            reddsa::VerificationKeyBytes::from(rk_bytes),
        )
        .expect("rk");
        rk.verify(msg, &sig).expect("rerandomized verification");
    }
}
