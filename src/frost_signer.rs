//! Experimental co-located FROST signing for Orchard spend authorization.
//!
//! This module implements the cryptographic 2-of-3 signing round using
//! FROST(Pallas, BLAKE2b-512), but it loads two long-term shares into one
//! process and runs both signing rounds locally. In the embedded anchor path
//! that process also holds `ANCHOR_SEED`, which is a full spending-key path.
//! It therefore demonstrates signature compatibility, not independent
//! threshold custody, and must not be presented or enabled as a production
//! custody control.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use pasta_curves::pallas;
use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use reddsa::frost::redpallas::{self, round1, round2, Identifier, PallasBlake2b512};

use frost_rerandomized::frost_core::frost;
use frost_rerandomized::frost_core::{Ciphersuite, Group};
use frost_rerandomized::RandomizedParams;

const EXPECTED_CIPHERSUITE: &str = "FROST(Pallas, BLAKE2b-512)";
const EXPECTED_THRESHOLD: u16 = 2;
const EXPECTED_MAX_SIGNERS: u16 = 3;

/// JSON format matching the ceremony output.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

struct LoadedShare {
    key_package: KeyPackage,
    commitment: Vec<[u8; 32]>,
}

/// Experimental signer holding two key packages for co-located 2-of-3 signing.
pub struct FrostSigner {
    key_pkg_2: KeyPackage,
    key_pkg_3: KeyPackage,
    pub_key_pkg: PublicKeyPackage,
}

impl FrostSigner {
    /// Load and validate two ceremony share files on disk.
    ///
    /// This constructor validates the ceremony metadata and cryptographic VSS
    /// relationship. It does not turn co-located shares into independent
    /// custody; runtime activation is separately fail-closed by configuration.
    pub fn from_files(
        path_2: &Path,
        path_3: &Path,
        experimental_colocated_frost_enabled: bool,
    ) -> Result<Self> {
        if !experimental_colocated_frost_enabled {
            anyhow::bail!(
                "co-located FROST is experimental and non-production; explicit EXPERIMENTAL_COLOCATED_FROST_ENABLED=true opt-in is required"
            );
        }
        let canonical_2 = Self::canonical_share_file(path_2)?;
        let canonical_3 = Self::canonical_share_file(path_3)?;
        if Self::same_file(&canonical_2, &canonical_3)? {
            anyhow::bail!("FROST share paths must resolve to two distinct files");
        }

        let share_2 = Self::load_share(&canonical_2)?;
        let share_3 = Self::load_share(&canonical_3)?;

        if share_2.key_package.identifier() == share_3.key_package.identifier() {
            anyhow::bail!("FROST share files must contain distinct participant identifiers");
        }
        if share_2.commitment != share_3.commitment {
            anyhow::bail!("FROST share files contain different VSS commitment vectors");
        }

        // The individual VSS checks below derive each group key from
        // commitment[0]. This pairwise comparison additionally guarantees both
        // locally loaded shares agree on the same group.
        let gvk_2_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
            &share_2.key_package.group_public().to_element(),
        );
        let gvk_3_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
            &share_3.key_package.group_public().to_element(),
        );
        if gvk_2_bytes != gvk_3_bytes {
            anyhow::bail!("FROST shares reference different group keys");
        }

        // Build PublicKeyPackage from the two shares
        let mut signer_pubkeys = std::collections::HashMap::new();
        signer_pubkeys.insert(
            *share_2.key_package.identifier(),
            *share_2.key_package.public(),
        );
        signer_pubkeys.insert(
            *share_3.key_package.identifier(),
            *share_3.key_package.public(),
        );
        let pub_key_pkg =
            PublicKeyPackage::new(signer_pubkeys, *share_2.key_package.group_public());

        Ok(Self {
            key_pkg_2: share_2.key_package,
            key_pkg_3: share_3.key_package,
            pub_key_pkg,
        })
    }

    fn canonical_share_file(path: &Path) -> Result<PathBuf> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("reading FROST share metadata from {}", path.display()))?;
        if !metadata.is_file() {
            anyhow::bail!("FROST share path is not a regular file: {}", path.display());
        }
        std::fs::canonicalize(path)
            .with_context(|| format!("canonicalizing FROST share path {}", path.display()))
    }

    fn same_file(path_2: &Path, path_3: &Path) -> Result<bool> {
        if path_2 == path_3 {
            return Ok(true);
        }

        #[cfg(windows)]
        {
            use std::ffi::c_void;
            use std::os::windows::io::AsRawHandle;

            #[repr(C)]
            #[derive(Default)]
            struct ByHandleFileInformation {
                file_attributes: u32,
                creation_time_low: u32,
                creation_time_high: u32,
                last_access_time_low: u32,
                last_access_time_high: u32,
                last_write_time_low: u32,
                last_write_time_high: u32,
                volume_serial_number: u32,
                file_size_high: u32,
                file_size_low: u32,
                number_of_links: u32,
                file_index_high: u32,
                file_index_low: u32,
            }

            #[link(name = "kernel32")]
            extern "system" {
                fn GetFileInformationByHandle(
                    file: *mut c_void,
                    information: *mut ByHandleFileInformation,
                ) -> i32;
            }

            fn file_identity(path: &Path) -> Result<(u32, u64)> {
                let file = std::fs::File::open(path)
                    .with_context(|| format!("opening FROST share file {}", path.display()))?;
                let mut information = ByHandleFileInformation::default();
                // SAFETY: `file` remains open for the call and `information`
                // points to a correctly laid out writable Win32 structure.
                let success = unsafe {
                    GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information)
                };
                if success == 0 {
                    return Err(std::io::Error::last_os_error()).with_context(|| {
                        format!("reading FROST share file identity from {}", path.display())
                    });
                }
                let file_index = ((information.file_index_high as u64) << 32)
                    | information.file_index_low as u64;
                Ok((information.volume_serial_number, file_index))
            }

            return Ok(file_identity(path_2)? == file_identity(path_3)?);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata_2 = std::fs::metadata(path_2).with_context(|| {
                format!("reading FROST share metadata from {}", path_2.display())
            })?;
            let metadata_3 = std::fs::metadata(path_3).with_context(|| {
                format!("reading FROST share metadata from {}", path_3.display())
            })?;
            return Ok(metadata_2.dev() == metadata_3.dev() && metadata_2.ino() == metadata_3.ino());
        }

        #[allow(unreachable_code)]
        Ok(false)
    }

    /// Load a single share, validate its VSS commitment, and construct a
    /// cryptographically consistent KeyPackage.
    fn load_share(path: &Path) -> Result<LoadedShare> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading FROST share from {}", path.display()))?;
        let json: ShareJson = serde_json::from_str(&data).context("parsing FROST share JSON")?;

        if json.ciphersuite != EXPECTED_CIPHERSUITE {
            anyhow::bail!(
                "wrong ciphersuite: expected {}, got {}",
                EXPECTED_CIPHERSUITE,
                json.ciphersuite
            );
        }
        if json.threshold != EXPECTED_THRESHOLD {
            anyhow::bail!(
                "wrong FROST threshold: expected {}, got {}",
                EXPECTED_THRESHOLD,
                json.threshold
            );
        }
        if json.max_signers != EXPECTED_MAX_SIGNERS {
            anyhow::bail!(
                "wrong FROST max_signers: expected {}, got {}",
                EXPECTED_MAX_SIGNERS,
                json.max_signers
            );
        }
        if json.commitment.len() != EXPECTED_THRESHOLD as usize {
            anyhow::bail!(
                "wrong FROST commitment length: expected {}, got {}",
                EXPECTED_THRESHOLD,
                json.commitment.len()
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

        // Parse every polynomial coefficient commitment before using the
        // declared group key. Malformed or identity points fail closed.
        let commitment: Vec<[u8; 32]> = json
            .commitment
            .iter()
            .enumerate()
            .map(|(index, encoded)| {
                hex::decode(encoded)
                    .with_context(|| format!("hex-decode commitment[{index}]"))?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("commitment[{index}] must be 32 bytes"))
            })
            .collect::<Result<_>>()?;
        let vss_commitment =
            frost::keys::VerifiableSecretSharingCommitment::<PallasBlake2b512>::deserialize(
                commitment.clone(),
            )
            .map_err(|e| anyhow::anyhow!("bad VSS commitment: {}", e))?;

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

        if commitment[0] != gvk_bytes {
            anyhow::bail!("FROST group_verifying_key does not match commitment[0]");
        }

        // SecretShare::verify evaluates the full VSS polynomial commitment at
        // this identifier and checks it against the secret signing share. It
        // also derives the authoritative verifying share and group key.
        let secret_share = SecretShare::new(identifier, signing_share, vss_commitment);
        let (derived_verifying_share, derived_group_public) = secret_share
            .verify()
            .map_err(|e| anyhow::anyhow!("FROST share failed VSS validation: {}", e))?;
        if derived_verifying_share.serialize() != verifying_share.serialize() {
            anyhow::bail!(
                "FROST verifying_share is inconsistent with signing_share and commitment"
            );
        }
        if derived_group_public.serialize() != group_public.serialize() {
            anyhow::bail!("FROST group_verifying_key is inconsistent with the VSS commitment");
        }

        let key_package: KeyPackage = secret_share
            .try_into()
            .map_err(|e| anyhow::anyhow!("constructing validated FROST key package: {}", e))?;

        Ok(LoadedShare {
            key_package,
            commitment,
        })
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
    /// Experimental co-located FROST 2-of-3 signing. This describes the
    /// cryptographic construction, not an independent custody boundary.
    FrostThreshold,
}

impl SigningMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "single_key" => Ok(Self::SingleKey),
            "frost" => Ok(Self::FrostThreshold),
            _ => anyhow::bail!("signing mode must be exactly single_key or frost"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_rerandomized::frost_core::frost::keys::IdentifierList;
    use pasta_curves::group::ff::Field;
    use reddsa::frost::redpallas::keys;
    use serde_json::Value;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempSharePair {
        dir: PathBuf,
        path_2: PathBuf,
        path_3: PathBuf,
    }

    impl Drop for TempSharePair {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn ceremony_values() -> (Value, Value) {
        let mut rng = rand::rngs::OsRng;
        let (shares, pub_key_pkg) =
            keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng)
                .expect("dealer keygen");
        let id_2 = Identifier::try_from(2u16).unwrap();
        let id_3 = Identifier::try_from(3u16).unwrap();

        let to_json = |share: &SecretShare| {
            let (verifying_share, group_public) = share.verify().expect("valid dealer share");
            assert_eq!(
                group_public.serialize(),
                pub_key_pkg.group_public().serialize()
            );
            let commitment = share
                .commitment()
                .serialize()
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>();

            serde_json::json!({
                "ciphersuite": EXPECTED_CIPHERSUITE,
                "identifier": hex::encode(share.identifier().serialize()),
                "signing_share": hex::encode(share.secret().serialize()),
                "verifying_share": hex::encode(verifying_share.serialize()),
                "group_verifying_key": hex::encode(group_public.serialize()),
                "commitment": commitment,
                "threshold": EXPECTED_THRESHOLD,
                "max_signers": EXPECTED_MAX_SIGNERS,
            })
        };

        (to_json(&shares[&id_2]), to_json(&shares[&id_3]))
    }

    fn write_pair(value_2: &Value, value_3: &Value) -> TempSharePair {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("zap1-frost-test-{}-{}", std::process::id(), nonce));
        std::fs::create_dir(&dir).expect("create test directory");
        let path_2 = dir.join("share-2.json");
        let path_3 = dir.join("share-3.json");
        std::fs::write(&path_2, serde_json::to_vec(value_2).unwrap()).unwrap();
        std::fs::write(&path_3, serde_json::to_vec(value_3).unwrap()).unwrap();
        TempSharePair {
            dir,
            path_2,
            path_3,
        }
    }

    fn assert_load_error(pair: &TempSharePair, expected: &str) {
        let error = FrostSigner::from_files(&pair.path_2, &pair.path_3, true)
            .err()
            .expect("share pair must fail");
        assert!(
            format!("{error:#}").contains(expected),
            "unexpected error: {error:#}"
        );
    }

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

    #[test]
    fn validated_share_files_sign_and_verify() {
        let (value_2, value_3) = ceremony_values();
        let pair = write_pair(&value_2, &value_3);
        let signer =
            FrostSigner::from_files(&pair.path_2, &pair.path_3, true).expect("valid shares");
        let message = b"validated co-located FROST test";
        let signature = signer.sign_raw(message).expect("signature");
        signer.verify(message, &signature).expect("verification");
    }

    #[test]
    fn signing_mode_parser_rejects_aliases_and_unknown_values() {
        assert_eq!(
            SigningMode::from_str("single_key").unwrap(),
            SigningMode::SingleKey
        );
        assert_eq!(
            SigningMode::from_str("frost").unwrap(),
            SigningMode::FrostThreshold
        );
        assert!(SigningMode::from_str("threshold").is_err());
        assert!(SigningMode::from_str("FROST").is_err());
        assert!(SigningMode::from_str("unknown").is_err());
    }

    #[test]
    fn rejects_same_file_path() {
        let (value_2, value_3) = ceremony_values();
        let pair = write_pair(&value_2, &value_3);
        let error = FrostSigner::from_files(&pair.path_2, &pair.path_2, true)
            .err()
            .expect("same path must fail");
        assert!(format!("{error:#}").contains("two distinct files"));
    }

    #[test]
    fn rejects_hard_linked_share_files() {
        let (value_2, value_3) = ceremony_values();
        let pair = write_pair(&value_2, &value_3);
        std::fs::remove_file(&pair.path_3).unwrap();
        std::fs::hard_link(&pair.path_2, &pair.path_3).expect("create hard link");
        assert_load_error(&pair, "two distinct files");
    }

    #[test]
    fn rejects_loading_without_experimental_opt_in() {
        let (value_2, value_3) = ceremony_values();
        let pair = write_pair(&value_2, &value_3);
        let error = FrostSigner::from_files(&pair.path_2, &pair.path_3, false)
            .err()
            .expect("missing opt-in must fail");
        assert!(format!("{error:#}").contains("explicit EXPERIMENTAL_COLOCATED_FROST_ENABLED=true"));
    }

    #[test]
    fn rejects_non_2_of_3_parameters() {
        let (value_2, mut value_3) = ceremony_values();
        value_3["threshold"] = serde_json::json!(3);
        let pair = write_pair(&value_2, &value_3);
        assert_load_error(&pair, "wrong FROST threshold");

        let (value_2, mut value_3) = ceremony_values();
        value_3["max_signers"] = serde_json::json!(4);
        let pair = write_pair(&value_2, &value_3);
        assert_load_error(&pair, "wrong FROST max_signers");
    }

    #[test]
    fn rejects_duplicate_participant_identifiers() {
        let (value_2, _) = ceremony_values();
        let pair = write_pair(&value_2, &value_2);
        assert_load_error(&pair, "distinct participant identifiers");
    }

    #[test]
    fn rejects_different_ceremony_commitments() {
        let (value_2, _) = ceremony_values();
        let (_, other_value_3) = ceremony_values();
        let pair = write_pair(&value_2, &other_value_3);
        assert_load_error(&pair, "different VSS commitment vectors");
    }

    #[test]
    fn rejects_group_key_not_bound_to_commitment() {
        let (value_2, mut value_3) = ceremony_values();
        let (_, other_value_3) = ceremony_values();
        value_3["group_verifying_key"] = other_value_3["group_verifying_key"].clone();
        let pair = write_pair(&value_2, &value_3);
        assert_load_error(&pair, "does not match commitment[0]");
    }

    #[test]
    fn rejects_declared_verifying_share_mismatch() {
        let (value_2, mut value_3) = ceremony_values();
        value_3["verifying_share"] = value_2["verifying_share"].clone();
        let pair = write_pair(&value_2, &value_3);
        assert_load_error(&pair, "verifying_share is inconsistent");
    }

    #[test]
    fn rejects_signing_share_that_fails_vss() {
        let (value_2, mut value_3) = ceremony_values();
        value_3["signing_share"] = value_2["signing_share"].clone();
        let pair = write_pair(&value_2, &value_3);
        assert_load_error(&pair, "failed VSS validation");
    }
}
