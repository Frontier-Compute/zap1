//! Universal decoder for Zcash shielded memo formats.
//!
//! Feed it raw decrypted memo bytes from any Orchard or Sapling output
//! and get back a typed classification with parsed content where possible.
//!
//! Supports: plain UTF-8 text, ZIP 302 TVLV structured memos, ZAP1/NSM1
//! attestation events, arbitrary binary (0xFF), empty memos (0xF6), and
//! graceful handling of unknown formats.
//!
//! No external dependencies. No server calls. Wallet-importable.

mod tvlv;

pub use tvlv::{decode as decode_tvlv, encode as encode_tvlv, TvlvError, TvlvPart};

/// Decoded memo with identified format and parsed content.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoFormat {
    /// Plain UTF-8 text (first byte 0x00-0xF4, trailing zeros trimmed).
    Text(String),

    /// ZAP1 attestation event (Zcash Attestation Protocol v1).
    /// Fields: event type byte, 32-byte payload hash, raw memo string.
    Attestation {
        protocol: AttestationProtocol,
        event_type: u8,
        event_label: &'static str,
        payload_hash: [u8; 32],
        raw: String,
    },

    /// ZIP 302 structured memo (0xF7 prefix, TVLV-encoded parts).
    Zip302Tvlv { parts: Vec<TvlvPart> },

    /// Empty memo (0xF6 followed by zeros, or all zeros).
    Empty,

    /// Arbitrary binary data (0xFF prefix, rest is payload).
    Binary(Vec<u8>),

    /// Unrecognized format. Not an error - just a format we don't know.
    Unknown { first_byte: u8, length: usize },
}

/// Which attestation protocol produced the memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationProtocol {
    /// Current: ZAP1 (Zcash Attestation Protocol v1)
    Zap1,
    /// Legacy: NSM1 (Nordic Shield Memo v1, pre-rename)
    Nsm1Legacy,
}

/// Decode raw memo bytes into a classified format.
///
/// The input should be decrypted memo plaintext from an Orchard or Sapling
/// note (typically 512 bytes, or up to 16384 post-ZIP 231).
pub fn decode(bytes: &[u8]) -> MemoFormat {
    if bytes.is_empty() || all_zeros(bytes) {
        return MemoFormat::Empty;
    }

    match bytes[0] {
        0xF6 => {
            if all_zeros(&bytes[1..]) {
                MemoFormat::Empty
            } else {
                MemoFormat::Unknown {
                    first_byte: 0xF6,
                    length: bytes.len(),
                }
            }
        }

        0xF7 => match tvlv::decode(bytes) {
            Ok(parts) => MemoFormat::Zip302Tvlv { parts },
            Err(_) => MemoFormat::Unknown {
                first_byte: 0xF7,
                length: bytes.len(),
            },
        },

        0xFF => MemoFormat::Binary(bytes[1..].to_vec()),

        // reserved or legacy ranges
        0xF5 | 0xF8..=0xFE => MemoFormat::Unknown {
            first_byte: bytes[0],
            length: bytes.len(),
        },

        // UTF-8 text range (0x00-0xF4)
        _ => decode_text_range(bytes),
    }
}

/// Short human-readable label for the format.
pub fn label(fmt: &MemoFormat) -> &'static str {
    match fmt {
        MemoFormat::Text(_) => "text",
        MemoFormat::Attestation {
            protocol: AttestationProtocol::Zap1,
            ..
        } => "zap1",
        MemoFormat::Attestation {
            protocol: AttestationProtocol::Nsm1Legacy,
            ..
        } => "nsm1",
        MemoFormat::Zip302Tvlv { .. } => "zip302",
        MemoFormat::Empty => "empty",
        MemoFormat::Binary(_) => "binary",
        MemoFormat::Unknown { .. } => "unknown",
    }
}

fn all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn decode_text_range(bytes: &[u8]) -> MemoFormat {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);

    if end == 0 {
        return MemoFormat::Empty;
    }

    let text = match core::str::from_utf8(&bytes[..end]) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return MemoFormat::Unknown {
                first_byte: bytes[0],
                length: bytes.len(),
            }
        }
    };

    // check for attestation protocols
    if let Some(parsed) = try_parse_attestation(&text, "ZAP1:", AttestationProtocol::Zap1) {
        return parsed;
    }
    if let Some(parsed) = try_parse_attestation(&text, "NSM1:", AttestationProtocol::Nsm1Legacy) {
        return parsed;
    }

    MemoFormat::Text(text)
}

fn try_parse_attestation(
    text: &str,
    prefix: &str,
    protocol: AttestationProtocol,
) -> Option<MemoFormat> {
    if !text.starts_with(prefix) {
        return None;
    }

    let rest = &text[prefix.len()..];
    let mut parts = rest.split(':');

    let type_hex = parts.next()?;
    let event_type = u8::from_str_radix(type_hex, 16).ok()?;

    let payload_hex = parts.next()?;
    if payload_hex.len() != 64 {
        return None;
    }

    // extra fields = invalid
    if parts.next().is_some() {
        return None;
    }

    let payload_hash = hex_to_bytes32(payload_hex)?;
    let event_label = event_type_label(event_type);

    Some(MemoFormat::Attestation {
        protocol,
        event_type,
        event_label,
        payload_hash,
        raw: text.to_string(),
    })
}

fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn event_type_label(byte: u8) -> &'static str {
    match byte {
        0x01 => "PROGRAM_ENTRY",
        0x02 => "OWNERSHIP_ATTEST",
        0x03 => "CONTRACT_ANCHOR",
        0x04 => "DEPLOYMENT",
        0x05 => "HOSTING_PAYMENT",
        0x06 => "SHIELD_RENEWAL",
        0x07 => "TRANSFER",
        0x08 => "EXIT",
        0x09 => "MERKLE_ROOT",
        0x0A => "STAKING_DEPOSIT",
        0x0B => "STAKING_WITHDRAW",
        0x0C => "STAKING_REWARD",
        0x0D => "GOVERNANCE_PROPOSAL",
        0x0E => "GOVERNANCE_VOTE",
        0x0F => "GOVERNANCE_RESULT",
        0x40 => "AGENT_REGISTER",
        0x41 => "AGENT_POLICY",
        0x42 => "AGENT_ACTION",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes() {
        assert_eq!(decode(&[]), MemoFormat::Empty);
    }

    #[test]
    fn all_zeros_is_empty() {
        assert_eq!(decode(&[0u8; 512]), MemoFormat::Empty);
    }

    #[test]
    fn f6_marker_is_empty() {
        let mut bytes = [0u8; 512];
        bytes[0] = 0xF6;
        assert_eq!(decode(&bytes), MemoFormat::Empty);
    }

    #[test]
    fn plain_text() {
        let mut bytes = [0u8; 512];
        let msg = b"payment for march hosting";
        bytes[..msg.len()].copy_from_slice(msg);
        match decode(&bytes) {
            MemoFormat::Text(s) => assert_eq!(s, "payment for march hosting"),
            other => panic!("expected Text, got {}", label(&other)),
        }
    }

    #[test]
    fn zap1_attestation() {
        let hash_hex = "ab".repeat(32);
        let memo = format!("ZAP1:01:{hash_hex}");
        let mut bytes = [0u8; 512];
        bytes[..memo.len()].copy_from_slice(memo.as_bytes());
        match decode(&bytes) {
            MemoFormat::Attestation {
                protocol,
                event_type,
                event_label,
                ..
            } => {
                assert_eq!(protocol, AttestationProtocol::Zap1);
                assert_eq!(event_type, 0x01);
                assert_eq!(event_label, "PROGRAM_ENTRY");
            }
            other => panic!("expected Attestation, got {}", label(&other)),
        }
    }

    #[test]
    fn legacy_nsm1() {
        let hash_hex = "cd".repeat(32);
        let memo = format!("NSM1:02:{hash_hex}");
        let mut bytes = [0u8; 512];
        bytes[..memo.len()].copy_from_slice(memo.as_bytes());
        match decode(&bytes) {
            MemoFormat::Attestation {
                protocol,
                event_type,
                ..
            } => {
                assert_eq!(protocol, AttestationProtocol::Nsm1Legacy);
                assert_eq!(event_type, 0x02);
            }
            other => panic!("expected Attestation, got {}", label(&other)),
        }
    }

    #[test]
    fn binary_memo() {
        let bytes = [0xFF, 1, 2, 3, 4, 5];
        match decode(&bytes) {
            MemoFormat::Binary(data) => assert_eq!(data, vec![1, 2, 3, 4, 5]),
            other => panic!("expected Binary, got {}", label(&other)),
        }
    }

    #[test]
    fn zip302_tvlv() {
        let encoded = tvlv::encode(&[(160, 0, b"hello".as_slice())]);
        match decode(&encoded) {
            MemoFormat::Zip302Tvlv { parts } => {
                assert_eq!(parts.len(), 1);
                assert_eq!(parts[0].part_type, 160);
                assert_eq!(parts[0].value, b"hello");
            }
            other => panic!("expected Zip302Tvlv, got {}", label(&other)),
        }
    }

    #[test]
    fn unknown_format() {
        let bytes = [0xF5, 0, 0, 0];
        assert!(matches!(decode(&bytes), MemoFormat::Unknown { .. }));
    }

    #[test]
    fn reserved_range_is_unknown() {
        for byte in [0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE] {
            let bytes = [byte, 0, 0, 0];
            assert!(
                matches!(decode(&bytes), MemoFormat::Unknown { .. }),
                "0x{:02x} should be unknown",
                byte
            );
        }
    }

    #[test]
    fn invalid_utf8_is_unknown() {
        let bytes = [0x80, 0xFF, 0xFE, 0x00];
        assert!(matches!(decode(&bytes), MemoFormat::Unknown { .. }));
    }

    #[test]
    fn malformed_zap1_falls_back_to_text() {
        let memo = b"ZAP1:01:tooshort";
        let mut bytes = [0u8; 512];
        bytes[..memo.len()].copy_from_slice(memo);
        match decode(&bytes) {
            MemoFormat::Text(s) => assert!(s.starts_with("ZAP1:01:tooshort")),
            other => panic!("expected Text fallback, got {}", label(&other)),
        }
    }

    #[test]
    fn all_event_labels() {
        assert_eq!(event_type_label(0x01), "PROGRAM_ENTRY");
        assert_eq!(event_type_label(0x09), "MERKLE_ROOT");
        assert_eq!(event_type_label(0x0C), "STAKING_REWARD");
        assert_eq!(event_type_label(0x0D), "GOVERNANCE_PROPOSAL");
        assert_eq!(event_type_label(0x0E), "GOVERNANCE_VOTE");
        assert_eq!(event_type_label(0x0F), "GOVERNANCE_RESULT");
        assert_eq!(event_type_label(0x40), "AGENT_REGISTER");
        assert_eq!(event_type_label(0x41), "AGENT_POLICY");
        assert_eq!(event_type_label(0x42), "AGENT_ACTION");
        assert_eq!(event_type_label(0xFF), "UNKNOWN");
    }

    #[test]
    fn labels_are_correct() {
        assert_eq!(label(&MemoFormat::Empty), "empty");
        assert_eq!(label(&MemoFormat::Text("x".into())), "text");
        assert_eq!(label(&MemoFormat::Binary(vec![])), "binary");
        assert_eq!(
            label(&MemoFormat::Unknown {
                first_byte: 0,
                length: 0
            }),
            "unknown"
        );
    }
}
