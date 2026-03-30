//! Universal Zcash memo decoder.
//!
//! Identifies and parses any shielded memo format: plain text, ZAP1 attestation,
//! ZIP 302 structured envelope, coin voting ballot, or raw binary.
//!
//! This module is wallet-importable. No server dependency. Works with any
//! decrypted memo bytes from Orchard or Sapling outputs.

use crate::memo::{MemoType, StructuredMemo};
use crate::zip302::TvlvPart;

/// Decoded memo with identified format.
#[derive(Debug)]
pub enum DecodedMemo {
    /// Plain UTF-8 text (first byte 0x00-0xF4)
    Text(String),

    /// ZAP1 attestation event
    Zap1 {
        event_type: MemoType,
        payload_hash: [u8; 32],
        raw: String,
    },

    /// Legacy NSM1 attestation event (pre-rename)
    LegacyNsm1 {
        event_type: MemoType,
        payload_hash: [u8; 32],
        raw: String,
    },

    /// ZIP 302 structured memo (0xF7 prefix, TVLV parts)
    Zip302 { parts: Vec<TvlvPart> },

    /// Empty memo (0xF6 followed by zeros)
    Empty,

    /// Arbitrary binary data (0xFF prefix)
    Binary(Vec<u8>),

    /// Unrecognized format
    Unknown { first_byte: u8, length: usize },
}

/// Decode a raw memo byte slice into a structured representation.
///
/// Handles all known Zcash memo formats:
/// - 0x00..0xF4: UTF-8 text (trim trailing zeros)
/// - 0xF5: legacy binary (treated as unknown)
/// - 0xF6: empty memo
/// - 0xF7: ZIP 302 TVLV structured memo
/// - 0xFF: arbitrary binary data
/// - ZAP1:/NSM1: text-encoded attestation (within UTF-8 range)
pub fn decode_memo(bytes: &[u8]) -> DecodedMemo {
    if bytes.is_empty() {
        return DecodedMemo::Empty;
    }

    match bytes[0] {
        // empty memo marker
        0xF6 => DecodedMemo::Empty,

        // ZIP 302 structured memo
        0xF7 => match crate::zip302::decode_tvlv(bytes) {
            Ok(parts) => DecodedMemo::Zip302 { parts },
            Err(_) => DecodedMemo::Unknown {
                first_byte: 0xF7,
                length: bytes.len(),
            },
        },

        // arbitrary binary
        0xFF => DecodedMemo::Binary(bytes[1..].to_vec()),

        // legacy binary agreement (0xF5) or reserved (0xF8-0xFE)
        0xF5 | 0xF8..=0xFE => DecodedMemo::Unknown {
            first_byte: bytes[0],
            length: bytes.len(),
        },

        // UTF-8 text range (0x00-0xF4)
        _ => {
            // trim trailing zeros
            let end = bytes
                .iter()
                .rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            let text = match std::str::from_utf8(&bytes[..end]) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    return DecodedMemo::Unknown {
                        first_byte: bytes[0],
                        length: bytes.len(),
                    }
                }
            };

            // check for ZAP1/NSM1 attestation format
            if text.starts_with("ZAP1:") {
                match StructuredMemo::decode(&text) {
                    Ok(memo) => DecodedMemo::Zap1 {
                        event_type: memo.memo_type,
                        payload_hash: memo.payload,
                        raw: text,
                    },
                    Err(_) => DecodedMemo::Text(text),
                }
            } else if text.starts_with("NSM1:") {
                match StructuredMemo::decode(&text) {
                    Ok(memo) => DecodedMemo::LegacyNsm1 {
                        event_type: memo.memo_type,
                        payload_hash: memo.payload,
                        raw: text,
                    },
                    Err(_) => DecodedMemo::Text(text),
                }
            } else {
                DecodedMemo::Text(text)
            }
        }
    }
}

/// Human-readable label for the decoded memo format.
pub fn format_label(memo: &DecodedMemo) -> &'static str {
    match memo {
        DecodedMemo::Text(_) => "text",
        DecodedMemo::Zap1 { .. } => "zap1",
        DecodedMemo::LegacyNsm1 { .. } => "nsm1-legacy",
        DecodedMemo::Zip302 { .. } => "zip302",
        DecodedMemo::Empty => "empty",
        DecodedMemo::Binary(_) => "binary",
        DecodedMemo::Unknown { .. } => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_memo() {
        let bytes = [0xF6, 0, 0, 0];
        assert!(matches!(decode_memo(&bytes), DecodedMemo::Empty));
    }

    #[test]
    fn decode_empty_bytes() {
        assert!(matches!(decode_memo(&[]), DecodedMemo::Empty));
    }

    #[test]
    fn decode_plain_text() {
        let mut bytes = [0u8; 512];
        let msg = b"hello zcash";
        bytes[..msg.len()].copy_from_slice(msg);
        match decode_memo(&bytes) {
            DecodedMemo::Text(s) => assert_eq!(s, "hello zcash"),
            other => panic!("expected Text, got {:?}", format_label(&other)),
        }
    }

    #[test]
    fn decode_zap1_attestation() {
        let payload_hex = "aa".repeat(32);
        let memo_str = format!("ZAP1:01:{payload_hex}");
        let mut bytes = [0u8; 512];
        bytes[..memo_str.len()].copy_from_slice(memo_str.as_bytes());
        match decode_memo(&bytes) {
            DecodedMemo::Zap1 { event_type, .. } => {
                assert_eq!(event_type, MemoType::ProgramEntry);
            }
            other => panic!("expected Zap1, got {:?}", format_label(&other)),
        }
    }

    #[test]
    fn decode_legacy_nsm1() {
        let payload_hex = "bb".repeat(32);
        let memo_str = format!("NSM1:02:{payload_hex}");
        let mut bytes = [0u8; 512];
        bytes[..memo_str.len()].copy_from_slice(memo_str.as_bytes());
        match decode_memo(&bytes) {
            DecodedMemo::LegacyNsm1 { event_type, .. } => {
                assert_eq!(event_type, MemoType::OwnershipAttest);
            }
            other => panic!("expected LegacyNsm1, got {:?}", format_label(&other)),
        }
    }

    #[test]
    fn decode_binary_memo() {
        let mut bytes = vec![0xFF];
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        match decode_memo(&bytes) {
            DecodedMemo::Binary(data) => assert_eq!(data, vec![1, 2, 3, 4]),
            other => panic!("expected Binary, got {:?}", format_label(&other)),
        }
    }

    #[test]
    fn decode_zip302_memo() {
        // use the encoder to produce valid TVLV, then decode through memo_decode
        let parts = vec![(160u16, 0u8, b"hi".as_slice())];
        let encoded = crate::zip302::encode_tvlv(&parts);
        match decode_memo(&encoded) {
            DecodedMemo::Zip302 { parts } => {
                assert_eq!(parts.len(), 1);
                assert_eq!(parts[0].part_type, 160);
                assert_eq!(parts[0].value, b"hi");
            }
            other => panic!("expected Zip302, got {:?}", format_label(&other)),
        }
    }

    #[test]
    fn decode_unknown_format() {
        let bytes = [0xF5, 0, 0, 0];
        assert!(matches!(decode_memo(&bytes), DecodedMemo::Unknown { .. }));
    }

    #[test]
    fn format_labels_correct() {
        assert_eq!(format_label(&DecodedMemo::Empty), "empty");
        assert_eq!(format_label(&DecodedMemo::Text("x".into())), "text");
        assert_eq!(format_label(&DecodedMemo::Binary(vec![])), "binary");
    }
}
