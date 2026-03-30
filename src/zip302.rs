// ZIP 302 TVLV (Type-Version-Length-Value) structured memo encoder/decoder.
// Implements the container format from str4d's ZIP 302 PR #638.

const TVLV_MARKER: u8 = 0xF7;
const MAX_MEMO_PRE231: usize = 512;
const MAX_MEMO_POST231: usize = 16384;

#[derive(Debug, Clone, PartialEq)]
pub struct TvlvPart {
    pub part_type: u16,
    pub version: u8,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub enum TvlvError {
    NotTvlv,
    Truncated,
    InvalidCompactSize,
    DuplicatePartType(u16),
    NonZeroPadding,
    MemoTooLarge,
}

impl std::fmt::Display for TvlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TvlvError::NotTvlv => write!(f, "missing 0xF7 marker"),
            TvlvError::Truncated => write!(f, "unexpected end of data"),
            TvlvError::InvalidCompactSize => write!(f, "invalid compactSize"),
            TvlvError::DuplicatePartType(t) => write!(f, "duplicate part type {}", t),
            TvlvError::NonZeroPadding => write!(f, "non-zero byte in padding"),
            TvlvError::MemoTooLarge => write!(f, "memo exceeds max size"),
        }
    }
}

impl std::error::Error for TvlvError {}

pub type Result<T> = std::result::Result<T, TvlvError>;

fn encode_compact_size(n: u64) -> Vec<u8> {
    if n <= 252 {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut buf = vec![0xFD];
        buf.extend_from_slice(&(n as u16).to_le_bytes());
        buf
    } else if n <= 0xFFFF_FFFF {
        let mut buf = vec![0xFE];
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xFF];
        buf.extend_from_slice(&n.to_le_bytes());
        buf
    }
}

fn decode_compact_size(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err(TvlvError::Truncated);
    }
    match data[0] {
        0..=252 => Ok((data[0] as u64, 1)),
        0xFD => {
            if data.len() < 3 {
                return Err(TvlvError::Truncated);
            }
            let v = u16::from_le_bytes([data[1], data[2]]) as u64;
            if v < 253 {
                return Err(TvlvError::InvalidCompactSize);
            }
            Ok((v, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(TvlvError::Truncated);
            }
            let v = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
            if v < 0x10000 {
                return Err(TvlvError::InvalidCompactSize);
            }
            Ok((v, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(TvlvError::Truncated);
            }
            let v = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            if v < 0x1_0000_0000 {
                return Err(TvlvError::InvalidCompactSize);
            }
            Ok((v, 9))
        }
    }
}

/// Encode parts as (type, version, value) into a TVLV memo.
/// Appends end marker and zero-pads to 512 bytes.
pub fn encode_tvlv(parts: &[(u16, u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![TVLV_MARKER];
    for &(ptype, ver, val) in parts {
        out.extend(encode_compact_size(ptype as u64));
        out.extend(encode_compact_size(ver as u64));
        out.extend(encode_compact_size(val.len() as u64));
        out.extend_from_slice(val);
    }
    // End marker: partType 0
    out.push(0x00);
    // Pad to 512 bytes if under
    if out.len() < MAX_MEMO_PRE231 {
        out.resize(MAX_MEMO_PRE231, 0x00);
    }
    out
}

/// Decode a TVLV memo into parts. Validates marker, dedup, and padding.
pub fn decode_tvlv(data: &[u8]) -> Result<Vec<TvlvPart>> {
    if data.is_empty() || data[0] != TVLV_MARKER {
        return Err(TvlvError::NotTvlv);
    }
    if data.len() > MAX_MEMO_POST231 {
        return Err(TvlvError::MemoTooLarge);
    }

    let mut pos = 1;
    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    loop {
        if pos >= data.len() {
            return Err(TvlvError::Truncated);
        }

        let (ptype, sz) = decode_compact_size(&data[pos..])?;
        pos += sz;

        // End marker
        if ptype == 0 {
            // Rest must be zero padding
            for &b in &data[pos..] {
                if b != 0x00 {
                    return Err(TvlvError::NonZeroPadding);
                }
            }
            return Ok(parts);
        }

        let ptype = ptype as u16;
        if !seen.insert(ptype) {
            return Err(TvlvError::DuplicatePartType(ptype));
        }

        let (ver, sz) = decode_compact_size(&data[pos..])?;
        pos += sz;

        let (len, sz) = decode_compact_size(&data[pos..])?;
        pos += sz;

        let len = len as usize;
        if pos + len > data.len() {
            return Err(TvlvError::Truncated);
        }

        parts.push(TvlvPart {
            part_type: ptype,
            version: ver as u8,
            value: data[pos..pos + len].to_vec(),
        });
        pos += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_roundtrip() {
        for n in [0u64, 1, 252, 253, 1000, 65535, 65536, 100_000] {
            let enc = encode_compact_size(n);
            let (dec, sz) = decode_compact_size(&enc).unwrap();
            assert_eq!(dec, n);
            assert_eq!(sz, enc.len());
        }
    }

    #[test]
    fn encode_decode_empty() {
        let memo = encode_tvlv(&[]);
        assert_eq!(memo.len(), 512);
        assert_eq!(memo[0], 0xF7);
        assert_eq!(memo[1], 0x00); // end marker
        let parts = decode_tvlv(&memo).unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn text_part_roundtrip() {
        let text = b"Hello Zcash";
        let memo = encode_tvlv(&[(160, 0, text)]);
        assert_eq!(memo.len(), 512);

        let parts = decode_tvlv(&memo).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_type, 160);
        assert_eq!(parts[0].version, 0);
        assert_eq!(parts[0].value, text);
    }

    #[test]
    fn binary_part_roundtrip() {
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let memo = encode_tvlv(&[(255, 0, &blob)]);
        let parts = decode_tvlv(&memo).unwrap();
        assert_eq!(parts[0].part_type, 255);
        assert_eq!(parts[0].value, blob);
    }

    #[test]
    fn zap1_experimental_type() {
        // ZAP1 attestation in experimental range (65530)
        let attest = b"node:zap1;slot:42;sig:abc123";
        let memo = encode_tvlv(&[(65530, 1, attest)]);
        let parts = decode_tvlv(&memo).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_type, 65530);
        assert_eq!(parts[0].version, 1);
        assert_eq!(parts[0].value, attest);
    }

    #[test]
    fn multi_part_roundtrip() {
        let text = b"payment for stuff";
        let blob = b"\x01\x02\x03";
        let memo = encode_tvlv(&[(160, 0, &text[..]), (255, 0, &blob[..])]);
        let parts = decode_tvlv(&memo).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_type, 160);
        assert_eq!(parts[1].part_type, 255);
    }

    #[test]
    fn padding_all_zeros() {
        let memo = encode_tvlv(&[(160, 0, b"x")]);
        // Everything after the end marker must be 0x00
        let marker_pos = 1 + 1 + 1 + 1 + 1; // marker + type(160=1byte) + ver(0) + len(1) + 'x'
        let end_pos = marker_pos; // end marker byte
        assert_eq!(memo[end_pos], 0x00);
        for &b in &memo[end_pos + 1..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn reject_no_marker() {
        let bad = vec![0x00; 512];
        assert!(matches!(decode_tvlv(&bad), Err(TvlvError::NotTvlv)));
    }

    #[test]
    fn reject_duplicate_type() {
        // Manually build a memo with duplicate type 160
        let mut raw = vec![0xF7];
        raw.push(160);
        raw.push(0);
        raw.push(1);
        raw.push(b'a');
        raw.push(160);
        raw.push(0);
        raw.push(1);
        raw.push(b'b');
        raw.push(0x00);
        raw.resize(512, 0x00);
        assert!(matches!(
            decode_tvlv(&raw),
            Err(TvlvError::DuplicatePartType(160))
        ));
    }

    #[test]
    fn reject_nonzero_padding() {
        let mut memo = encode_tvlv(&[]);
        memo[511] = 0x01;
        assert!(matches!(decode_tvlv(&memo), Err(TvlvError::NonZeroPadding)));
    }
}
