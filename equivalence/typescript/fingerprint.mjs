#!/usr/bin/env node
/*
 * ZAP1 verifier cross-implementation fingerprint (TypeScript-family side).
 *
 * Runs under plain Node.js with no npm install. It independently recomputes the
 * ZAP1 proof verdict and the canonical fingerprint encoding for each case in
 * equivalence/corpus.json, then prints "<id> <sha256_hex>" sorted by id.
 *
 * This is intentionally standalone instead of importing the Python or Rust
 * verifier. A match shows Python, Rust, and this JavaScript/TypeScript runtime
 * agree on the frozen corpus. It is consistency evidence, not a proof of
 * protocol correctness; see equivalence/README.md.
 */

import crypto from "node:crypto";
import fs from "node:fs";

const DOMAIN = "zap1-verifier-equiv-v1";
const COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2";
const LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD";
const LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133;

const MASK64 = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const NODE_PERSONAL = Uint8Array.from([
  0x4e, 0x6f, 0x72, 0x64, 0x69, 0x63, 0x53, 0x68,
  0x69, 0x65, 0x6c, 0x64, 0x5f, 0x4d, 0x52, 0x4b,
]);
const ROOT_PERSONAL = Uint8Array.from([
  0x4e, 0x6f, 0x72, 0x64, 0x69, 0x63, 0x53, 0x68,
  0x69, 0x65, 0x6c, 0x64, 0x5f, 0x52, 0x54, 0x4b,
]);

function rotr64(x, n) {
  const bn = BigInt(n);
  return ((x >> bn) | (x << (64n - bn))) & MASK64;
}

function readLE64(buf, off) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(buf[off + i]) << BigInt(8 * i);
  return v;
}

function writeLE64(buf, off, val) {
  for (let i = 0; i < 8; i++) buf[off + i] = Number((val >> BigInt(8 * i)) & 0xffn);
}

function compress(h, block, t, last) {
  const v = new Array(16);
  for (let i = 0; i < 8; i++) {
    v[i] = h[i];
    v[i + 8] = IV[i];
  }
  v[12] ^= t & MASK64;
  v[13] ^= (t >> 64n) & MASK64;
  if (last) v[14] ^= MASK64;

  const m = new Array(16);
  for (let i = 0; i < 16; i++) m[i] = readLE64(block, i * 8);

  function g(a, b, c, d, x, y) {
    v[a] = (v[a] + v[b] + x) & MASK64;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = (v[a] + v[b] + y) & MASK64;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = rotr64(v[b] ^ v[c], 63);
  }

  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10];
    g(0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (let i = 0; i < 8; i++) h[i] = h[i] ^ v[i] ^ v[i + 8];
}

function blake2b256(input, personalization) {
  const p = new Uint8Array(64);
  p[0] = 32;
  p[2] = 1;
  p[3] = 1;
  if (personalization) {
    if (personalization.length !== 16) throw new Error("BLAKE2b personalization must be 16 bytes");
    p.set(personalization, 48);
  }

  const h = new Array(8);
  for (let i = 0; i < 8; i++) h[i] = IV[i] ^ readLE64(p, i * 8);

  let t = 0n;
  let off = 0;
  if (input.length === 0) {
    compress(h, new Uint8Array(128), 0n, true);
  } else {
    while (off + 128 < input.length) {
      t += 128n;
      compress(h, input.subarray(off, off + 128), t, false);
      off += 128;
    }
    const last = new Uint8Array(128);
    last.set(input.subarray(off));
    t += BigInt(input.length - off);
    compress(h, last, t, true);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) writeLE64(out, i * 8, h[i]);
  return out;
}

function hexToBytes(hex, label) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${label} must be even-length hex`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function nodeHash(left, right) {
  if (left.length !== 32 || right.length !== 32) throw new Error("node children must be 32 bytes");
  const input = new Uint8Array(64);
  input.set(left, 0);
  input.set(right, 32);
  return blake2b256(input, NODE_PERSONAL);
}

function commitRoot(leafCount, rawRoot) {
  const count = BigInt(leafCount);
  if (count <= 0n) throw new Error("leaf_count must be positive");
  if (count > 0xffffffffffffffffn) throw new Error("leaf_count exceeds u64");
  const input = new Uint8Array(41);
  input[0] = 1;
  let tmp = count;
  for (let i = 8; i >= 1; i--) {
    input[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  input.set(rawRoot, 9);
  return blake2b256(input, ROOT_PERSONAL);
}

function walkRaw(leaf, proof) {
  let current = leaf;
  for (const step of proof) {
    const sibling = hexToBytes(step.hash, "proof step hash");
    if (sibling.length !== 32) throw new Error("proof step hash must be 32 bytes");
    if (step.position === "right") {
      current = nodeHash(current, sibling);
    } else if (step.position === "left") {
      current = nodeHash(sibling, current);
    } else {
      throw new Error(`bad proof position: ${step.position}`);
    }
  }
  return current;
}

function legacyAllowed(scheme, anchorHeight, allowHistoricalLegacy) {
  return (
    (allowHistoricalLegacy || scheme === LEGACY_SCHEME) &&
    anchorHeight !== null &&
    anchorHeight !== undefined &&
    Number(anchorHeight) <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
  );
}

function verifyCase(caseData) {
  const leaf = hexToBytes(caseData.leaf_hash, "leaf_hash");
  const expected = hexToBytes(caseData.expected_root, "expected_root");
  if (leaf.length !== 32) throw new Error(`${caseData.id}: leaf_hash must be 32 bytes`);
  if (expected.length !== 32) throw new Error(`${caseData.id}: expected_root must be 32 bytes`);

  const rawRoot = walkRaw(leaf, caseData.proof);
  const countBoundRoot = commitRoot(caseData.leaf_count, rawRoot);

  if (equalBytes(countBoundRoot, expected)) {
    return { valid: true, resultScheme: COUNT_BOUND_SCHEME, countBoundRoot, rawRoot };
  }
  if (
    equalBytes(rawRoot, expected) &&
    legacyAllowed(caseData.scheme, caseData.anchor_height, Boolean(caseData.allow_historical_legacy))
  ) {
    return { valid: true, resultScheme: LEGACY_SCHEME, countBoundRoot, rawRoot };
  }
  return { valid: false, resultScheme: "INVALID", countBoundRoot, rawRoot };
}

function u32(n) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n);
  return out;
}

function u64(n) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n));
  return out;
}

function lp(s) {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([u32(b.length), b]);
}

function encodeCase(caseData, result) {
  const chunks = [
    Buffer.from(DOMAIN, "ascii"),
    lp(caseData.id),
    Buffer.from(hexToBytes(caseData.leaf_hash, "leaf_hash")),
    u64(caseData.leaf_count),
    u64(caseData.proof.length),
  ];

  for (const step of caseData.proof) {
    chunks.push(Buffer.from([step.position === "right" ? 1 : 0]));
    chunks.push(Buffer.from(hexToBytes(step.hash, "proof step hash")));
  }

  chunks.push(Buffer.from(hexToBytes(caseData.expected_root, "expected_root")));
  if (caseData.scheme === null || caseData.scheme === undefined) {
    chunks.push(Buffer.from([0]));
  } else {
    chunks.push(Buffer.from([1]));
    chunks.push(lp(caseData.scheme));
  }

  if (caseData.anchor_height === null || caseData.anchor_height === undefined) {
    chunks.push(Buffer.from([0]));
  } else {
    chunks.push(Buffer.from([1]));
    chunks.push(u64(caseData.anchor_height));
  }

  chunks.push(Buffer.from([caseData.allow_historical_legacy ? 1 : 0]));
  chunks.push(Buffer.from([result.valid ? 1 : 0]));
  chunks.push(lp(result.resultScheme));
  chunks.push(Buffer.from(result.countBoundRoot));
  chunks.push(Buffer.from(result.rawRoot));
  return Buffer.concat(chunks);
}

function fingerprintCase(caseData) {
  const result = verifyCase(caseData);
  return crypto.createHash("sha256").update(encodeCase(caseData, result)).digest("hex");
}

function main() {
  const corpusPath = process.argv[2] || "equivalence/corpus.json";
  const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  const lines = corpus.cases.map((caseData) => `${caseData.id} ${fingerprintCase(caseData)}`);
  lines.sort();
  for (const line of lines) console.log(line);
}

main();
