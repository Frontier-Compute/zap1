/**
 * blake2b.js - Pure JS BLAKE2b-256 with personalization support
 * Compatible with Python hashlib.blake2b and Rust blake2b_simd
 * No WASM, no native modules, no dependencies.
 */

const MASK64 = (1n << 64n) - 1n;

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];

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
  for (let i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
  v[12] ^= t & MASK64;
  v[13] ^= (t >> 64n) & MASK64;
  if (last) v[14] ^= MASK64;

  const m = new Array(16);
  for (let i = 0; i < 16; i++) m[i] = readLE64(block, i * 8);

  function G(a, b, c, d, x, y) {
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
    G(0,4, 8,12, m[s[ 0]], m[s[ 1]]);
    G(1,5, 9,13, m[s[ 2]], m[s[ 3]]);
    G(2,6,10,14, m[s[ 4]], m[s[ 5]]);
    G(3,7,11,15, m[s[ 6]], m[s[ 7]]);
    G(0,5,10,15, m[s[ 8]], m[s[ 9]]);
    G(1,6,11,12, m[s[10]], m[s[11]]);
    G(2,7, 8,13, m[s[12]], m[s[13]]);
    G(3,4, 9,14, m[s[14]], m[s[15]]);
  }

  for (let i = 0; i < 8; i++) h[i] = h[i] ^ v[i] ^ v[i + 8];
}

/**
 * BLAKE2b-256 hash with optional 16-byte personalization.
 * @param {Uint8Array} input
 * @param {Uint8Array} [personalization] - 16 bytes
 * @returns {Uint8Array} 32-byte digest
 */
export function blake2b256(input, personalization) {
  const p = new Uint8Array(64);
  p[0] = 32; // digest length
  p[2] = 1;  // fanout
  p[3] = 1;  // max depth
  if (personalization) {
    for (let i = 0; i < 16; i++) p[48 + i] = personalization[i] || 0;
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

// Hex utilities

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error("hex must contain an even number of lowercase hexadecimal characters");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function assertHashHex(value, label = "hash") {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be exactly 64 lowercase hexadecimal characters`);
  }
  return value;
}

function hashToBytes(value, label) {
  return hexToBytes(assertHashHex(value, label));
}

export function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// ZAP1 BLAKE2b personalizations

// "NordicShield_\x00\x00\x00" (13 chars + 3 null = 16 bytes)
const LEAF_PERSONAL = new Uint8Array([
  0x4e,0x6f,0x72,0x64,0x69,0x63,0x53,0x68,
  0x69,0x65,0x6c,0x64,0x5f,0x00,0x00,0x00,
]);

// "NordicShield_MRK" (16 bytes)
const NODE_PERSONAL = new Uint8Array([
  0x4e,0x6f,0x72,0x64,0x69,0x63,0x53,0x68,
  0x69,0x65,0x6c,0x64,0x5f,0x4d,0x52,0x4b,
]);

// "NordicShield_RTK" (16 bytes)
const ROOT_PERSONAL = new Uint8Array([
  0x4e,0x6f,0x72,0x64,0x69,0x63,0x53,0x68,
  0x69,0x65,0x6c,0x64,0x5f,0x52,0x54,0x4b,
]);

const ENCODER = new TextEncoder();
export const COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2";
export const LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD";
export const LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133;
export const PROOF_BUNDLE_PROTOCOL = "ZAP1";
export const PROOF_BUNDLE_VERSION = "2";
export const DEFAULT_API_BASE = "https://api.frontiercompute.cash";

// Event-type prefix bytes (known types)
const EVENT_PREFIX = {
  PROGRAM_ENTRY: 0x01,
  OWNERSHIP_ATTEST: 0x02,
};

/**
 * Recompute a leaf hash from event data.
 * Returns null if the event type's hash formula is unknown.
 */
export function computeLeafHash(eventType, walletHash, serialNumber) {
  const prefix = EVENT_PREFIX[eventType];
  if (prefix === undefined) return null;

  if (eventType === "PROGRAM_ENTRY") {
    const walletBytes = ENCODER.encode(walletHash);
    const input = new Uint8Array(1 + walletBytes.length);
    input[0] = prefix;
    input.set(walletBytes, 1);
    return blake2b256(input, LEAF_PERSONAL);
  }

  if (eventType === "OWNERSHIP_ATTEST") {
    const walletBytes = ENCODER.encode(walletHash);
    const serialBytes = ENCODER.encode(serialNumber || "");
    const input = new Uint8Array(1 + 2 + walletBytes.length + 2 + serialBytes.length);
    let off = 0;
    input[off++] = prefix;
    input[off++] = (walletBytes.length >> 8) & 0xff;
    input[off++] = walletBytes.length & 0xff;
    input.set(walletBytes, off); off += walletBytes.length;
    input[off++] = (serialBytes.length >> 8) & 0xff;
    input[off++] = serialBytes.length & 0xff;
    input.set(serialBytes, off);
    return blake2b256(input, LEAF_PERSONAL);
  }

  return null;
}

/**
 * Hash two 32-byte children into a Merkle node.
 */
export function nodeHash(left, right) {
  if (!(left instanceof Uint8Array) || left.length !== 32 ||
      !(right instanceof Uint8Array) || right.length !== 32) {
    throw new Error("Merkle children must each be exactly 32 bytes");
  }
  const input = new Uint8Array(64);
  input.set(left, 0);
  input.set(right, 32);
  return blake2b256(input, NODE_PERSONAL);
}

export function commitRoot(leafCount, rawRoot) {
  const count = BigInt(leafCount);
  if (count <= 0n || count > 0xffffffffffffffffn) {
    throw new Error("leaf_count must be an unsigned 64-bit positive integer");
  }
  if (!(rawRoot instanceof Uint8Array) || rawRoot.length !== 32) {
    throw new Error("raw root must be exactly 32 bytes");
  }
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

/**
 * Walk a Merkle proof from leaf to root.
 * @param {string} leafHashHex
 * @param {Array<{hash: string, position: string}>} proof - sibling steps
 * @param {number} [leafCount]
 * @returns {{ computedRoot: string, legacyRoot: string, rootScheme: string, steps: Array<{left: string, right: string, result: string}> }}
 */
export function walkProof(leafHashHex, proof, leafCount) {
  let current = hashToBytes(leafHashHex, "leaf.hash");
  const steps = [];

  if (!Array.isArray(proof)) throw new Error("proof must be an array");

  for (let index = 0; index < proof.length; index++) {
    const step = proof[index];
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new Error(`proof[${index}] must be an object`);
    }
    const sibling = hashToBytes(step.hash, `proof[${index}].hash`);
    let left, right;
    if (step.position === "right") {
      left = current; right = sibling;
    } else if (step.position === "left") {
      left = sibling; right = current;
    } else {
      throw new Error(`proof[${index}].position must be exactly left or right`);
    }
    current = nodeHash(left, right);
    steps.push({
      left: bytesToHex(left),
      right: bytesToHex(right),
      result: bytesToHex(current),
    });
  }

  const legacyRoot = bytesToHex(current);
  if (leafCount === undefined || leafCount === null) {
    return {
      computedRoot: legacyRoot,
      legacyRoot,
      rootScheme: LEGACY_SCHEME,
      steps,
    };
  }

  if (!Number.isSafeInteger(leafCount) || leafCount <= 0) {
    throw new Error("root.leaf_count must be a positive safe integer");
  }

  return {
    computedRoot: bytesToHex(commitRoot(leafCount, current)),
    legacyRoot,
    rootScheme: COUNT_BOUND_SCHEME,
    steps,
  };
}

export function isHistoricalLegacyBundle(bundle) {
  const scheme = bundle?.root?.scheme;
  const height = bundle?.anchor?.height;
  return (
    scheme === LEGACY_SCHEME &&
    Number.isSafeInteger(height) &&
    height >= 0 &&
    height <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
  );
}

function validateAnchor(anchor) {
  if (!anchor || typeof anchor !== "object" || Array.isArray(anchor)) {
    throw new Error("anchor must be an object");
  }
  if (anchor.txid !== null) assertHashHex(anchor.txid, "anchor.txid");
  if (anchor.height !== null &&
      (!Number.isSafeInteger(anchor.height) || anchor.height < 0)) {
    throw new Error("anchor.height must be null or a nonnegative safe integer");
  }
}

export function verifyProofBundle(bundle, requestedHash) {
  assertHashHex(requestedHash, "requested leaf hash");
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    throw new Error("proof bundle must be an object");
  }
  if (bundle.protocol !== PROOF_BUNDLE_PROTOCOL) {
    throw new Error(`protocol must be exactly ${PROOF_BUNDLE_PROTOCOL}`);
  }
  if (bundle.version !== PROOF_BUNDLE_VERSION) {
    throw new Error(`proof bundle version must be exactly ${PROOF_BUNDLE_VERSION}`);
  }
  if (!bundle.leaf || typeof bundle.leaf !== "object" || Array.isArray(bundle.leaf)) {
    throw new Error("leaf must be an object");
  }
  assertHashHex(bundle.leaf.hash, "leaf.hash");
  if (bundle.leaf.hash !== requestedHash) {
    throw new Error("returned leaf hash does not match the requested leaf hash");
  }
  if (!bundle.root || typeof bundle.root !== "object" || Array.isArray(bundle.root)) {
    throw new Error("root must be an object");
  }
  assertHashHex(bundle.root.hash, "root.hash");
  if (!Number.isSafeInteger(bundle.root.leaf_count) || bundle.root.leaf_count <= 0) {
    throw new Error("root.leaf_count must be a positive safe integer");
  }
  if (bundle.root.scheme !== COUNT_BOUND_SCHEME && bundle.root.scheme !== LEGACY_SCHEME) {
    throw new Error("root.scheme is not a supported exact ZAP1 scheme");
  }
  validateAnchor(bundle.anchor);

  let leafRecomputed = false;
  let leafMatch = null;
  let recomputedHash = null;
  if (typeof bundle.leaf.wallet_hash === "string") {
    const computed = computeLeafHash(
      bundle.leaf.event_type,
      bundle.leaf.wallet_hash,
      bundle.leaf.serial_number
    );
    if (computed) {
      recomputedHash = bytesToHex(computed);
      leafMatch = recomputedHash === bundle.leaf.hash;
      leafRecomputed = true;
    }
  }

  const { computedRoot, legacyRoot, steps } = walkProof(
    bundle.leaf.hash,
    bundle.proof,
    bundle.root.leaf_count
  );
  const rootMatchV2 = computedRoot === bundle.root.hash;
  const rootMatchLegacy = legacyRoot === bundle.root.hash;
  const legacyAllowed = rootMatchLegacy && isHistoricalLegacyBundle(bundle);
  const rootMatch = bundle.root.scheme === COUNT_BOUND_SCHEME
    ? rootMatchV2
    : legacyAllowed;

  return {
    requestMatch: true,
    leafMatch,
    rootMatch,
    rootScheme: bundle.root.scheme,
    rootMatchV2,
    rootMatchLegacy,
    legacyAllowed,
    computedRoot,
    legacyRoot,
    steps,
    leafRecomputed,
    recomputedHash,
  };
}

export function proofBundleUrl(apiBase, requestedHash) {
  assertHashHex(requestedHash, "requested leaf hash");
  if (typeof apiBase !== "string" || !apiBase.trim()) {
    throw new Error("apiBase must be an explicit HTTP(S) origin or base path");
  }
  let base;
  try {
    base = new URL(apiBase);
  } catch {
    throw new Error("apiBase must be a valid absolute URL");
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") {
    throw new Error("apiBase must use HTTP or HTTPS");
  }
  if (base.username || base.password || base.search || base.hash) {
    throw new Error("apiBase must not contain credentials, a query, or a fragment");
  }
  const normalizedPath = base.pathname.replace(/\/+$/, "");
  base.pathname = `${normalizedPath}/verify/${requestedHash}/proof.json`;
  return base.toString();
}

export function fetchProofBundle(
  apiBase,
  requestedHash,
  fetchImpl = globalThis.fetch
) {
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is required");
  }
  return fetchImpl(proofBundleUrl(apiBase, requestedHash));
}
