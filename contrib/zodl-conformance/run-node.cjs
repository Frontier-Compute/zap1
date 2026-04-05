#!/usr/bin/env node
// ZAP1 Memo Conformance - Node.js runner
// Run: node run-node.cjs
//
// Loads test-vectors.json and runs each vector against
// inline ZAP1 parser logic.  Reports PASS/FAIL per vector.

"use strict";

const fs = require("fs");
const path = require("path");

// Inline parser - same regex and logic as Kotlin/Swift implementations.
// If the real parsers diverge from this, the test is stale.
const PATTERN = /^(ZAP1|NSM1):([0-9a-fA-F]{2}):([0-9a-fA-F]{64})$/;

const EVENTS = {
  "01": "PROGRAM_ENTRY",
  "02": "OWNERSHIP_ATTEST",
  "03": "CONTRACT_ANCHOR",
  "04": "DEPLOYMENT",
  "05": "HOSTING_PAYMENT",
  "06": "SHIELD_RENEWAL",
  "07": "TRANSFER",
  "08": "EXIT",
  "09": "MERKLE_ROOT",
  "0a": "STAKING_DEPOSIT",
  "0b": "STAKING_WITHDRAW",
  "0c": "STAKING_REWARD",
  "0d": "GOVERNANCE_PROPOSAL",
  "0e": "GOVERNANCE_VOTE",
  "0f": "GOVERNANCE_RESULT",
};

function parse(memo) {
  const cleaned = memo.trim().replace(/\0/g, "");
  const m = cleaned.match(PATTERN);
  if (!m) return null;

  const typeHex = m[2].toLowerCase();
  return {
    prefix: m[1],
    typeHex: typeHex,
    event: EVENTS[typeHex] || `TYPE_0x${typeHex}`,
    hash: m[3],
    get shortHash() {
      return this.hash.slice(0, 12) + "...";
    },
    get isLegacy() {
      return this.prefix === "NSM1";
    },
  };
}

// Load vectors
const candidates = [
  path.join(__dirname, "test-vectors.json"),
  path.join(process.cwd(), "test-vectors.json"),
  path.join(process.cwd(), "contrib/zodl-conformance/test-vectors.json"),
];

let vectorPath = null;
for (const p of candidates) {
  if (fs.existsSync(p)) {
    vectorPath = p;
    break;
  }
}

if (!vectorPath) {
  console.error("ERROR: test-vectors.json not found");
  console.error("Run from the zodl-conformance directory or the repo root");
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
const vectors = data.vectors;

let passed = 0;
let failed = 0;

console.log("ZAP1 Conformance - Node.js");
console.log(`Vectors: ${vectors.length}`);
console.log("");

for (const v of vectors) {
  const { id, input, expected_parse, description } = v;
  const result = parse(input);
  const errors = [];

  if (expected_parse) {
    if (!result) {
      errors.push("expected parse success, got null");
    } else {
      if (v.expected_prefix !== null && result.prefix !== v.expected_prefix) {
        errors.push(`prefix: got '${result.prefix}', want '${v.expected_prefix}'`);
      }
      if (v.expected_type_hex !== null && result.typeHex !== v.expected_type_hex) {
        errors.push(`typeHex: got '${result.typeHex}', want '${v.expected_type_hex}'`);
      }
      if (v.expected_event_name !== null && result.event !== v.expected_event_name) {
        errors.push(`event: got '${result.event}', want '${v.expected_event_name}'`);
      }
      if (v.expected_hash !== null && result.hash !== v.expected_hash) {
        errors.push(`hash: got '${result.hash}', want '${v.expected_hash}'`);
      }
      if (v.expected_short_hash !== null && result.shortHash !== v.expected_short_hash) {
        errors.push(`shortHash: got '${result.shortHash}', want '${v.expected_short_hash}'`);
      }
      if (v.expected_is_legacy !== null && result.isLegacy !== v.expected_is_legacy) {
        errors.push(`isLegacy: got '${result.isLegacy}', want '${v.expected_is_legacy}'`);
      }
    }
  } else {
    if (result !== null) {
      errors.push(`expected parse failure, got result: ${result.event}`);
    }
  }

  if (errors.length === 0) {
    console.log(`  PASS  ${id}`);
    passed++;
  } else {
    console.log(`  FAIL  ${id} - ${description}`);
    for (const e of errors) console.log(`        ${e}`);
    failed++;
  }
}

console.log("");
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);

if (failed > 0) {
  process.exit(1);
}
