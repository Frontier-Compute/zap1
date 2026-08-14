import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { TextEncoder } from "node:util";
import {
  COUNT_BOUND_SCHEME,
  DEFAULT_API_BASE,
  LEGACY_ROOT_MAX_ANCHOR_HEIGHT,
  LEGACY_SCHEME,
  bytesToHex,
  commitRoot,
  fetchProofBundle,
  hexToBytes,
  proofBundleUrl,
  verifyProofBundle,
  walkProof,
} from "./blake2b.js";

const LEAF = "11".repeat(32);
const OTHER_LEAF = "22".repeat(32);
const COUNT_ROOT = bytesToHex(commitRoot(1, hexToBytes(LEAF)));
const EXPECTED_CORPUS_ACCEPTS = new Map([
  ["v2_valid_program_entry", true],
  ["v2_valid_ownership_attest", true],
  ["v2_valid_multilevel_4leaf", true],
  ["v2_valid_single_leaf", true],
  ["legacy_gated_valid", true],
  ["neg_wrong_root", false],
  ["neg_fake_scheme", false],
  ["neg_wrong_leaf_count", false],
  ["neg_legacy_ungated_downgrade", false],
  ["neg_legacy_height_too_high", false],
  ["neg_tampered_sibling", false],
]);

function countBundle() {
  return {
    protocol: "ZAP1",
    version: "2",
    leaf: { hash: LEAF, event_type: "PROGRAM_ENTRY" },
    proof: [],
    root: {
      hash: COUNT_ROOT,
      leaf_count: 1,
      scheme: COUNT_BOUND_SCHEME,
    },
    anchor: { txid: null, height: null },
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function corpusBundle(caseData) {
  return {
    protocol: "ZAP1",
    version: "2",
    leaf: { hash: caseData.leaf_hash, event_type: "CORPUS_CASE" },
    proof: caseData.proof,
    root: {
      hash: caseData.expected_root,
      leaf_count: caseData.leaf_count,
      scheme: caseData.scheme ?? COUNT_BOUND_SCHEME,
    },
    anchor: { txid: null, height: caseData.anchor_height },
  };
}

function coreOutcome(bundle, requestedHash) {
  try {
    const result = verifyProofBundle(bundle, requestedHash);
    return {
      accepted: result.requestMatch === true && result.rootMatch === true &&
        result.leafMatch !== false,
      result: {
        requestMatch: result.requestMatch,
        rootMatch: result.rootMatch,
        rootMatchV2: result.rootMatchV2,
        rootMatchLegacy: result.rootMatchLegacy,
        legacyAllowed: result.legacyAllowed,
        computedRoot: result.computedRoot,
        legacyRoot: result.legacyRoot,
        rootScheme: result.rootScheme,
      },
    };
  } catch (error) {
    return { accepted: false, error: error.message };
  }
}

function mustReject(label, mutate, pattern) {
  const bundle = countBundle();
  mutate(bundle);
  assert.throws(() => verifyProofBundle(bundle, LEAF), pattern, label);
}

const valid = verifyProofBundle(countBundle(), LEAF);
assert.equal(valid.requestMatch, true);
assert.equal(valid.rootMatch, true);
assert.equal(valid.rootScheme, COUNT_BOUND_SCHEME);

assert.throws(
  () => verifyProofBundle(countBundle(), OTHER_LEAF),
  /returned leaf hash does not match/,
  "a response for another leaf must not satisfy the request"
);
mustReject("protocol is exact", (b) => { b.protocol = "zap1"; }, /protocol must be exactly/);
mustReject("version is exact", (b) => { b.version = 2; }, /version must be exactly/);
mustReject("leaf hash length is exact", (b) => { b.leaf.hash = "11"; }, /leaf.hash must be exactly/);
mustReject("leaf hash alphabet is exact", (b) => { b.leaf.hash = "g".repeat(64); }, /leaf.hash must be exactly/);
mustReject("root hash is exact", (b) => { b.root.hash = "AA".repeat(32); }, /root.hash must be exactly/);
mustReject("scheme is exact", (b) => { b.root.scheme = "ZAP1_COUNT_BOUND"; }, /root.scheme/);
mustReject("leaf count is an integer", (b) => { b.root.leaf_count = "1"; }, /leaf_count/);
mustReject("proof is an array", (b) => { b.proof = {}; }, /proof must be an array/);
mustReject("sibling hash is exact", (b) => {
  b.proof = [{ hash: "00", position: "left" }];
}, /proof\[0\]\.hash must be exactly/);
mustReject("position is exact", (b) => {
  b.proof = [{ hash: OTHER_LEAF, position: "LEFT" }];
}, /position must be exactly left or right/);
mustReject("anchor txid is exact", (b) => { b.anchor.txid = "tx"; }, /anchor.txid must be exactly/);
mustReject("anchor height is an integer", (b) => { b.anchor.height = "10"; }, /anchor.height/);

const countLabelOnRawRoot = countBundle();
countLabelOnRawRoot.root.hash = LEAF;
assert.equal(
  verifyProofBundle(countLabelOnRawRoot, LEAF).rootMatch,
  false,
  "count-bound scheme must not fall back to a matching legacy raw root"
);

const legacy = countBundle();
legacy.root.hash = LEAF;
legacy.root.scheme = LEGACY_SCHEME;
legacy.anchor.height = LEGACY_ROOT_MAX_ANCHOR_HEIGHT;
assert.equal(verifyProofBundle(legacy, LEAF).rootMatch, true);
legacy.anchor.height = LEGACY_ROOT_MAX_ANCHOR_HEIGHT + 1;
assert.equal(
  verifyProofBundle(legacy, LEAF).rootMatch,
  false,
  "legacy raw roots must fail after the historical cutoff"
);

assert.throws(() => hexToBytes("0"), /even number/);
assert.throws(() => hexToBytes("GG"), /lowercase hexadecimal/);
assert.throws(
  () => walkProof(LEAF, [{ hash: OTHER_LEAF, position: "sideways" }], 2),
  /position must be exactly left or right/
);

const selfHosted = proofBundleUrl("https://self.example/zap/", LEAF);
assert.equal(selfHosted, `https://self.example/zap/verify/${LEAF}/proof.json`);
assert.equal(selfHosted.includes("api.frontiercompute.cash"), false);
assert.equal(
  proofBundleUrl(DEFAULT_API_BASE, LEAF),
  `https://api.frontiercompute.cash/verify/${LEAF}/proof.json`
);
assert.throws(() => proofBundleUrl("javascript:alert(1)", LEAF), /HTTP or HTTPS/);
assert.throws(() => proofBundleUrl("https://self.example/?target=other", LEAF), /query/);
let requestedEndpoint = null;
const responseMarker = {};
const response = await fetchProofBundle(
  "https://self.example/zap/",
  LEAF,
  async (endpoint) => {
    requestedEndpoint = endpoint;
    return responseMarker;
  }
);
assert.equal(response, responseMarker);
assert.equal(requestedEndpoint, selfHosted);
assert.equal(requestedEndpoint.includes("api.frontiercompute.cash"), false);

const standaloneSource = fs.readFileSync(
  new URL("./verify-standalone.html", import.meta.url),
  "utf8"
);
assert.doesNotMatch(standaloneSource, /[^\x00-\x7f]/, "standalone UI must remain ASCII");
assert.match(
  standaloneSource,
  /const API = "https:\/\/api\.frontiercompute\.cash";/,
  "standalone endpoint must be explicit"
);
const scriptMatch = standaloneSource.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "standalone script must be extractable");

const elements = new Map();
function makeElement() {
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    style: {},
    classList: { add() {}, remove() {} },
    addEventListener() {},
    click() {},
  };
}
let standaloneFetchCalls = 0;
const context = vm.createContext({
  console: { log() {}, error() {} },
  TextEncoder,
  document: {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, makeElement());
      return elements.get(id);
    },
    createElement() {
      return makeElement();
    },
  },
  navigator: { clipboard: { writeText() {} } },
  setTimeout() {},
  fetch() {
    standaloneFetchCalls++;
    throw new Error("standalone regression test forbids network access");
  },
});
vm.runInContext(scriptMatch[1], context, { filename: "verify-standalone.html" });
elements.get("leafInput").value = "not-a-hash";
await vm.runInContext("doVerify()", context);
assert.equal(
  standaloneFetchCalls,
  0,
  "standalone must reject malformed requests before selecting an endpoint"
);

const standaloneBundle = JSON.stringify(countBundle());
const standaloneValid = vm.runInContext(
  `verifyProofBundle(${standaloneBundle}, "${LEAF}")`,
  context
);
assert.equal(standaloneValid.rootMatch, true);
assert.throws(
  () => vm.runInContext(
    `verifyProofBundle(${standaloneBundle}, "${OTHER_LEAF}")`,
    context
  ),
  /returned leaf hash does not match/
);
const badStandalonePosition = clone(countBundle());
badStandalonePosition.proof = [{ hash: OTHER_LEAF, position: "sideways" }];
assert.throws(
  () => vm.runInContext(
    `verifyProofBundle(${JSON.stringify(badStandalonePosition)}, "${LEAF}")`,
    context
  ),
  /position must be exactly left or right/
);

const corpus = JSON.parse(
  fs.readFileSync(new URL("../equivalence/corpus.json", import.meta.url), "utf8")
);
assert.equal(corpus.cases.length, 11, "browser corpus coverage must remain 11 cases");
assert.deepEqual(
  corpus.cases.map((caseData) => caseData.id).sort(),
  [...EXPECTED_CORPUS_ACCEPTS.keys()].sort(),
  "every frozen corpus case must have an explicit expected browser verdict"
);

for (const caseData of corpus.cases) {
  assert.equal(
    caseData.allow_historical_legacy,
    false,
    `${caseData.id}: browser bundles have no caller-only legacy override`
  );
  const bundle = corpusBundle(caseData);
  const expected = EXPECTED_CORPUS_ACCEPTS.get(caseData.id);
  const core = coreOutcome(bundle, caseData.leaf_hash);

  context.corpusBundle = clone(bundle);
  context.corpusRequestedHash = caseData.leaf_hash;
  const standalone = JSON.parse(JSON.stringify(vm.runInContext(`(() => {
    try {
      const result = verifyProofBundle(corpusBundle, corpusRequestedHash);
      return {
        accepted: result.requestMatch === true && result.rootMatch === true &&
          result.leafMatch !== false,
        result: {
          requestMatch: result.requestMatch,
          rootMatch: result.rootMatch,
          rootMatchV2: result.rootMatchV2,
          rootMatchLegacy: result.rootMatchLegacy,
          legacyAllowed: result.legacyAllowed,
          computedRoot: result.computedRoot,
          legacyRoot: result.legacyRoot,
          rootScheme: result.rootScheme,
        },
      };
    } catch (error) {
      return { accepted: false, error: error.message };
    }
  })()`, context)));
  delete context.corpusBundle;
  delete context.corpusRequestedHash;

  assert.equal(core.accepted, expected, `${caseData.id}: browser core verdict`);
  assert.equal(standalone.accepted, expected, `${caseData.id}: standalone verdict`);
  assert.deepEqual(
    standalone.result,
    core.result,
    `${caseData.id}: browser core and standalone computed results`
  );
}

const reactSource = fs.readFileSync(new URL("./ProofVerifier.jsx", import.meta.url), "utf8");
assert.doesNotMatch(reactSource, /[^\x00-\x7f]/, "React verifier UI must remain ASCII");
assert.match(reactSource, /apiBase = DEFAULT_API_BASE/);
assert.match(reactSource, /fetchProofBundle\(apiBase, h\)/);
assert.match(reactSource, /verifyProofBundle\(data, h\)/);
assert.doesNotMatch(
  reactSource,
  /fetch\(`\$\{API\}/,
  "React verifier must not bypass its configured endpoint"
);

console.log("PASS: browser verifier request binding, 11-case corpus parity, and fail-closed parser regressions");
