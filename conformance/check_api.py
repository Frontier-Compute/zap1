#!/usr/bin/env python3
"""
Validate live ZAP1 API responses against the schema contract.

    python3 conformance/check_api.py [base_url]
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
BASE = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("ZAP1_API_BASE", "https://api.frontiercompute.cash")
).rstrip("/")
USER_AGENT = os.environ.get("ZAP1_USER_AGENT", "zap1-anchor-liveness/1.0")
API_RETRIES = int(os.environ.get("ZAP1_API_RETRIES", "3"))
API_RETRY_DELAY_SECONDS = float(os.environ.get("ZAP1_API_RETRY_DELAY_SECONDS", "1"))
REQUIRE_SOURCE_PARITY = os.environ.get("ZAP1_REQUIRE_SOURCE_PARITY", "false").lower() == "true"
EXPECTED_SOURCE_REVISION = os.environ.get("ZAP1_EXPECTED_SOURCE_REVISION", "")
EXPECTED_SOURCE_TREE = os.environ.get("ZAP1_EXPECTED_SOURCE_TREE", "")
EXPECTED_SOURCE_MANIFEST = os.environ.get("ZAP1_EXPECTED_SOURCE_MANIFEST_SHA256", "")
EXPECTED_DEPLOYMENT_IMAGE_ID = os.environ.get("ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID", "")
MAX_SYNC_LAG_BLOCKS_RAW = os.environ.get("ZAP1_MAX_SYNC_LAG_BLOCKS", "10")
REQUIRE_ADMIN_CHECK_RAW = os.environ.get("ZAP1_REQUIRE_AUTHENTICATED_ADMIN_CHECKS", "false")

NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3_317_133
MAX_U64 = (1 << 64) - 1
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")

try:
    MAX_SYNC_LAG_BLOCKS = int(MAX_SYNC_LAG_BLOCKS_RAW)
except ValueError:
    raise SystemExit("ZAP1_MAX_SYNC_LAG_BLOCKS must be a nonnegative integer")
if MAX_SYNC_LAG_BLOCKS < 0:
    raise SystemExit("ZAP1_MAX_SYNC_LAG_BLOCKS must be a nonnegative integer")

if REQUIRE_ADMIN_CHECK_RAW not in {"true", "false"}:
    raise SystemExit("ZAP1_REQUIRE_AUTHENTICATED_ADMIN_CHECKS must be exactly true or false")
REQUIRE_ADMIN_CHECK = REQUIRE_ADMIN_CHECK_RAW == "true"

# Public inclusion proofs need commitments, not event payload openings. Keep the
# complete POST /event payload vocabulary here so any accidental disclosure is
# a failing evaluator result, including a leak nested below a future wrapper.
PUBLIC_EVENT_PREIMAGE_FIELDS = frozenset(
    {
        "wallet_hash",
        "serial_number",
        "serial",
        "old_wallet_hash",
        "new_wallet_hash",
        "contract_sha256",
        "facility_id",
        "month",
        "year",
        "amount_zat",
        "validator_id",
        "epoch",
        "proposal_id",
        "proposal_hash",
        "vote_commitment",
        "result_hash",
        "agent_id",
        "pubkey_hash",
        "model_hash",
        "policy_hash",
        "policy_version",
        "rules_hash",
        "action_type",
        "input_hash",
        "output_hash",
    }
)

passed = 0
failed = 0


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        print(f"  pass  {label}")
        passed += 1
    else:
        print(f"  FAIL  {label}  {detail}")
        failed += 1


API_KEY = os.environ.get("ZAP1_ADMIN_API_KEY", "")
if REQUIRE_ADMIN_CHECK and re.fullmatch(r"[A-Za-z0-9._~-]+", API_KEY) is None:
    raise SystemExit(
        "ZAP1_ADMIN_API_KEY is required when authenticated admin checks are mandatory "
        "and must use the safe token alphabet"
    )



def request_headers(headers=None, *, accept_json=False, content_type=None):
    merged = {"User-Agent": USER_AGENT}
    if accept_json:
        merged["Accept"] = "application/json"
    if content_type:
        merged["Content-Type"] = content_type
    merged.update(headers or {})
    return merged


def fetch(path, headers=None):
    url = f"{BASE}{path}"
    for attempt in range(1, API_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=request_headers(headers, accept_json=True))
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.load(resp)
        except Exception:
            if attempt >= API_RETRIES:
                return None
            time.sleep(API_RETRY_DELAY_SECONDS)


def fetch_raw(path, headers=None, method="GET"):
    url = f"{BASE}{path}"
    for attempt in range(1, API_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=request_headers(headers), method=method)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(), resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return e.code, "", ""
        except Exception:
            if attempt >= API_RETRIES:
                return 0, "", ""
            time.sleep(API_RETRY_DELAY_SECONDS)


def value_has_type(value, expected_type):
    if expected_type == "null":
        return value is None
    if expected_type == "boolean":
        return type(value) is bool
    if expected_type == "integer":
        return type(value) is int
    if expected_type == "number":
        return type(value) in (int, float)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    return False


def schema_errors(value, schema, path):
    errors = []
    expected_types = schema.get("type")
    if expected_types is not None:
        if not isinstance(expected_types, list):
            expected_types = [expected_types]
        if not any(value_has_type(value, expected) for expected in expected_types):
            return [f"{path}: expected {expected_types}, got {type(value).__name__}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is outside enum")
    if type(value) in (int, float):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema:
            import re

            if re.fullmatch(schema["pattern"], value) is None:
                errors.append(f"{path}: does not match required pattern")
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                errors.append(f"{path}: missing {field}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value).difference(properties))
            if unknown:
                errors.append(f"{path}: unexpected fields {unknown}")
        for field, field_schema in properties.items():
            if field in value:
                errors.extend(schema_errors(value[field], field_schema, f"{path}.{field}"))
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(schema_errors(item, schema["items"], f"{path}[{index}]"))
    return errors


def validate_required(data, schema, path):
    if data is None:
        check(path, False, "fetch failed")
        return False
    errors = schema_errors(data, schema, path)
    check(f"{path} schema", not errors, "; ".join(errors[:4]))
    return not errors


def public_preimage_leaks(value, path="$"):
    leaks = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in PUBLIC_EVENT_PREIMAGE_FIELDS:
                leaks.append(child_path)
            leaks.extend(public_preimage_leaks(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaks.extend(public_preimage_leaks(child, f"{path}[{index}]"))
    return leaks


def require_hex32(value, label):
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return value


def require_leaf_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_U64:
        raise ValueError("root.leaf_count must be an integer from 1 through 2^64-1")
    return value


def require_anchor_height(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("anchor.height must be a nonnegative u32 or null")
    return value


def hash_node(left, right):
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node inputs must each be 32 bytes")
    return hashlib.blake2b(left + right, digest_size=32, person=NODE_PERSONAL).digest()


def commit_root(leaf_count, raw_root):
    leaf_count = require_leaf_count(leaf_count)
    if len(raw_root) != 32:
        raise ValueError("raw Merkle root must be 32 bytes")
    payload = b"\x01" + leaf_count.to_bytes(8, "big") + raw_root
    return hashlib.blake2b(payload, digest_size=32, person=ROOT_PERSONAL).digest()


def verify_public_proof_bundle(bundle, requested_leaf):
    """Independently verify one public API proof bundle.

    This deliberately does not trust /verify/{hash}/check. It validates the
    exact public bundle profile, binds the response to the requested leaf, and
    recomputes the selected Merkle scheme locally.
    """
    if not isinstance(bundle, dict):
        raise ValueError("proof bundle must be a JSON object")
    if bundle.get("protocol") != "ZAP1":
        raise ValueError("bundle protocol must be exactly 'ZAP1'")
    if bundle.get("version") != "2":
        raise ValueError("public API proof bundle version must be exactly '2'")

    leaf = bundle.get("leaf")
    proof = bundle.get("proof")
    root = bundle.get("root")
    anchor = bundle.get("anchor")
    if not isinstance(leaf, dict) or not isinstance(root, dict) or not isinstance(anchor, dict):
        raise ValueError("bundle leaf, root, and anchor must be objects")
    if not isinstance(proof, list):
        raise ValueError("bundle proof must be an array")

    requested_leaf = require_hex32(requested_leaf, "requested leaf hash")
    leaf_hash = require_hex32(leaf.get("hash"), "leaf.hash")
    if leaf_hash != requested_leaf:
        raise ValueError("returned bundle leaf.hash does not match the requested leaf hash")
    root_hash = require_hex32(root.get("hash"), "root.hash")
    leaf_count = require_leaf_count(root.get("leaf_count"))
    scheme = root.get("scheme")
    if scheme not in (COUNT_BOUND_SCHEME, LEGACY_SCHEME):
        raise ValueError("root.scheme is not an admitted ZAP1 Merkle scheme")
    if root.get("legacy_max_anchor_height") != LEGACY_ROOT_MAX_ANCHOR_HEIGHT:
        raise ValueError("root.legacy_max_anchor_height does not match the admitted cutoff")

    txid = anchor.get("txid")
    if txid is not None:
        require_hex32(txid, "anchor.txid")
    anchor_height = require_anchor_height(anchor.get("height"))

    current = bytes.fromhex(leaf_hash)
    for index, step in enumerate(proof):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        sibling = bytes.fromhex(require_hex32(step.get("hash"), f"proof[{index}].hash"))
        position = step.get("position")
        if position == "right":
            current = hash_node(current, sibling)
        elif position == "left":
            current = hash_node(sibling, current)
        else:
            raise ValueError(f"proof[{index}].position must be exactly 'left' or 'right'")

    expected = bytes.fromhex(root_hash)
    if scheme == COUNT_BOUND_SCHEME:
        if root.get("legacy_allowed") is not False:
            raise ValueError("count-bound bundle must declare legacy_allowed=false")
        if commit_root(leaf_count, current) != expected:
            raise ValueError("count-bound Merkle proof does not match root.hash")
    else:
        if root.get("legacy_allowed") is not True:
            raise ValueError("legacy bundle must declare legacy_allowed=true")
        if anchor_height is None or anchor_height > LEGACY_ROOT_MAX_ANCHOR_HEIGHT:
            raise ValueError("legacy bundle lacks an admitted historical anchor height")
        if current != expected:
            raise ValueError("legacy Merkle proof does not match root.hash")
    return True


def proof_verifier_self_test():
    leaf = "00" * 32
    sibling = "11" * 32
    raw_root = hash_node(bytes.fromhex(leaf), bytes.fromhex(sibling))
    bundle = {
        "protocol": "ZAP1",
        "version": "2",
        "leaf": {"hash": leaf},
        "proof": [{"hash": sibling, "position": "right"}],
        "root": {
            "hash": commit_root(2, raw_root).hex(),
            "leaf_count": 2,
            "scheme": COUNT_BOUND_SCHEME,
            "legacy_allowed": False,
            "legacy_max_anchor_height": LEGACY_ROOT_MAX_ANCHOR_HEIGHT,
        },
        "anchor": {"txid": None, "height": None},
    }
    verify_public_proof_bundle(bundle, leaf)

    def must_fail(label, mutate):
        candidate = json.loads(json.dumps(bundle))
        mutate(candidate)
        try:
            verify_public_proof_bundle(candidate, leaf)
        except ValueError:
            return
        raise SystemExit(f"self-test failed: {label} was accepted")

    must_fail("tampered sibling", lambda value: value["proof"][0].update(hash="22" * 32))
    must_fail("tampered root", lambda value: value["root"].update(hash="ff" * 32))
    must_fail("fake scheme", lambda value: value["root"].update(scheme="ZAP1_FAKE"))
    must_fail("wrong requested leaf", lambda value: value["leaf"].update(hash="33" * 32))

    legacy = json.loads(json.dumps(bundle))
    legacy["root"].update(
        hash=raw_root.hex(),
        scheme=LEGACY_SCHEME,
        legacy_allowed=True,
    )
    legacy["anchor"]["height"] = LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    verify_public_proof_bundle(legacy, leaf)
    legacy["anchor"]["height"] = LEGACY_ROOT_MAX_ANCHOR_HEIGHT + 1
    try:
        verify_public_proof_bundle(legacy, leaf)
    except ValueError:
        pass
    else:
        raise SystemExit("self-test failed: post-cutoff legacy bundle was accepted")


def self_test():
    safe = {
        "leaf": {
            "hash": "00" * 32,
            "event_type": "OWNERSHIP_ATTEST",
            "event_type_authentication": "unverified_server_metadata_without_disclosed_witness",
            "preimage_disclosure": "withheld from the public proof bundle",
        }
    }
    if public_preimage_leaks(safe):
        raise SystemExit("self-test failed: safe public bundle was rejected")
    strict_errors = schema_errors(
        {"hash": "00" * 32, "unexpected": "preimage"},
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {"hash": {"type": "string"}},
        },
        "$.leaf",
    )
    if not strict_errors:
        raise SystemExit("self-test failed: unexpected public field was accepted")

    nested = {"events": [{"metadata": {"wallet_hash": "subject"}}]}
    if public_preimage_leaks(nested) != ["$.events[0].metadata.wallet_hash"]:
        raise SystemExit("self-test failed: nested subject preimage was not rejected")

    declared = {"leaf": {field: "value" for field in PUBLIC_EVENT_PREIMAGE_FIELDS}}
    leaked_fields = {path.rsplit(".", 1)[-1] for path in public_preimage_leaks(declared)}
    if leaked_fields != PUBLIC_EVENT_PREIMAGE_FIELDS:
        raise SystemExit("self-test failed: declared payload preimage coverage is incomplete")

    proof_verifier_self_test()

    healthy = {
        "scanner_operational": True,
        "rpc_reachable": True,
        "last_scanned_height": 100,
        "chain_tip": 100 + MAX_SYNC_LAG_BLOCKS,
        "sync_lag": MAX_SYNC_LAG_BLOCKS,
    }
    if not health_policy_passes(healthy):
        raise SystemExit("self-test failed: boundary-valid health was rejected")
    for key, value in (
        ("scanner_operational", False),
        ("rpc_reachable", False),
        ("sync_lag", MAX_SYNC_LAG_BLOCKS + 1),
        ("chain_tip", healthy["chain_tip"] + 1),
    ):
        unhealthy = dict(healthy)
        unhealthy[key] = value
        if health_policy_passes(unhealthy):
            raise SystemExit(f"self-test failed: unhealthy {key} was accepted")

    print("PASS: evaluator privacy policy self-test")
    print("PASS: evaluator health policy self-test")
    print("PASS: evaluator independent proof policy self-test")


def health_policy_passes(data):
    sync_lag = data.get("sync_lag")
    last_scanned = data.get("last_scanned_height")
    chain_tip = data.get("chain_tip")
    expected_lag = (
        max(chain_tip - last_scanned, 0)
        if type(chain_tip) is int and type(last_scanned) is int
        else None
    )
    return (
        data.get("scanner_operational") is True
        and data.get("rpc_reachable") is True
        and type(sync_lag) is int
        and 0 <= sync_lag <= MAX_SYNC_LAG_BLOCKS
        and sync_lag == expected_lag
    )


def main():
    with open(os.path.join(DIR, "api_schemas.json")) as f:
        schemas = json.load(f)["schemas"]

    print(f"ZAP1 API schema validation against {BASE}")
    print("=" * 50)
    print()

    # /protocol/info
    data = fetch("/protocol/info")
    if validate_required(data, schemas["/protocol/info"], "/protocol/info"):
        check("/protocol/info protocol=ZAP1", data.get("protocol") == "ZAP1")
        check("/protocol/info hash=BLAKE2b-256", data.get("hash_function") == "BLAKE2b-256")
        version = data.get("version", "")
        check("/protocol/info version major=3", isinstance(version, str) and version.startswith("3."))
        defined = data.get("defined_event_types", [])
        writable = data.get("write_api_event_types", [])
        managed = data.get("system_managed_event_types", [])
        check(
            "/protocol/info defined registry count is exact",
            isinstance(defined, list)
            and data.get("defined_types") == len(defined) == 18,
        )
        check(
            "/protocol/info write/system registries partition defined types",
            isinstance(writable, list)
            and isinstance(managed, list)
            and data.get("write_api_types") == len(writable) == 15
            and data.get("system_managed_types") == len(managed) == 3
            and not set(writable).intersection(managed)
            and set(writable).union(managed) == set(defined),
        )
        check(
            "/protocol/info legacy aliases remain additive",
            data.get("event_types") == data.get("defined_types")
            and data.get("deployed_types") == data.get("write_api_types")
            and data.get("reserved_types") == data.get("system_managed_types"),
        )

    # /build/info
    build_data = fetch("/build/info")
    if validate_required(build_data, schemas["/build/info"], "/build/info"):
        source = build_data["source"]
        assurance = build_data["build_assurance"]
        deployment = build_data["deployment"]
        check("/build/info metadata is complete", assurance.get("metadata_complete") is True)
        check("/build/info used Cargo.lock", assurance.get("cargo_locked") is True)
        check("/build/info remapped build paths", assurance.get("path_remapping") is True)
        check(
            "/build/info reports an internally matching runtime-source manifest",
            source.get("source_manifest_verified") is True
            and assurance.get("source_manifest_verified") is True,
        )
        if REQUIRE_SOURCE_PARITY:
            check(
                "source parity expectations are complete",
                bool(
                    EXPECTED_SOURCE_REVISION
                    and EXPECTED_SOURCE_TREE
                    and EXPECTED_SOURCE_MANIFEST
                    and EXPECTED_DEPLOYMENT_IMAGE_ID
                ),
            )
            check(
                "declared deployment revision matches evaluator checkout",
                source.get("deployment_revision") == EXPECTED_SOURCE_REVISION,
                f"expected {EXPECTED_SOURCE_REVISION}, got {source.get('deployment_revision')}",
            )
            check(
                "declared source tree matches evaluator checkout",
                source.get("source_tree") == EXPECTED_SOURCE_TREE,
                f"expected {EXPECTED_SOURCE_TREE}, got {source.get('source_tree')}",
            )
            check(
                "declared runtime-source manifest matches committed archive",
                source.get("source_manifest_sha256") == EXPECTED_SOURCE_MANIFEST,
                f"expected {EXPECTED_SOURCE_MANIFEST}, got {source.get('source_manifest_sha256')}",
            )
            check(
                "declared public evidence revision matches evaluator checkout",
                source.get("public_evidence_revision") == EXPECTED_SOURCE_REVISION,
                f"expected {EXPECTED_SOURCE_REVISION}, got {source.get('public_evidence_revision')}",
            )
            check(
                "declared image ID matches operator-local pinned-image receipt",
                deployment.get("image_id") == EXPECTED_DEPLOYMENT_IMAGE_ID,
                f"expected {EXPECTED_DEPLOYMENT_IMAGE_ID}, got {deployment.get('image_id')}",
            )

    # /stats
    data = fetch("/stats")
    if validate_required(data, schemas["/stats"], "/stats"):
        check("/stats anchors >= 0", data.get("total_anchors", -1) >= 0)
        check("/stats leaves >= 0", data.get("total_leaves", -1) >= 0)
        type_counts = data.get("type_counts", {})
        event_types = data.get("event_types", [])
        numeric_counts = (
            isinstance(type_counts, dict)
            and all(isinstance(value, int) and value >= 0 for value in type_counts.values())
        )
        check("/stats type_counts are nonnegative integers", numeric_counts)
        if numeric_counts:
            check(
                "/stats type counts sum to total leaves",
                sum(type_counts.values()) == data.get("total_leaves"),
            )
        check(
            "/stats classified plus unclassified equals total",
            data.get("classified_leaves", -1) + data.get("unclassified_leaves", -1)
            == data.get("total_leaves"),
        )
        check(
            "/stats every declared event type has a count",
            isinstance(event_types, list)
            and all(event_type in type_counts for event_type in event_types),
        )

    # /health
    data = fetch("/health")
    if validate_required(data, schemas["/health"], "/health"):
        check("/health passes the complete live policy", health_policy_passes(data))
        check("/health scanner is operational", data.get("scanner_operational") is True)
        check("/health RPC is reachable", data.get("rpc_reachable") is True)
        sync_lag = data.get("sync_lag")
        check(
            f"/health sync lag <= {MAX_SYNC_LAG_BLOCKS} blocks",
            type(sync_lag) is int and 0 <= sync_lag <= MAX_SYNC_LAG_BLOCKS,
            f"reported {sync_lag!r}; policy ZAP1_MAX_SYNC_LAG_BLOCKS={MAX_SYNC_LAG_BLOCKS}",
        )
        last_scanned = data.get("last_scanned_height")
        chain_tip = data.get("chain_tip")
        expected_lag = (
            max(chain_tip - last_scanned, 0)
            if type(chain_tip) is int and type(last_scanned) is int
            else None
        )
        check(
            "/health sync lag is internally consistent",
            expected_lag is not None and sync_lag == expected_lag,
            f"tip={chain_tip!r}, scanned={last_scanned!r}, lag={sync_lag!r}",
        )

    # /events
    verify_hash = None
    events_data = fetch("/events?limit=3")
    event_leaks = public_preimage_leaks(events_data)
    check(
        "/events withholds declared event payload preimages",
        events_data is not None and not event_leaks,
        ", ".join(event_leaks[:4]),
    )
    events = events_data.get("events", []) if isinstance(events_data, dict) else []
    if isinstance(events, list) and events:
        candidate_hash = events[0].get("leaf_hash") if isinstance(events[0], dict) else None
        if isinstance(candidate_hash, str) and re.fullmatch(r"[0-9a-f]{64}", candidate_hash):
            verify_hash = candidate_hash
    if validate_required(events_data, schemas["/events"], "/events"):
        check("/events protocol=ZAP1", events_data.get("protocol") == "ZAP1")
        if events:
            ev = events[0]
            check("/events[0] has leaf_hash", "leaf_hash" in ev and len(ev["leaf_hash"]) == 64)
            check("/events[0] has verify_url", "verify_url" in ev)

    # /anchor/history
    has_anchors = False
    data = fetch("/anchor/history")
    if validate_required(data, schemas["/anchor/history"], "/anchor/history"):
        anchors = data.get("anchors", [])
        has_anchors = len(anchors) > 0
        check("/anchor/history total consistent", data.get("total", -1) == len(anchors))
        if anchors:
            check("/anchor/history[0] has root", len(anchors[0].get("root", "")) >= 64)

    # /verify/{hash}/check
    if verify_hash is None:
        print("  skip  /verify/check  (no events available to sample)")
        print("  skip  /verify/proof.json  (no events available to sample)")
    else:
        data = fetch(f"/verify/{verify_hash}/check")
        if validate_required(data, schemas["/verify/{hash}/check"], "/verify/check"):
            check("/verify/check valid=true", data.get("valid") is True)
            check("/verify/check protocol=ZAP1", data.get("protocol") == "ZAP1")
        proof_data = fetch(f"/verify/{verify_hash}/proof.json")
        proof_leaks = public_preimage_leaks(proof_data)
        check(
            "/verify/proof.json withholds declared event payload preimages",
            proof_data is not None and not proof_leaks,
            ", ".join(proof_leaks[:4]),
        )
        if validate_required(
            proof_data,
            schemas["/verify/{hash}/proof.json"],
            "/verify/proof.json",
        ):
            check(
                "/verify/proof.json leaf matches requested event",
                proof_data.get("leaf", {}).get("hash") == verify_hash,
            )
            check(
                "/verify/proof.json labels event type as unverified metadata",
                proof_data.get("leaf", {}).get("event_type_authentication")
                == "unverified_server_metadata_without_disclosed_witness",
            )
            try:
                independently_verified = verify_public_proof_bundle(proof_data, verify_hash)
                verification_detail = ""
            except (TypeError, ValueError) as error:
                independently_verified = False
                verification_detail = str(error)
            check(
                "/verify/proof.json independently verifies Merkle inclusion",
                independently_verified,
                verification_detail,
            )
    # /memo/decode
    hex_body = "5a4150313a30313a30373562303064663238363033386137623366366262373030353464663631333433653334383166626135373935393133353461303032313465396530313962"
    try:
        req = urllib.request.Request(
            f"{BASE}/memo/decode",
            data=hex_body.encode(),
            headers=request_headers(
                accept_json=True,
                content_type="text/plain; charset=utf-8",
            ),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        check("/memo/decode returns format", "format" in data)
        check("/memo/decode format=zap1", data.get("format") == "zap1")
    except Exception as e:
        check("/memo/decode", False, str(e))

    # /admin/anchor/qr (requires header auth and must fail closed when no send is due)
    status, body, ctype = fetch_raw("/admin/anchor/qr")
    check("/admin/anchor/qr rejects without auth", status == 401)
    anchor_status = fetch("/anchor/status")
    anchor_status_valid = isinstance(anchor_status, dict)
    if anchor_status_valid:
        current_root = anchor_status.get("current_root")
        leaf_count = anchor_status.get("leaf_count")
        unanchored = anchor_status.get("unanchored_leaves")
        last_txid = anchor_status.get("last_anchor_txid")
        needs_anchor = anchor_status.get("needs_anchor")
        root_is_none = current_root == "none"
        root_is_hex = (
            isinstance(current_root, str)
            and HEX32_RE.fullmatch(current_root) is not None
        )
        anchor_status_valid = (
            (root_is_none or root_is_hex)
            and type(leaf_count) is int
            and leaf_count >= 0
            and type(unanchored) is int
            and 0 <= unanchored <= leaf_count
            and type(needs_anchor) is bool
            and (
                last_txid is None
                or isinstance(last_txid, str)
                and HEX32_RE.fullmatch(last_txid) is not None
            )
        )
        if anchor_status_valid and root_is_none:
            anchor_status_valid = (
                leaf_count == 0
                and unanchored == 0
                and last_txid is None
                and needs_anchor is False
            )
        elif anchor_status_valid:
            anchor_status_valid = (
                leaf_count > 0
                and needs_anchor == (last_txid is None or unanchored > 0)
            )
    check("/anchor/status supports the authenticated QR gate", anchor_status_valid)

    if API_KEY:
        status, body, ctype = fetch_raw(
            "/admin/anchor/qr",
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        if anchor_status_valid and current_root != "none":
            check("/admin/anchor/qr returns 200 with auth", status == 200)
            check("/admin/anchor/qr content-type is HTML", "text/html" in ctype)
            check("/admin/anchor/qr body contains HTML", "<html" in body.lower())
            check("/admin/anchor/qr binds current root", current_root in body)
            check(
                "/admin/anchor/qr binds leaf counts",
                f"Leaves: {leaf_count} ({unanchored} unanchored)" in body,
            )
            check("/admin/anchor/qr does not reflect the API key", API_KEY not in body)
            send_expected = last_txid is None and unanchored > 0
            if send_expected:
                check(
                    "/admin/anchor/qr exposes one actionable send state",
                    'data-anchor-send-enabled="true"' in body and "<svg" in body,
                )
                check(
                    "/admin/anchor/qr binds the exact memo",
                    f"Memo: ZAP1:09:{current_root}" in body,
                )
                check(
                    "/admin/anchor/qr record command is endpoint-explicit and port-agnostic",
                    "ZAP1_API_BASE" in body
                    and "/admin/anchor/record" in body
                    and "127.0.0.1:3081" not in body,
                )
            else:
                check(
                    "/admin/anchor/qr suppresses duplicate send actions",
                    'data-anchor-send-enabled="false"' in body
                    and "<svg" not in body
                    and "Scan with" not in body
                    and "/admin/anchor/record" not in body,
                )
        else:
            check("/admin/anchor/qr accepted auth", status in (200, 400))
            if status == 400:
                print("  skip  /admin/anchor/qr HTML checks  (no Merkle root yet)")
    elif REQUIRE_ADMIN_CHECK:
        check(
            "/admin/anchor/qr authenticated checks are mandatory",
            False,
            "ZAP1_ADMIN_API_KEY not set",
        )
    else:
        print("  skip  /admin/anchor/qr authenticated checks  (ZAP1_ADMIN_API_KEY not set)")

    # /admin/anchor/record (POST-only, requires auth)
    status, _, _ = fetch_raw("/admin/anchor/record")
    check("/admin/anchor/record rejects GET", status in (401, 405))

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        self_test()
    else:
        main()
