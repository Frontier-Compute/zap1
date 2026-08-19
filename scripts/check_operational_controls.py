#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


main_rs = read("src/main.rs")
api_rs = read("src/api.rs")
setup = read("scripts/operator-setup.sh")
live = read("scripts/check_live.sh")
checker = read("conformance/check_api.py")
anchor_workflow = read(".github/workflows/anchor-liveness.yml")

require("Test address (index 0)" not in main_rs, "startup still logs a UFVK-derived address")
require("test_addr" not in main_rs, "startup retains a derived-address logging handle")
require(
    'tracing::info!("Created invoice {} -> {}"' not in api_rs,
    "invoice creation still logs the receiver",
)

require("anchor_send_required" in api_rs, "anchor send-state guard is missing")
require(
    'data-anchor-send-enabled="true"' in api_rs
    and 'data-anchor-send-enabled="false"' in api_rs,
    "anchor QR page lacks explicit send and no-send states",
)
require("ZAP1_API_BASE" in api_rs, "record command lacks an operator-bound API base")
require(
    "127.0.0.1:3081/admin/anchor/record" not in api_rs,
    "record command still targets the fixed 3081 listener",
)

require(
    'ZAP1_ADMIN_API_KEY="\\$ADMIN_API_KEY"' in setup,
    "generated runner does not scope the private API key to the checker",
)
require(
    "ZAP1_REQUIRE_AUTHENTICATED_ADMIN_CHECKS=true" in setup,
    "generated runner does not require authenticated admin checks",
)
require("API_KEY_LINES" in setup, "generated runner does not require one API_KEY line")
require(
    re.search(r"(?:^|\n)\s*(?:source|\.)\s+.*\.env", setup) is None,
    "generated runner sources the env file as shell code",
)
require("Address: $ADDRESS" not in setup, "operator setup summary prints the receiver")

require(
    "ZAP1_REQUIRE_AUTHENTICATED_ADMIN_CHECKS=true" in live,
    "live gate does not require authenticated admin checks",
)
require("ADMIN_API_KEY" in live, "live gate does not validate the admin key")
require(
    "REQUIRE_ADMIN_CHECK" in checker
    and "/admin/anchor/qr authenticated checks are mandatory" in checker,
    "API checker can silently skip a required admin path",
)

require(
    "github.event_name == 'schedule' || inputs.mode == 'public-monitor'"
    in anchor_workflow,
    "scheduled public monitoring is not isolated from the exact deployment gate",
)
require(
    "ZAP1_REQUIRE_FRESH_ANCHOR: 'false'" in anchor_workflow,
    "paused anchor authority is not explicit in the public monitor",
)
require(
    "python3 conformance/check_api.py ${ZAP1_API_BASE}" in anchor_workflow,
    "scheduled monitoring omits the public API privacy contract",
)
require(
    "github.event_name == 'workflow_dispatch' && inputs.mode == 'exact-deployment'"
    in anchor_workflow,
    "the secret-bearing exact deployment gate is not manual-only",
)
require(
    anchor_workflow.count("bash scripts/check_live.sh") == 1
    and anchor_workflow.count("ZAP1_ADMIN_API_KEY: ${{ secrets.ZAP1_ADMIN_API_KEY }}") == 1,
    "the exact deployment checker or its secret is duplicated across workflow paths",
)
require(
    "permissions:\n  contents: read" in anchor_workflow,
    "anchor workflow token permissions are not explicitly read-only",
)

require(live.startswith("#!/usr/bin/env bash\nset +x\n"), "live checker does not disable xtrace")
require(
    "unset ZAP1_ADMIN_API_KEY" in live
    and "authenticated_api_check" in live
    and 'ZAP1_ADMIN_API_KEY="$ADMIN_API_KEY"' in live,
    "live checker does not scope the admin key to the authenticated checker",
)
require(setup.count("set +x") >= 2, "setup or generated runner leaves xtrace enabled")
require(
    'tracing::info!("Zebra RPC: {}"' not in main_rs
    and "Scanner backend: Zebra RPC at" not in read("src/node.rs"),
    "runtime logs can disclose configured RPC endpoints",
)

print(
    "PASS: operational privacy, admin-auth, anchor-send, and monitoring-separation contracts"
)
