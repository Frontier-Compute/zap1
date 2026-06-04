#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import check_anchor_liveness as liveness


def fixture(*, age=100, needs_anchor=True, unanchored=1):
    protocol = {"protocol": "ZAP1"}
    stats = {
        "total_anchors": 1,
        "total_leaves": 3,
        "last_anchor_block": 10,
    }
    history = {
        "total": 1,
        "last_anchor_age_hours": age,
        "anchors": [{"height": 10, "txid": "tx1"}],
    }
    status = {
        "needs_anchor": needs_anchor,
        "unanchored_leaves": unanchored,
        "last_anchor_txid": "tx1",
    }
    return protocol, stats, history, status


class AnchorLivenessPolicyTest(unittest.TestCase):
    def test_pending_stale_anchor_fails_when_fresh_anchor_required(self):
        summary = liveness.build_summary(
            *fixture(),
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )

        self.assertEqual(summary["warnings"], [])
        self.assertEqual(len(summary["errors"]), 1)
        self.assertIn("last anchor age 100h exceeds threshold 72h", summary["errors"][0])

    def test_pending_stale_anchor_warns_when_fresh_anchor_not_required(self):
        summary = liveness.build_summary(
            *fixture(),
            require_fresh_anchor=False,
            max_anchor_age_hours=72,
        )

        self.assertEqual(summary["errors"], [])
        self.assertEqual(len(summary["warnings"]), 1)
        self.assertIn("fresh-anchor requirement disabled", summary["warnings"][0])
        self.assertFalse(summary["fresh_anchor_required"])

    def test_stale_anchor_without_pending_work_is_warning(self):
        summary = liveness.build_summary(
            *fixture(needs_anchor=False, unanchored=0),
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )

        self.assertEqual(summary["errors"], [])
        self.assertEqual(len(summary["warnings"]), 1)

    def test_txid_mismatch_still_fails_when_fresh_anchor_not_required(self):
        protocol, stats, history, status = fixture()
        status["last_anchor_txid"] = "other"
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=False,
            max_anchor_age_hours=72,
        )

        self.assertTrue(
            any("anchor/status txid" in error for error in summary["errors"])
        )


if __name__ == "__main__":
    unittest.main()
