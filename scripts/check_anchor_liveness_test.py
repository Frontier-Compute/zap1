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
        "anchors": [
            {
                "height": 10,
                "txid": "a" * 64,
                "root": "c" * 64,
                "leaf_count": 2,
                "created_at": "2026-08-14T00:00:00+00:00",
                "scheme": "ZAP1_COUNT_BOUND_V2",
            }
        ],
    }
    status = {
        "needs_anchor": needs_anchor,
        "unanchored_leaves": unanchored,
        "last_anchor_txid": "a" * 64,
        "leaf_count": 3,
        "current_root": "b" * 64,
    }
    history["anchors"][0]["txid"] = "a" * 64
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
        protocol, stats, history, status = fixture(needs_anchor=False, unanchored=0)
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

    def test_pending_current_root_does_not_mismatch_previous_anchor_txid(self):
        protocol, stats, history, status = fixture(age=1)
        status["last_anchor_txid"] = None
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )
        self.assertEqual(summary["errors"], [])

    def test_invalid_anchor_history_fails_closed(self):
        protocol, stats, history, status = fixture(age=1)
        history["anchors"][0].update(
            {
                "root": "not-a-root",
                "txid": "not-a-txid",
                "leaf_count": 4,
                "height": -1,
                "created_at": "not-a-time",
                "scheme": "unknown",
            }
        )
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=False,
            max_anchor_age_hours=72,
        )
        errors = " ".join(summary["errors"])
        for fragment in ("root", "txid", "leaf_count", "height", "created_at", "scheme"):
            self.assertIn(fragment, errors)

    def test_invalid_status_types_fail_closed(self):
        protocol, stats, history, status = fixture()
        status["needs_anchor"] = "false"
        status["unanchored_leaves"] = True
        status["leaf_count"] = "3"
        status["current_root"] = "none"
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )
        self.assertTrue(any("needs_anchor" in error for error in summary["errors"]))
        self.assertTrue(any("unanchored_leaves" in error for error in summary["errors"]))
        self.assertTrue(any("leaf_count" in error for error in summary["errors"]))
        self.assertTrue(any("current_root" in error for error in summary["errors"]))

    def test_pending_count_cannot_exceed_total_or_hide_behind_false_flag(self):
        protocol, stats, history, status = fixture(needs_anchor=False, unanchored=4)
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )
        self.assertTrue(any("exceeds total_leaves" in error for error in summary["errors"]))
        self.assertTrue(any("needs_anchor=false" in error for error in summary["errors"]))

    def test_nonempty_tree_without_history_fails_when_freshness_is_required(self):
        protocol, stats, history, status = fixture()
        stats["total_anchors"] = 0
        history.update({"total": 0, "anchors": [], "last_anchor_age_hours": -1})
        status.update({"last_anchor_txid": None, "unanchored_leaves": 3})
        summary = liveness.build_summary(
            protocol,
            stats,
            history,
            status,
            require_fresh_anchor=True,
            max_anchor_age_hours=72,
        )
        self.assertIn("nonempty Merkle tree has no recorded anchor", summary["errors"])


if __name__ == "__main__":
    unittest.main()
