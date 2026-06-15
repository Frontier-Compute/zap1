"""
ZAP1 reference client. Generated from conformance/openapi.yaml.
Zero dependencies beyond stdlib. Works with any ZAP1-compatible server.
"""

import json
import urllib.request
from typing import Optional


class Zap1Client:
    def __init__(self, base_url: str = "https://api.frontiercompute.cash"):
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=10) as resp:
            return json.load(resp)

    def _post(self, path: str, body: str) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=body.encode(), method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)

    def protocol_info(self) -> dict:
        return self._get("/protocol/info")

    def stats(self) -> dict:
        return self._get("/stats")

    def health(self) -> dict:
        return self._get("/health")

    def events(self, limit: int = 50) -> dict:
        return self._get(f"/events?limit={limit}")

    def anchor_history(self) -> dict:
        return self._get("/anchor/history")

    def anchor_status(self) -> dict:
        return self._get("/anchor/status")

    def verify(self, leaf_hash: str) -> dict:
        return self._get(f"/verify/{leaf_hash}/check")

    def proof_bundle(self, leaf_hash: str) -> dict:
        return self._get(f"/verify/{leaf_hash}/proof.json")

    def decode_memo(self, hex_bytes: str) -> dict:
        return self._post("/memo/decode", hex_bytes)

    def lifecycle(self, wallet_hash: str) -> dict:
        return self._get(f"/lifecycle/{wallet_hash}")


if __name__ == "__main__":
    client = Zap1Client()
    info = client.protocol_info()
    print(f"{info['protocol']} v{info['version']}")
    stats = client.stats()
    print(f"{stats['total_anchors']} anchors, {stats['total_leaves']} leaves")
    events = client.events(limit=3)
    for ev in events["events"]:
        print(f"  {ev['event_type']} {ev['leaf_hash'][:16]}...")
