"""
ZAP1 reference client. Generated from conformance/openapi.yaml.
Zero dependencies beyond stdlib. Works with any ZAP1-compatible server.
"""

import json
import urllib.request
from urllib.parse import quote


class Zap1Client:
    def __init__(
        self,
        base_url: str = "https://api.frontiercompute.cash",
        api_key: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""

    def _headers(self, authenticated: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if authenticated:
            if not self.api_key:
                raise ValueError("API key required for authenticated route")
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _get(self, path: str, authenticated: bool = False) -> dict:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers=self._headers(authenticated),
        )
        with urllib.request.urlopen(request, timeout=10) as resp:
            return json.load(resp)

    def _post_text(self, path: str, body: str) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body.encode(),
            headers={"Accept": "application/json", "Content-Type": "text/plain"},
            method="POST",
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
        return self._get(f"/events?limit={quote(str(limit), safe='')}")

    def anchor_history(self) -> dict:
        return self._get("/anchor/history")

    def anchor_status(self) -> dict:
        return self._get("/anchor/status")

    def verify(self, leaf_hash: str) -> dict:
        return self._get(f"/verify/{quote(leaf_hash, safe='')}/check")

    def proof_bundle(self, leaf_hash: str) -> dict:
        return self._get(f"/verify/{quote(leaf_hash, safe='')}/proof.json")

    def decode_memo(self, hex_bytes: str) -> dict:
        return self._post_text("/memo/decode", hex_bytes)

    def lifecycle(self, wallet_hash: str) -> dict:
        return self._get(
            f"/lifecycle/{quote(wallet_hash, safe='')}",
            authenticated=True,
        )


if __name__ == "__main__":
    client = Zap1Client()
    info = client.protocol_info()
    print(f"{info['protocol']} v{info['version']}")
    stats = client.stats()
    print(f"{stats['total_anchors']} API-recorded transaction references, {stats['total_leaves']} leaves")
    events = client.events(limit=3)
    for ev in events["events"]:
        print(f"  {ev['event_type']} {ev['leaf_hash'][:16]}...")
