"""Tiny urllib client for the pkg-integrity transparency log."""

import json
import urllib.request


class LogClient:
    def __init__(self, base_url: str, timeout: int = 20):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(self.base + path,
                                    timeout=self.timeout) as r:
            return json.load(r)

    def _post(self, path: str, obj: dict) -> dict:
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def sth(self) -> dict:
        return self._get("/sth")

    def add_entries(self, entries: list) -> dict:
        return self._post("/entries", {"entries": entries})

    def proofs_batch(self, hashes: list, tree_size: int) -> dict:
        return self._post("/proofs-batch",
                          {"hashes": hashes, "tree_size": tree_size})

    def lookup(self, name: str, image_line: str) -> list:
        from urllib.parse import quote
        return self._get("/lookup?name=%s&image_line=%s"
                         % (quote(name), quote(image_line)))["published"]
