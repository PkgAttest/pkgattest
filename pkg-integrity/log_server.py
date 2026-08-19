#!/usr/bin/env python3
"""Minimal RFC-6962-style transparency log for package publication records.

Stdlib HTTP server (offline reliability — nothing beyond `cryptography` on
the serving path). Storage: append-only log/log.jsonl of canonical leaf
strings; the tree is rebuilt on start, so the root is byte-stable across
restarts.

Endpoints:
  GET  /sth                                signed tree head (+ pubkey PEM)
  POST /entries        {"entries":[{...}]} append records, returns new STH
  GET  /proof-by-hash?hash=&tree_size=     one inclusion proof
  POST /proofs-batch   {"hashes":[],"tree_size":N}
  GET  /lookup?name=&image_line=           published versions of a package
  GET  /                                   human page (QR target)
"""

import argparse
import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity import merkle  # noqa: E402
from pkgintegrity.canonical import log_leaf_data  # noqa: E402

REQUIRED_FIELDS = ("arch", "image_line", "name", "pkg_leaf_hash", "version")


class Log:
    def __init__(self, store_dir, key_path, pub_path):
        self.lock = threading.Lock()
        self.store = os.path.join(store_dir, "log.jsonl")
        self.sth_file = os.path.join(store_dir, "sth.json")
        self.key = merkle.load_ed25519_private(key_path)
        with open(pub_path) as f:
            self.pub_pem = f.read()
        self.tree = merkle.MerkleTree()
        self.entries = []          # canonical leaf strings
        self.by_leaf_hash = {}     # rfc6962 leaf hash hex -> index
        self.by_name = {}          # (image_line, name) -> [index]
        os.makedirs(store_dir, exist_ok=True)
        if os.path.exists(self.store):
            with open(self.store) as f:
                for line in f:
                    rec = json.loads(line)
                    self._add_to_tree(rec["leaf"])
        self.sth = self._sign_sth()
        self._write_sth()

    def _add_to_tree(self, leaf_str):
        data = leaf_str.encode("ascii")
        idx = self.tree.append_data(data)
        self.entries.append(leaf_str)
        lh = merkle.leaf_hash(data).hex()
        self.by_leaf_hash[lh] = idx
        obj = json.loads(leaf_str)
        self.by_name.setdefault((obj["image_line"], obj["name"]),
                                []).append(idx)
        return idx

    def _sign_sth(self):
        return merkle.sign_sth(self.key, self.tree.size,
                               self.tree.root().hex())

    def _write_sth(self):
        with open(self.sth_file, "w") as f:
            json.dump(self.sth, f, indent=1)

    def append(self, records):
        added, duplicates = 0, 0
        with self.lock:
            with open(self.store, "a") as f:
                for obj in records:
                    missing = [k for k in REQUIRED_FIELDS if k not in obj]
                    if missing:
                        raise ValueError("record missing %s" % missing)
                    leaf_str = log_leaf_data(
                        obj["image_line"], obj["name"], obj["version"],
                        obj["arch"], obj["pkg_leaf_hash"]).decode("ascii")
                    lh = merkle.leaf_hash(leaf_str.encode("ascii")).hex()
                    if lh in self.by_leaf_hash:
                        duplicates += 1
                        continue
                    idx = self._add_to_tree(leaf_str)
                    f.write(json.dumps({"index": idx, "leaf": leaf_str}) + "\n")
                    added += 1
            self.sth = self._sign_sth()
            self._write_sth()
        return added, duplicates

    def proof(self, leaf_hash_hex, tree_size):
        with self.lock:
            idx = self.by_leaf_hash.get(leaf_hash_hex)
            if idx is None or idx >= tree_size or tree_size > self.tree.size:
                return None
            path = self.tree.inclusion_proof(idx, tree_size)
        return {"index": idx, "path": [p.hex() for p in path]}

    def lookup(self, image_line, name):
        with self.lock:
            idxs = self.by_name.get((image_line, name), [])
            out = []
            for i in idxs:
                obj = json.loads(self.entries[i])
                out.append({"version": obj["version"], "arch": obj["arch"],
                            "pkg_leaf_hash": obj["pkg_leaf_hash"],
                            "leaf_index": i})
        return out


LOG = None


class Handler(BaseHTTPRequestHandler):
    server_version = "pkg-log/1"

    def _json(self, code, obj):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 64 * 1024 * 1024:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(length))

    def log_message(self, fmt, *args):  # quiet
        pass

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/sth":
            sth = dict(LOG.sth)
            sth["pubkey"] = LOG.pub_pem
            self._json(200, sth)
        elif url.path == "/proof-by-hash":
            try:
                proof = LOG.proof(q["hash"][0], int(q["tree_size"][0]))
            except (KeyError, ValueError):
                return self._json(400, {"error": "hash and tree_size required"})
            if proof is None:
                return self._json(404, {"error": "leaf not found"})
            self._json(200, proof)
        elif url.path == "/lookup":
            try:
                name = q["name"][0]
                image_line = q["image_line"][0]
            except KeyError:
                return self._json(400,
                                  {"error": "name and image_line required"})
            self._json(200, {"published": LOG.lookup(image_line, name)})
        elif url.path == "/":
            sth = LOG.sth
            page = (
                "pkg-integrity transparency log\n"
                "==============================\n\n"
                "signed tree head:\n"
                "  tree_size  %d\n  root_hash  %s\n  timestamp  %d\n"
                "  signature  %s\n\nverify (python):\n"
                "  payload = b'pkg-log-sth-v1 %d %s %d\\n'\n"
                "  Ed25519(pubkey).verify(bytes.fromhex(signature), payload)\n"
                "\npubkey (PEM):\n%s\n"
                "endpoints: /sth /lookup?name=&image_line= "
                "/proof-by-hash?hash=&tree_size=\n"
                % (sth["tree_size"], sth["root_hash"], sth["timestamp"],
                   sth["signature"], sth["tree_size"], sth["root_hash"],
                   sth["timestamp"], LOG.pub_pem))
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "unknown path"})

    def do_POST(self):
        url = urlparse(self.path)
        try:
            body = self._read_body()
        except Exception as e:
            return self._json(400, {"error": str(e)})
        if url.path == "/entries":
            try:
                added, dup = LOG.append(body.get("entries", []))
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            self._json(200, {"added": added, "duplicates": dup,
                             "sth": LOG.sth})
        elif url.path == "/proofs-batch":
            try:
                size = int(body["tree_size"])
                hashes = body["hashes"]
            except (KeyError, ValueError):
                return self._json(400,
                                  {"error": "hashes and tree_size required"})
            proofs = {h: LOG.proof(h, size) for h in hashes}
            self._json(200, {"proofs": proofs})
        else:
            self._json(404, {"error": "unknown path"})


def main():
    global LOG
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--store", default=os.path.join(base, "log"))
    ap.add_argument("--key", default=os.path.join(base, "keys",
                                                  "log_ed25519.key"))
    ap.add_argument("--pub", default=os.path.join(base, "keys",
                                                  "log_ed25519.pub"))
    args = ap.parse_args()
    LOG = Log(args.store, args.key, args.pub)
    print("pkg-log: %d entries, root %s, listening on %s:%d"
          % (LOG.tree.size, LOG.tree.root().hex()[:16], args.bind, args.port))
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
