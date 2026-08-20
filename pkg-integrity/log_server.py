#!/usr/bin/env python3
"""Minimal RFC-6962-style transparency log for package publication records.

Stdlib HTTP server (offline reliability — nothing beyond `cryptography` on
the serving path).

Storage:
  log/log.jsonl           append-only canonical leaf strings; the tree is
                          rebuilt from this on start
  log/sth-history.jsonl   every signed tree head, append-only
  log/sth.json            the current head (a cache of the last history record)

The head is LOADED on start, never re-signed: re-signing an unchanged tree
would change its signature and timestamp, invalidating every publication
receipt and any citable snapshot. A stored head whose root disagrees with
the rebuilt tree is a fork, and the server refuses to start.

Reads are open — public verification is the point. Writes are off unless
--writable, are refused when an Origin header is present (a browser always
sends one, the CLI never does), and may require a bearer token.

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
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity import merkle  # noqa: E402
from pkgintegrity.canonical import log_leaf_data  # noqa: E402

REQUIRED_FIELDS = ("arch", "image_line", "name", "pkg_leaf_hash", "version")

# Request limits. The write path is localhost-only by default; these caps stop
# a lying Content-Length from exhausting memory and an unbounded proof batch
# from monopolising the tree. (Handler.timeout bounds how long a lying
# Content-Length can pin a thread.)
#
# 8 MiB, not 1: publishing this image's 2131 packages is already a 519 KB
# POST, and a larger image line must not hit the ceiling mid-publication.
# Chunking instead would sign one head per chunk and pollute the history.
MAX_BODY = 8 << 20          # 8 MiB
MAX_BATCH_HASHES = 256


class ForkedHeadError(RuntimeError):
    """The stored tree head does not match the tree rebuilt from log.jsonl."""


def _key_id(pub_pem: str) -> str:
    """sha256 over the SPKI DER — the value to pin out of band."""
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pub_pem.encode())
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _write_atomic(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


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
        self.history_file = os.path.join(store_dir, "sth-history.jsonl")
        self.key_id = _key_id(self.pub_pem)
        os.makedirs(store_dir, exist_ok=True)
        if os.path.exists(self.store):
            with open(self.store) as f:
                for line in f:
                    rec = json.loads(line)
                    self._add_to_tree(rec["leaf"])
        self.history = self._read_history()
        self.sth = self._adopt_head()
        self._write_sth()

    # -- signed tree head persistence -------------------------------------
    # The head is LOADED, never re-signed on start: re-signing would change
    # the signature and timestamp of an unchanged tree, invalidating every
    # published receipt and any citable snapshot. Signing happens only in
    # append(), under the lock.

    def _pub(self):
        """Public key from the in-memory PEM (merkle.py loads from a path;
        it is frozen, so the PEM-string loader lives here)."""
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(self.pub_pem.encode())

    def _read_history(self):
        if not os.path.exists(self.history_file):
            return []
        with open(self.history_file) as f:
            return [json.loads(line) for line in f if line.strip()]

    def _append_history(self, sth):
        """Persist an enriched history record; return the plain signed head.

        The served STH must always be exactly the four signed fields, in
        every code path — anything else and the head's shape depends on
        whether the server just started or just appended.
        """
        sth = {k: sth[k] for k in
               ("tree_size", "root_hash", "timestamp", "signature")}
        rec = dict(sth)
        rec["schema"] = "sth-v1"
        rec["seq"] = len(self.history)
        rec["key_id"] = self.key_id
        prev = self.history[-1] if self.history else None
        rec["prev_size"] = prev["tree_size"] if prev else 0
        rec["prev_root"] = (prev["root_hash"] if prev
                            else hashlib.sha256(b"").hexdigest())
        with open(self.history_file, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.history.append(rec)
        return sth

    def _adopt_head(self):
        """Reuse the stored head when it matches the rebuilt tree."""
        size, root = self.tree.size, self.tree.root().hex()

        candidate = self.history[-1] if self.history else None
        if candidate is None and os.path.exists(self.sth_file):
            # Pre-history store: adopt sth.json and backfill the history.
            with open(self.sth_file) as f:
                candidate = json.load(f)
            if (candidate.get("tree_size") == size
                    and candidate.get("root_hash") == root
                    and merkle.verify_sth(self._pub(), candidate)):
                return self._append_history(
                    {k: candidate[k] for k in
                     ("tree_size", "root_hash", "timestamp", "signature")})
            candidate = None

        if candidate is not None:
            if candidate["tree_size"] == size:
                if candidate["root_hash"] != root:
                    raise ForkedHeadError(
                        "stored head at size %d has root %s but log.jsonl "
                        "rebuilds to %s — refusing to start"
                        % (size, candidate["root_hash"], root))
                return {k: candidate[k] for k in
                        ("tree_size", "root_hash", "timestamp", "signature")}
            if candidate["tree_size"] > size:
                raise ForkedHeadError(
                    "stored head is ahead of the log (%d > %d) — refusing "
                    "to start" % (candidate["tree_size"], size))
            # History is short (crash between log append and head signing):
            # sign exactly one catch-up head.

        return self._append_history(self._sign_head())

    def _sign_head(self):
        prev = self.history[-1] if self.history else None
        ts = int(time.time())
        if prev is not None:
            ts = max(ts, prev["timestamp"] + 1)
        return merkle.sign_sth(self.key, self.tree.size,
                               self.tree.root().hex(), ts)

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

    def _write_sth(self):
        _write_atomic(self.sth_file, json.dumps(self.sth, indent=1))

    def append(self, records):
        # Validate the WHOLE batch before mutating anything. Raising midway
        # through the loop used to leave earlier records committed to both
        # the tree and log.jsonl while the head went unsigned — /sth would
        # then serve a stale head over a larger tree, which is precisely the
        # inconsistency this project exists to detect.
        leaves = []
        for obj in records:
            missing = [k for k in REQUIRED_FIELDS if k not in obj]
            if missing:
                raise ValueError("record missing %s" % missing)
            leaves.append(log_leaf_data(
                obj["image_line"], obj["name"], obj["version"],
                obj["arch"], obj["pkg_leaf_hash"]).decode("ascii"))

        added, duplicates = 0, 0
        with self.lock:
            seen = set()
            with open(self.store, "a") as f:
                for leaf_str in leaves:
                    lh = merkle.leaf_hash(leaf_str.encode("ascii")).hex()
                    if lh in self.by_leaf_hash or lh in seen:
                        duplicates += 1
                        continue
                    seen.add(lh)
                    idx = self._add_to_tree(leaf_str)
                    f.write(json.dumps({"index": idx, "leaf": leaf_str}) + "\n")
                    added += 1
                f.flush()
                os.fsync(f.fileno())
            if added:
                self.sth = self._append_history(self._sign_head())
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
    timeout = 10

    # Set by main(); tests drive the Handler directly and keep the defaults.
    writable = True
    auth_token = None

    def _json(self, code, obj):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            raise ValueError("body too large")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            raise ValueError("Content-Type must be application/json")
        return json.loads(self.rfile.read(length))

    def _write_allowed(self):
        """Guard the append path.

        A browser can issue a cross-origin CORS-simple POST without a
        preflight, and DNS rebinding reaches 127.0.0.1 — so a page an
        attendee merely opens could otherwise append to the log. The CLI
        never sends Origin; a browser always does.
        """
        if not self.writable:
            return (403, "server is read-only (start with --writable)")
        if self.headers.get("Origin") is not None:
            return (403, "cross-origin writes are refused")
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "[::1]", "::1", ""):
            return (403, "unexpected Host header")
        if self.auth_token is not None:
            sent = self.headers.get("Authorization", "")
            prefix = "Bearer "
            ok = sent.startswith(prefix) and hmac.compare_digest(
                sent[len(prefix):], self.auth_token)
            if not ok:
                return (401, "bad or missing bearer token")
        return None

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
            denied = self._write_allowed()
            if denied:
                return self._json(denied[0], {"error": denied[1]})
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
            if not isinstance(hashes, list):
                return self._json(400, {"error": "hashes must be a list"})
            if len(hashes) > MAX_BATCH_HASHES:
                return self._json(
                    413, {"error": "at most %d hashes per batch"
                          % MAX_BATCH_HASHES})
            proofs = {h: LOG.proof(h, size) for h in hashes}
            self._json(200, {"proofs": proofs})
        else:
            self._json(404, {"error": "unknown path"})


def main():
    global LOG
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8799)
    # Localhost by default: http.server is not an internet-facing server and
    # must never be reachable from a conference network.
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--store", default=os.path.join(base, "log"))
    ap.add_argument("--key", default=os.path.join(base, "keys",
                                                  "log_ed25519.key"))
    ap.add_argument("--pub", default=os.path.join(base, "keys",
                                                  "log_ed25519.pub"))
    ap.add_argument("--writable", action="store_true",
                    help="allow POST /entries (off by default)")
    ap.add_argument("--token-file", default=None,
                    help="file holding a bearer token required for writes "
                         "(never pass a token in argv — ps is public)")
    args = ap.parse_args()

    Handler.writable = args.writable
    if args.token_file:
        with open(args.token_file) as f:
            Handler.auth_token = f.read().strip()

    try:
        LOG = Log(args.store, args.key, args.pub)
    except ForkedHeadError as e:
        print("pkg-log: FATAL: %s" % e, file=sys.stderr)
        return 2
    print("pkg-log: %d entries, root %s, head ts %d, key %s, %s, "
          "listening on %s:%d"
          % (LOG.tree.size, LOG.tree.root().hex()[:16], LOG.sth["timestamp"],
             LOG.key_id[:14], "writable" if args.writable else "read-only",
             args.bind, args.port))
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
