"""Prove the browser verifier (site/verify.js) agrees with the Python one.

The site's whole claim is that the reader's browser — not a server — does the
verification. That claim is only worth anything if the JS reproduces
pkgintegrity/{merkle,canonical}.py byte for byte, so this generates vectors
from the real data and re-derives every one of them under node.

node is a *test* dependency only: nothing at runtime needs it, CI does not
install it, and these tests skip when it is absent. The golden vectors are
written next to the test so a reviewer can diff them without running anything.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical, merkle  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARITY_JS = os.path.join(BASE, "tools", "parity.js")
VERIFY_JS = os.path.join(BASE, "site", "verify.js")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
LOG_STORE = os.path.join(BASE, "log", "log.jsonl")
HISTORY = os.path.join(BASE, "log", "sth-history.jsonl")
MEAS_A = os.path.join(
    BASE, "artifacts", "A",
    "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")

NODE = shutil.which("node")

requires_node = pytest.mark.skipif(
    NODE is None or not os.path.exists(VERIFY_JS),
    reason="node (test-only dependency) or site/verify.js not present")


def _pubkey_raw_hex():
    from cryptography.hazmat.primitives import serialization
    pub = merkle.load_ed25519_public(PUB)
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw).hex()


def _synthetic_mth_vectors():
    """RFC 6962 sizes that catch a careless port: n=1 (the `1 << -1` trap),
    n=2, the odd cases where the split is not in the middle, and the real
    tree size."""
    out = []
    for n in (1, 2, 3, 5, 6, 7, 8, 2048, 2049, 2131):
        leaves = [hashlib.sha256(b"leaf-%d" % i).digest() for i in range(n)]
        tree = merkle.MerkleTree()
        tree.leaves = list(leaves)
        out.append({"n": n, "leaves": [b.hex() for b in leaves],
                    "root": tree.root(n).hex()})
    return out


def build_vectors(limit_packages=None):
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}

    # Every package of image A, so the ca-certificates UTF-8 path is covered.
    if os.path.exists(MEAS_A):
        doc = canonical.load_measurements_json(MEAS_A)
        pkgs = doc["packages"]
        if limit_packages:
            names = {"ca-certificates", "dropbear", "systemd", "os-release"}
            pkgs = ([p for p in pkgs if p["name"] in names]
                    + pkgs[:limit_packages])
        vectors["packages"] = [
            {"name": p["name"], "version": p["version"], "arch": p["arch"],
             "files": [{"path": f["path"], "sha256": f["sha256"]}
                       for f in p["files"]],
             "preimage_hex": canonical.PkgLeaf(
                 p["name"], p["version"], p["arch"],
                 [(f["path"], f["sha256"]) for f in p["files"]]
             ).preimage().hex(),
             "leaf_hash": p["leaf_hash"]}
            for p in pkgs]
        vectors["device_trees"] = [{
            "label": "image-A",
            "leaf_hashes": [p["leaf_hash"] for p in doc["packages"]],
            "root": doc["merkle_root"],
            "pcr14": merkle.expected_pcr14(doc["merkle_root"]),
        }]

    if os.path.exists(LOG_STORE):
        records, leaf_hashes = [], []
        with open(LOG_STORE) as f:
            for i, line in enumerate(f):
                leaf_str = json.loads(line)["leaf"]
                obj = json.loads(leaf_str)
                data = canonical.log_leaf_data(
                    obj["image_line"], obj["name"], obj["version"],
                    obj["arch"], obj["pkg_leaf_hash"])
                assert data.decode() == leaf_str, "store is not canonical"
                records.append({
                    "index": i, "arch": obj["arch"],
                    "image_line": obj["image_line"], "name": obj["name"],
                    "version": obj["version"],
                    "pkg_leaf_hash": obj["pkg_leaf_hash"],
                    "data_hex": data.hex(),
                    "leaf_hash": merkle.leaf_hash(data).hex()})
                leaf_hashes.append(merkle.leaf_hash(data))
        vectors["log_records"] = records

        tree = merkle.MerkleTree()
        tree.leaves = list(leaf_hashes)

        heads = []
        if os.path.exists(HISTORY):
            with open(HISTORY) as f:
                heads = [json.loads(line) for line in f if line.strip()]
        vectors["heads"] = [
            {k: h[k] for k in
             ("tree_size", "root_hash", "timestamp", "signature")}
            for h in heads]

        size = tree.size
        sample = sorted({0, 1, 18, size // 2, size - 1})
        vectors["inclusion"] = [
            {"index": i, "tree_size": size,
             "path": [p.hex() for p in tree.inclusion_proof(i, size)],
             "root": tree.root(size).hex()}
            for i in sample if i < size]

        vectors["consistency"] = [
            {"old_size": h["tree_size"], "new_size": size,
             "old_root": h["root_hash"], "new_root": tree.root(size).hex(),
             "proof": [p.hex() for p in
                       tree.consistency_proof(h["tree_size"], size)]}
            for h in heads if 0 < h["tree_size"] < size]

    return vectors


def _run_parity(vectors, tmp_path):
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps(vectors))
    proc = subprocess.run([NODE, PARITY_JS, str(path)],
                          capture_output=True, text=True, timeout=300)
    return proc


@requires_node
def test_js_matches_python_on_real_data(tmp_path):
    vectors = build_vectors()
    if not vectors.get("log_records"):
        pytest.skip("no production log store to compare against")
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "parity OK" in proc.stdout


@requires_node
def test_js_matches_python_on_synthetic_vectors(tmp_path):
    """Runs with no built artifacts — the case a fresh clone hits."""
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_node
def test_parity_harness_detects_a_mismatch(tmp_path):
    """The parity test must be able to fail — a harness that always passes
    proves nothing."""
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}
    vectors["mth_sizes"][0]["root"] = "00" * 32
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 1
    assert "PARITY FAILED" in proc.stdout


@requires_node
def test_utf8_path_is_the_live_trap(tmp_path):
    """Encoding, not sorting, is what breaks: the one non-ASCII path in the
    image must hash as UTF-8, not via charCode truncation."""
    p = ("/usr/share/ca-certificates/mozilla/"
         "NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt")
    assert hashlib.sha256(p.encode("utf-8")).hexdigest().startswith(
        "ebca1496dd1a66c2ddf84eee")
    wrong = hashlib.sha256(bytes(ord(c) & 0xFF for c in p)).hexdigest()
    assert not wrong.startswith("ebca1496")

    script = (
        "const V=require(%s);"
        "const p=%s;"
        "console.log(V.hex(V.sha256(V.utf8(p))));"
        % (json.dumps(VERIFY_JS), json.dumps(p)))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == hashlib.sha256(p.encode("utf-8")).hexdigest()


@requires_node
def test_utf8_byte_sort_not_utf16(tmp_path):
    """Array.sort() ranks by UTF-16 code unit and disagrees with Python's
    codepoint order for astral characters. No such path exists in today's
    image, which is precisely why the comparator must be tested directly."""
    items = ["a\U0001F600b", "aﬀb", "aÿb"]
    expected = sorted(items)          # Python codepoint order
    script = (
        "const V=require(%s);"
        "const it=%s;"
        "console.log(JSON.stringify(it.slice().sort(V.compareUtf8)));"
        "console.log(JSON.stringify(it.slice().sort()));"
        % (json.dumps(VERIFY_JS), json.dumps(items)))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    utf8_sorted, naive_sorted = proc.stdout.strip().splitlines()
    assert json.loads(utf8_sorted) == expected
    # And prove the naive sort really would have differed.
    assert json.loads(naive_sorted) != expected


@requires_node
def test_vendored_crypto_is_reproducible():
    """The committed vendor bundle must be exactly what the pinned upstream
    sources regenerate — offline, no network."""
    proc = subprocess.run(
        [sys.executable, os.path.join(BASE, "tools", "vendor_crypto.py"),
         "--check"], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check-vendor: OK" in proc.stdout
