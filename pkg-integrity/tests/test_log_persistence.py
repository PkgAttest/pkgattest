"""Regression tests for the transparency log's head persistence, append
atomicity, and write-path hardening.

The golden test at the bottom is the highest-value test in the project: it
pins the real published values so that no future change can silently
invalidate the demo's log, the device roots, or a published receipt.
"""

import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_server  # noqa: E402
from pkgintegrity import merkle  # noqa: E402
from pkgintegrity.logclient import LogClient  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(BASE, "keys", "log_ed25519.key")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
PROD_LOG = os.path.join(BASE, "log", "log.jsonl")
ART = os.path.join(BASE, "artifacts")

# The real published values. The log is append-only, so its SIZE grows as
# builds are published — but the head that image A was published under is
# immutable, and so is dropbear's index. Those are what the demo depends on.
HEAD_A_ROOT = "141332105f0e028bc77320f5460e6636abc799147024680fe75cd659b2bc0727"
HEAD_A_SIZE = 2131
HEAD_A_SIG = ("a24bbed774dbe5e91bd8b53c39d51f70ea15906111fbd57a4056173aeb898ba5"
              "0a3760dbacc1d0f0ace725ad1d4455d4ac7b59c98eadd8ff35f2907ae87bdd0f")
HEAD_A_TS = 1787153183
ROOT_A = "c923f7235a1f641c8744875a807181805a925ca5d394c5bc1543f0d0f3ed8d72"
PACKAGE_COUNT = 2131          # packages in image A, not the tree size
DROPBEAR_INDEX = 18


def _record(i):
    return {"name": "pkg%d" % i, "version": "1.%d-r0" % i,
            "arch": "cortexa53-nocrypto", "image_line": "rpi3-openbmc",
            "pkg_leaf_hash": ("%02x" % i) * 32}


def _open(store):
    return log_server.Log(store, KEY, PUB)


# --------------------------------------------------------------- persistence
def test_sth_stable_across_restarts(tmp_path):
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(5)])
    first = dict(log.sth)

    for _ in range(3):
        again = _open(store).sth
        assert again == first, "STH changed across restart"
    assert merkle.verify_sth(merkle.load_ed25519_public(PUB), first)


def test_sth_shape_is_identical_on_both_paths(tmp_path):
    """The served head must be exactly the four signed fields whether it was
    just signed or just loaded — otherwise /sth's shape depends on uptime."""
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(0)])
    signed = set(log.sth)
    loaded = set(_open(store).sth)
    assert signed == loaded == {"tree_size", "root_hash", "timestamp",
                                "signature"}


def test_history_only_grows_when_the_tree_changes(tmp_path):
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(3)])
    assert len(log.history) == 2          # genesis head + one append

    log.append([_record(0)])              # pure duplicate
    assert len(log.history) == 2, "duplicate-only append re-signed the head"

    _open(store)
    with open(os.path.join(store, "sth-history.jsonl")) as f:
        assert len(f.readlines()) == 2, "restart appended a redundant head"


def test_history_records_chain(tmp_path):
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(4)])
    recs = log.history
    assert recs[0]["prev_size"] == 0
    for prev, cur in zip(recs, recs[1:]):
        assert cur["prev_size"] == prev["tree_size"]
        assert cur["prev_root"] == prev["root_hash"]
        assert cur["timestamp"] > prev["timestamp"]
        assert cur["tree_size"] > prev["tree_size"]


def test_forked_head_refuses_to_start(tmp_path):
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(3)])

    # Same size, different root: the store has forked.
    hist = os.path.join(store, "sth-history.jsonl")
    recs = [json.loads(l) for l in open(hist)]
    recs[-1]["root_hash"] = "11" * 32
    with open(hist, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    with pytest.raises(log_server.ForkedHeadError):
        _open(store)


def test_head_ahead_of_log_refuses_to_start(tmp_path):
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(3)])
    hist = os.path.join(store, "sth-history.jsonl")
    recs = [json.loads(l) for l in open(hist)]
    recs[-1]["tree_size"] = 99
    with open(hist, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    with pytest.raises(log_server.ForkedHeadError):
        _open(store)


def test_short_history_signs_one_catch_up_head(tmp_path):
    """Crash between the log append and signing the head: recover, don't fork."""
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(i) for i in range(3)])
    hist = os.path.join(store, "sth-history.jsonl")
    recs = [json.loads(l) for l in open(hist)]
    with open(hist, "w") as f:                    # drop the latest head
        f.write(json.dumps(recs[0], sort_keys=True) + "\n")

    log2 = _open(store)
    assert log2.sth["tree_size"] == 3
    assert log2.sth["root_hash"] == log2.tree.root().hex()
    assert merkle.verify_sth(merkle.load_ed25519_public(PUB), log2.sth)


# ----------------------------------------------------------------- atomicity
def test_append_is_atomic_on_a_bad_record(tmp_path):
    """A malformed record must not leave earlier records of the same batch
    committed with an unsigned head — a stale /sth over a larger tree is the
    exact inconsistency this project exists to detect."""
    store = str(tmp_path)
    log = _open(store)
    log.append([_record(0)])
    before_size, before_sth = log.tree.size, dict(log.sth)

    with pytest.raises(ValueError):
        log.append([_record(1), {"name": "malformed"}])

    assert log.tree.size == before_size, "partial batch was committed"
    assert log.sth == before_sth
    assert log.sth["root_hash"] == log.tree.root().hex()
    with open(os.path.join(store, "log.jsonl")) as f:
        assert len(f.readlines()) == before_size

    reopened = _open(store)
    assert reopened.sth == before_sth
    assert reopened.tree.size == before_size


# ------------------------------------------------------------ write hardening
@pytest.fixture
def server(tmp_path):
    log_server.LOG = _open(str(tmp_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), log_server.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()


def _post(url, obj, headers=None):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(), method="POST",
        headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    return urllib.request.urlopen(req, timeout=10)


def _post_status(url, obj, headers=None):
    try:
        return _post(url, obj, headers).status
    except urllib.error.HTTPError as e:
        return e.code


def test_write_refused_when_read_only(server, monkeypatch):
    monkeypatch.setattr(log_server.Handler, "writable", False)
    assert _post_status(server + "/entries", {"entries": [_record(1)]}) == 403
    assert log_server.LOG.tree.size == 0


def test_cross_origin_write_refused(server):
    """A browser always sends Origin; the CLI never does. A CORS-simple POST
    from any page the user opens must not be able to append."""
    code = _post_status(server + "/entries", {"entries": [_record(1)]},
                        {"Origin": "https://evil.example"})
    assert code == 403
    assert log_server.LOG.tree.size == 0


def test_content_type_is_enforced(server):
    code = _post_status(server + "/entries", {"entries": [_record(1)]},
                        {"Content-Type": "text/plain"})
    assert code == 400
    assert log_server.LOG.tree.size == 0


def test_bearer_token_enforced(server, monkeypatch):
    monkeypatch.setattr(log_server.Handler, "auth_token", "s3cret")
    body = {"entries": [_record(1)]}
    assert _post_status(server + "/entries", body) == 401
    assert _post_status(server + "/entries", body,
                        {"Authorization": "Bearer wrong"}) == 401
    assert _post_status(server + "/entries", body,
                        {"Authorization": "Bearer s3cret"}) == 200
    assert log_server.LOG.tree.size == 1


def test_proofs_batch_is_capped(server):
    LogClient(server).add_entries([_record(i) for i in range(3)])
    hashes = ["%064x" % i for i in range(log_server.MAX_BATCH_HASHES + 1)]
    code = _post_status(server + "/proofs-batch",
                        {"hashes": hashes, "tree_size": 3})
    assert code == 413


def test_oversized_body_refused(server, monkeypatch):
    monkeypatch.setattr(log_server, "MAX_BODY", 2048)
    big = {"entries": [_record(0)], "pad": "x" * 4096}
    assert _post_status(server + "/entries", big) == 400
    assert log_server.LOG.tree.size == 0


def test_real_publication_payload_fits(server):
    """A full 2131-package publication must go through in one POST — a
    chunked publish would sign one head per chunk."""
    entries = [_record(i) for i in range(2131)]
    body = json.dumps({"entries": entries}).encode()
    assert len(body) < log_server.MAX_BODY
    assert _post_status(server + "/entries", {"entries": entries}) == 200
    assert log_server.LOG.tree.size == 2131
    assert len(log_server.LOG.history) == 2


def test_reads_are_unauthenticated(server):
    """The read path must stay open — the whole point is public verification."""
    with urllib.request.urlopen(server + "/sth", timeout=10) as r:
        assert json.load(r)["tree_size"] == 0


# -------------------------------------------------------------------- golden
@pytest.mark.skipif(not os.path.exists(PROD_LOG),
                    reason="production log store not present")
def test_production_log_golden(tmp_path):
    """Pin the real published values. If this fails the demo is broken: the
    head image A was published under, dropbear's index, or the append-only
    property has moved, and every published receipt and QR code is wrong.

    The tree SIZE is deliberately not pinned — the log is append-only and
    grows with each published build. What must never change is the historical
    head and the fact that the current tree still extends it."""
    store = str(tmp_path / "log")
    shutil.copytree(os.path.join(BASE, "log"), store)
    log = _open(store)
    pub = merkle.load_ed25519_public(PUB)

    # The current head is valid and at least as large as image A's.
    assert log.tree.size >= HEAD_A_SIZE
    assert log.sth["root_hash"] == log.tree.root().hex()
    assert merkle.verify_sth(pub, log.sth)
    assert _open(store).sth == log.sth, "reopening moved the head"

    # Image A's head is still in the history, byte-for-byte.
    head_a = next(h for h in log.history if h["tree_size"] == HEAD_A_SIZE)
    assert head_a["root_hash"] == HEAD_A_ROOT
    assert head_a["signature"] == HEAD_A_SIG
    assert head_a["timestamp"] == HEAD_A_TS
    assert merkle.verify_sth(pub, head_a)

    # Append-only: the current tree still reproduces that historical root,
    # and a proper RFC 6962 consistency proof connects the two.
    assert log.tree.root(HEAD_A_SIZE).hex() == HEAD_A_ROOT
    if log.tree.size > HEAD_A_SIZE:
        proof = log.tree.consistency_proof(HEAD_A_SIZE, log.tree.size)
        assert merkle.verify_consistency(
            HEAD_A_SIZE, log.tree.size, bytes.fromhex(HEAD_A_ROOT),
            bytes.fromhex(log.sth["root_hash"]), proof)

    # Every head in the history is signed and chains to its predecessor.
    for prev, cur in zip(log.history, log.history[1:]):
        assert merkle.verify_sth(pub, cur)
        assert cur["prev_root"] == prev["root_hash"]
        assert log.tree.root(cur["tree_size"]).hex() == cur["root_hash"]

    # dropbear is published at its known index, provable under BOTH heads.
    assert log.by_name[("rpi3-openbmc", "dropbear")] == [DROPBEAR_INDEX]
    leaf_str = log.entries[DROPBEAR_INDEX]
    assert json.loads(leaf_str)["version"] == "2026.92-r0"
    leaf = merkle.leaf_hash(leaf_str.encode())
    for size, root in ((HEAD_A_SIZE, HEAD_A_ROOT),
                       (log.tree.size, log.sth["root_hash"])):
        path = log.tree.inclusion_proof(DROPBEAR_INDEX, size)
        assert merkle.verify_inclusion(leaf, DROPBEAR_INDEX, size, path,
                                       bytes.fromhex(root))

    # And 2026.91 is still absent — the demo's whole point.
    versions = {json.loads(log.entries[i])["version"]
                for i in log.by_name[("rpi3-openbmc", "dropbear")]}
    assert "2026.91-r0" not in versions


@pytest.mark.skipif(
    not os.path.exists(os.path.join(
        ART, "A", "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")),
    reason="built artifacts not present")
def test_image_a_device_root_golden():
    from pkgintegrity import canonical
    doc = canonical.load_measurements_json(os.path.join(
        ART, "A", "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json"))
    assert doc["merkle_root"] == ROOT_A
    assert len(doc["packages"]) == PACKAGE_COUNT
    assert canonical.verify_measurements_doc(doc) == []


@pytest.mark.skipif(
    not os.path.exists(os.path.join(ART, "A", "publication-receipt.json")),
    reason="publication receipt not present")
def test_publication_receipt_still_verifies():
    with open(os.path.join(ART, "A", "publication-receipt.json")) as f:
        receipt = json.load(f)
    assert receipt["merkle_root"] == ROOT_A
    assert receipt["package_count"] == PACKAGE_COUNT
    assert merkle.verify_sth(merkle.load_ed25519_public(PUB), receipt["sth"])
    assert receipt["sth"]["signature"] == HEAD_A_SIG
