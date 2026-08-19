import json
import os
import sys
import threading
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


def _record(i):
    return {"name": "pkg%d" % i, "version": "1.%d-r0" % i,
            "arch": "cortexa53-nocrypto", "image_line": "rpi3-openbmc",
            "pkg_leaf_hash": ("%02x" % i) * 32}


@pytest.fixture
def server(tmp_path):
    log_server.LOG = log_server.Log(str(tmp_path), KEY, PUB)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), log_server.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1], str(tmp_path)
    httpd.shutdown()


def test_publish_proofs_restart(server):
    url, store = server
    client = LogClient(url)
    pub = merkle.load_ed25519_public(PUB)

    sth0 = client.sth()
    assert merkle.verify_sth(pub, sth0)
    assert sth0["tree_size"] == 0

    result = client.add_entries([_record(i) for i in range(5)])
    assert result["added"] == 5
    sth1 = result["sth"]
    assert merkle.verify_sth(pub, sth1) and sth1["tree_size"] == 5

    # duplicates are deduped
    again = client.add_entries([_record(1)])
    assert again["added"] == 0 and again["duplicates"] == 1

    # inclusion proof round trip
    from pkgintegrity.canonical import log_leaf_data
    data = log_leaf_data("rpi3-openbmc", "pkg2", "1.2-r0",
                         "cortexa53-nocrypto", "02" * 32)
    lh = merkle.leaf_hash(data)
    proofs = client.proofs_batch([lh.hex()], sth1["tree_size"])["proofs"]
    proof = proofs[lh.hex()]
    assert proof is not None
    assert merkle.verify_inclusion(
        lh, proof["index"], sth1["tree_size"],
        [bytes.fromhex(x) for x in proof["path"]],
        bytes.fromhex(sth1["root_hash"]))

    # unknown leaf -> null proof
    unknown = client.proofs_batch(["ff" * 32], sth1["tree_size"])["proofs"]
    assert unknown["ff" * 32] is None

    # lookup
    published = client.lookup("pkg2", "rpi3-openbmc")
    assert published and published[0]["version"] == "1.2-r0"

    # restart from the same store: root must be byte-stable
    restarted = log_server.Log(store, KEY, PUB)
    assert restarted.tree.root().hex() == sth1["root_hash"]

    # consistency 0->5 is trivial; check 5->8 after more appends
    client.add_entries([_record(i) for i in range(5, 8)])
    sth2 = client.sth()
    tree = log_server.LOG.tree
    proof = tree.consistency_proof(5, 8)
    assert merkle.verify_consistency(
        5, 8, bytes.fromhex(sth1["root_hash"]),
        bytes.fromhex(sth2["root_hash"]), proof)

    # human page renders
    with urllib.request.urlopen(url + "/") as r:
        page = r.read().decode()
    assert "signed tree head" in page


def test_rejects_bad_record(server):
    url, _ = server
    client = LogClient(url)
    try:
        client.add_entries([{"name": "x"}])
        assert False, "should have raised"
    except Exception:
        pass
