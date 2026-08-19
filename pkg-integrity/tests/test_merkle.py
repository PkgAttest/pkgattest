import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import merkle


# Independent recursive RFC 6962 MTH implementation for cross-checking.
def mth(entries):
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + mth(entries[:k]) + mth(entries[k:])
                          ).digest()


ENTRIES = [bytes([i]) * (i % 7 + 1) for i in range(64)]


def build(n):
    t = merkle.MerkleTree()
    for e in ENTRIES[:n]:
        t.append_data(e)
    return t


def test_empty_root():
    assert merkle.MerkleTree().root().hex() == hashlib.sha256(b"").hexdigest()


def test_roots_match_reference():
    for n in range(1, 65):
        assert build(n).root() == mth(ENTRIES[:n]), "n=%d" % n


def test_inclusion_proofs_all_sizes():
    t = build(64)
    for size in (1, 2, 3, 7, 8, 33, 64):
        root = t.root(size)
        for idx in range(size):
            path = t.inclusion_proof(idx, size)
            leaf = merkle.leaf_hash(ENTRIES[idx])
            assert merkle.verify_inclusion(leaf, idx, size, path, root), \
                "idx=%d size=%d" % (idx, size)
            # tampered leaf must fail
            bad = merkle.leaf_hash(ENTRIES[idx] + b"x")
            assert not merkle.verify_inclusion(bad, idx, size, path, root)


def test_consistency_proofs():
    t = build(64)
    for old in (1, 2, 3, 7, 8, 33):
        for new in (old, old + 1, 48, 64):
            if new < old:
                continue
            proof = t.consistency_proof(old, new)
            assert merkle.verify_consistency(
                old, new, t.root(old), t.root(new), proof), \
                "old=%d new=%d" % (old, new)
            if old != new:
                assert not merkle.verify_consistency(
                    old, new, t.root(old),
                    hashlib.sha256(b"junk").digest(), proof)


def test_device_tree():
    leaves = [hashlib.sha256(bytes([i])).hexdigest() for i in range(5)]
    # manual: ((0,1),(2,3)) then pair with promoted 4
    n01 = merkle.device_node_hash(leaves[0], leaves[1])
    n23 = merkle.device_node_hash(leaves[2], leaves[3])
    n0123 = merkle.device_node_hash(n01, n23)
    expected = merkle.device_node_hash(n0123, leaves[4])
    assert merkle.device_root(leaves) == expected
    assert merkle.device_root([leaves[0]]) == leaves[0]


def test_sth_sign_verify(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    key = Ed25519PrivateKey.generate()
    sth = merkle.sign_sth(key, 42, "ab" * 32, 1700000000)
    assert merkle.verify_sth(key.public_key(), sth)
    sth["tree_size"] = 43
    assert not merkle.verify_sth(key.public_key(), sth)
