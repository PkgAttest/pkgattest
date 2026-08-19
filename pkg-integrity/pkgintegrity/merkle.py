"""Merkle machinery for pkg-integrity (SPEC.md sections 2 and 4).

Two distinct trees:

* device tree (``pkg-merkle-v1``): hex/text construction recomputable with
  busybox sha256sum on the BMC — leaves sorted by package name, node =
  sha256(b"pkg-node-v1\\n<Lhex>\\n<Rhex>\\n"), odd node promoted.

* log tree: RFC 6962 proper — leaf = sha256(0x00 || data), node =
  sha256(0x01 || l || r), split at largest power of two < n, with inclusion
  and consistency proofs and an Ed25519-signed tree head.
"""

import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# --------------------------------------------------------------------------
# Device tree (pkg-merkle-v1)
# --------------------------------------------------------------------------


def device_node_hash(left_hex: str, right_hex: str) -> str:
    data = "pkg-node-v1\n%s\n%s\n" % (left_hex, right_hex)
    return hashlib.sha256(data.encode("ascii")).hexdigest()


def device_root(leaves_hex: list) -> str:
    """pkg-merkle-v1 root over leaf hashes (hex), odd node promoted."""
    if not leaves_hex:
        raise ValueError("empty leaf set")
    level = list(leaves_hex)
    while len(level) > 1:
        nxt = [
            device_node_hash(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def expected_pcr14(root_hex: str) -> str:
    """PCR14 after a single sha256-bank extend of the root from reset."""
    return hashlib.sha256(b"\x00" * 32 + bytes.fromhex(root_hex)).hexdigest()


# --------------------------------------------------------------------------
# Log tree (RFC 6962)
# --------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_lt(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class MerkleTree:
    """Append-only RFC 6962 tree over leaf *data* bytes."""

    def __init__(self):
        self.leaves = []  # leaf hashes (bytes)

    @property
    def size(self) -> int:
        return len(self.leaves)

    def append_data(self, data: bytes) -> int:
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def _subtree(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return self.leaves[lo]
        k = _largest_power_of_two_lt(n)
        return node_hash(self._subtree(lo, lo + k), self._subtree(lo + k, hi))

    def root(self, size: int = None) -> bytes:
        size = self.size if size is None else size
        if size == 0:
            return hashlib.sha256(b"").digest()
        if size > self.size:
            raise ValueError("size beyond tree")
        return self._subtree(0, size)

    def inclusion_proof(self, index: int, size: int = None) -> list:
        """Audit path for leaf `index` in the size-`size` tree (RFC 6962)."""
        size = self.size if size is None else size
        if not (0 <= index < size <= self.size):
            raise ValueError("bad index/size")

        def path(m, lo, hi):
            n = hi - lo
            if n == 1:
                return []
            k = _largest_power_of_two_lt(n)
            if m < k:
                return path(m, lo, lo + k) + [self._subtree(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self._subtree(lo, lo + k)]

        return path(index, 0, size)

    def consistency_proof(self, old_size: int, new_size: int = None) -> list:
        new_size = self.size if new_size is None else new_size
        if not (0 < old_size <= new_size <= self.size):
            raise ValueError("bad sizes")

        def subproof(m, lo, hi, complete):
            n = hi - lo
            if m == n:
                return [] if complete else [self._subtree(lo, hi)]
            k = _largest_power_of_two_lt(n)
            if m <= k:
                return subproof(m, lo, lo + k, complete) + [
                    self._subtree(lo + k, hi)
                ]
            return subproof(m - k, lo + k, hi, False) + [
                self._subtree(lo, lo + k)
            ]

        if old_size == new_size:
            return []
        return subproof(old_size, 0, new_size, True)


def verify_inclusion(leaf: bytes, index: int, size: int, path: list,
                     root: bytes) -> bool:
    """RFC 6962 sec 2.1.1 verification (leaf = leaf hash bytes)."""
    if index >= size:
        return False
    h = leaf
    fn, sn = index, size - 1
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            h = node_hash(p, h)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            h = node_hash(h, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and h == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes,
                       new_root: bytes, proof: list) -> bool:
    """RFC 6962 sec 2.1.2 consistency verification."""
    if old_size == new_size:
        return not proof and old_root == new_root
    if not (0 < old_size < new_size):
        return False
    proof = list(proof)
    if old_size == (old_size & -old_size):  # power of two
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for p in proof[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(p, fr)
            sr = node_hash(p, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


# --------------------------------------------------------------------------
# Signed tree head
# --------------------------------------------------------------------------


def sth_payload(size: int, root_hex: str, timestamp: int) -> bytes:
    return ("pkg-log-sth-v1 %d %s %d\n" % (size, root_hex, timestamp)).encode(
        "ascii"
    )


def sign_sth(private_key: Ed25519PrivateKey, size: int, root_hex: str,
             timestamp: int = None) -> dict:
    timestamp = int(time.time()) if timestamp is None else timestamp
    sig = private_key.sign(sth_payload(size, root_hex, timestamp))
    return {
        "tree_size": size,
        "root_hash": root_hex,
        "timestamp": timestamp,
        "signature": sig.hex(),
    }


def verify_sth(public_key: Ed25519PublicKey, sth: dict) -> bool:
    try:
        public_key.verify(
            bytes.fromhex(sth["signature"]),
            sth_payload(sth["tree_size"], sth["root_hash"],
                        sth["timestamp"]),
        )
        return True
    except Exception:
        return False


def load_ed25519_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ed25519_public(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
