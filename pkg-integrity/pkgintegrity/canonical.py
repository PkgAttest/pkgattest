"""Canonical pkg-integrity formats (SPEC.md sections 1, 2, 4, 6).

Byte-format twin of pkg-measurements.bbclass (build) and pkg-measure.sh
(target). The #1 integration risk of the project lives here — change all
three together.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field

from . import merkle


@dataclass
class PkgLeaf:
    name: str
    version: str
    arch: str
    files: list = field(default_factory=list)  # [(path, sha256hex)]

    def preimage(self) -> bytes:
        # UTF-8: python codepoint sort == LC_ALL=C byte sort (UTF-8 is
        # order-preserving), so all three implementations agree.
        lines = sorted("%s %s" % (p, h) for p, h in self.files)
        head = "pkg-leaf-v1\nname=%s\nversion=%s\narch=%s\nfiles=%d\n" % (
            self.name, self.version, self.arch, len(lines))
        return (head + "".join(l + "\n" for l in lines)).encode("utf-8")

    def leaf_hash(self) -> str:
        return hashlib.sha256(self.preimage()).hexdigest()


def parse_measurement_list(data: bytes) -> list:
    """Strict parser for the concatenated preimages; asserts byte-exact
    re-serialization so any drift is caught immediately."""
    text = data.decode("utf-8")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        if lines[i] != "pkg-leaf-v1":
            raise ValueError("expected pkg-leaf-v1 at line %d, got %r"
                             % (i + 1, lines[i][:40]))
        def want(prefix, j):
            if j >= n or not lines[j].startswith(prefix):
                raise ValueError("expected %r at line %d" % (prefix, j + 1))
            return lines[j][len(prefix):]
        name = want("name=", i + 1)
        version = want("version=", i + 2)
        arch = want("arch=", i + 3)
        count = int(want("files=", i + 4))
        files = []
        for k in range(count):
            line = lines[i + 5 + k]
            path, _, digest = line.rpartition(" ")
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or not path:
                raise ValueError("bad file line %r" % line[:80])
            files.append((path, digest))
        out.append(PkgLeaf(name, version, arch, files))
        i += 5 + count
    if b"".join(p.preimage() for p in out) != data:
        raise ValueError("measurement-list re-serialization mismatch")
    return out


def device_tree_root(pkgs: list) -> str:
    """pkg-merkle-v1 root over PkgLeaf list (must already be name-sorted)."""
    names = [p.name for p in pkgs]
    if names != sorted(names):
        raise ValueError("packages not in tree (name-sorted) order")
    return merkle.device_root([p.leaf_hash() for p in pkgs])


def log_leaf_data(image_line: str, name: str, version: str, arch: str,
                  pkg_leaf_hash: str) -> bytes:
    obj = {
        "arch": arch,
        "image_line": image_line,
        "name": name,
        "pkg_leaf_hash": pkg_leaf_hash,
        "schema": "log-leaf-v1",
        "version": version,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def load_measurements_json(path: str) -> dict:
    with open(path) as f:
        doc = json.load(f)
    if doc.get("schema") != "pkg-measurements-v1":
        raise ValueError("not a pkg-measurements-v1 document: %s" % path)
    return doc


def pkgs_from_measurements(doc: dict) -> list:
    return [
        PkgLeaf(p["name"], p["version"], p["arch"],
                [(e["path"], e["sha256"]) for e in p["files"]])
        for p in doc["packages"]
    ]


def verify_measurements_doc(doc: dict) -> list:
    """Recompute every leaf and the root; return problem strings (empty ==
    good). This is publish.py's hard gate against canonicalization drift."""
    problems = []
    pkgs = pkgs_from_measurements(doc)
    for pkg, rec in zip(pkgs, doc["packages"]):
        got = pkg.leaf_hash()
        if got != rec["leaf_hash"]:
            problems.append("leaf mismatch %s: doc %s != computed %s"
                            % (pkg.name, rec["leaf_hash"], got))
    root = merkle.device_root([p["leaf_hash"] for p in doc["packages"]])
    if root != doc["merkle_root"]:
        problems.append("root mismatch: doc %s != computed %s"
                        % (doc["merkle_root"], root))
    return problems


def abbrev(h: str) -> str:
    return h[:4] + "…" + h[-4:] if len(h) > 12 else h


def display_version(v: str) -> str:
    return re.sub(r"-r\d+$", "", v)
