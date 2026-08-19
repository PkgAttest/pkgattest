import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical, merkle  # noqa: E402


def make_measurements_doc(n_pkgs=6, with_dropbear=True):
    """Synthetic pkg-measurements-v1 document (deterministic)."""
    pkgs = []
    names = sorted(
        (["dropbear"] if with_dropbear else [])
        + ["bash", "busybox", "libssl3", "systemd", "zlib"][: n_pkgs - 1])
    for name in names:
        files = []
        for i in range(3):
            path = "/usr/bin/%s-%d" % (name, i)
            digest = hashlib.sha256(("content:%s:%d" % (name, i)).encode()
                                    ).hexdigest()
            files.append({"path": path, "sha256": digest})
        version = "2026.92-r0" if name == "dropbear" else "1.0-r0"
        leaf = canonical.PkgLeaf(name, version, "cortexa53-nocrypto",
                                 [(f["path"], f["sha256"]) for f in files])
        pkgs.append({"name": name, "version": version,
                     "arch": "cortexa53-nocrypto",
                     "leaf_hash": leaf.leaf_hash(), "files": files})
    root = merkle.device_root([p["leaf_hash"] for p in pkgs])
    return {
        "schema": "pkg-measurements-v1",
        "image_line": "rpi3-openbmc",
        "machine": "raspberrypi3-64",
        "image_name": "obmc-phosphor-image-test",
        "version": "test",
        "timestamp": "20260101000000",
        "merkle_root": root,
        "packages": pkgs,
    }


@pytest.fixture
def measurements_doc():
    return make_measurements_doc()


@pytest.fixture
def measurements_file(tmp_path, measurements_doc):
    p = tmp_path / "test.pkg-measurements.json"
    p.write_text(json.dumps(measurements_doc))
    return str(p)
