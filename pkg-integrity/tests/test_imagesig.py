import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import imagesig

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY_TAR = ("/home/zimmerle/obmc/openbmc/build/rpi3-64/tmp/deploy/images/"
              "raspberrypi3-64/obmc-phosphor-image-raspberrypi3-64.ext4.mmc.tar")
ARTIFACT_A = os.path.join(BASE, "artifacts", "A",
                          "obmc-phosphor-image-raspberrypi3-64.ext4.mmc.tar")


def _pinned_for(tar_path):
    """The matching public key: demo key for our artifacts, else the key
    embedded in the tar (covers the stock-key build)."""
    import tarfile
    demo_pub = os.path.join(BASE, "keys", "build-rsa4096.pub.pem")
    with tarfile.open(tar_path) as tar:
        embedded = tar.extractfile("publickey").read()
    if os.path.exists(demo_pub):
        with open(demo_pub, "rb") as f:
            demo = f.read()
        if demo.strip() == embedded.strip():
            return demo
    return embedded


def _existing_tar():
    for p in (ARTIFACT_A, DEPLOY_TAR):
        if os.path.exists(p):
            return p
    return None


@pytest.mark.skipif(_existing_tar() is None,
                    reason="no built mmc tar available")
def test_real_tar_verifies():
    tar = _existing_tar()
    v = imagesig.verify_mmc_tar(tar, _pinned_for(tar))
    assert v.ok, v.checks
    assert len(v.sha384) == 96


@pytest.mark.skipif(_existing_tar() is None,
                    reason="no built mmc tar available")
def test_corrupted_tar_fails(tmp_path):
    src = _existing_tar()
    dst = tmp_path / "corrupt.mmc.tar"
    shutil.copy(src, dst)
    # flip one byte inside image-rofs (past the first tar header block)
    with open(dst, "r+b") as f:
        f.seek(5 * 1024 * 1024)
        b = f.read(1)
        f.seek(-1, os.SEEK_CUR)
        f.write(bytes([b[0] ^ 0xFF]))
    v = imagesig.verify_mmc_tar(str(dst), _pinned_for(src))
    assert not v.ok


@pytest.mark.skipif(_existing_tar() is None,
                    reason="no built mmc tar available")
def test_manifest_fields():
    fields = imagesig.read_manifest_fields(_existing_tar())
    assert fields.get("HashType") == "RSA-SHA256"
    assert "version" in fields
