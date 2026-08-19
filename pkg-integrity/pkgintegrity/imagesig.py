"""OpenBMC signed-image verification (Beat 1).

Mirrors phosphor-software-manager's bmc/image_verify.cpp semantics against a
phosphor `*.ext4.mmc.tar` payload: RSA/SHA256 PKCS#1 v1.5 detached sigs.
System-level: MANIFEST.sig and publickey.sig verify under the PINNED build
public key; image-level: every blob's .sig (and image-full.sig) verifies
under the tar's embedded `publickey`.

Empirically verified quirk (do not "fix"): image-full is the concatenation
of the six .sig files in en_US.UTF-8 collation order.
"""

import hashlib
import tarfile
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BLOBS = ["image-u-boot", "image-kernel", "image-rofs", "image-rwfs",
         "MANIFEST", "publickey"]
# en_US.UTF-8 collation order used by make_signatures()'s bare `sort`
IMAGE_FULL_ORDER = ["image-kernel.sig", "image-rofs.sig", "image-rwfs.sig",
                    "image-u-boot.sig", "MANIFEST.sig", "publickey.sig"]


@dataclass
class ImageVerdict:
    path: str
    sha384: str = ""
    checks: dict = field(default_factory=dict)  # name -> bool

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(self.checks.values())


def _rsa_verify(pub, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def verify_mmc_tar(path: str, pinned_pubkey_pem: bytes) -> ImageVerdict:
    v = ImageVerdict(path=path)

    h = hashlib.sha384()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    v.sha384 = h.hexdigest()

    with tarfile.open(path) as tar:
        members = {}
        for name in BLOBS + [b + ".sig" for b in BLOBS] + ["image-full.sig"]:
            try:
                members[name] = tar.extractfile(name).read()
            except (KeyError, AttributeError):
                v.checks["member:" + name] = False
        if not all(n in members
                   for n in BLOBS + [b + ".sig" for b in BLOBS]
                   + ["image-full.sig"]):
            return v

    pinned = serialization.load_pem_public_key(pinned_pubkey_pem)
    embedded = serialization.load_pem_public_key(members["publickey"])

    v.checks["publickey==pinned"] = (
        members["publickey"].strip() == pinned_pubkey_pem.strip())
    # system-level (Signature::systemLevelVerify)
    v.checks["MANIFEST.sig(system)"] = _rsa_verify(
        pinned, members["MANIFEST"], members["MANIFEST.sig"])
    v.checks["publickey.sig(system)"] = _rsa_verify(
        pinned, members["publickey"], members["publickey.sig"])
    # image-level, under the embedded key
    for blob in BLOBS:
        v.checks[blob + ".sig"] = _rsa_verify(
            embedded, members[blob], members[blob + ".sig"])
    image_full = b"".join(members[n] for n in IMAGE_FULL_ORDER)
    v.checks["image-full.sig"] = _rsa_verify(
        embedded, image_full, members["image-full.sig"])
    return v


def read_manifest_fields(path: str) -> dict:
    out = {}
    with tarfile.open(path) as tar:
        data = tar.extractfile("MANIFEST").read().decode()
    for line in data.splitlines():
        if "=" in line:
            k, _, val = line.partition("=")
            out[k.strip()] = val.strip().strip('"')
    return out
