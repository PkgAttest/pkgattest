#!/usr/bin/env python3
"""Fake-device evidence bundle: build a collect tar (SPEC.md section 5) from
a pkg-measurements.json, with a synthetic ECDSA-signed TPM quote — no TPM,
no hardware. Used as verify.py --collect-cmd:

  verify.py --collect-cmd "python3 sim/make-bundle.py \
      --measurements artifacts/A/....pkg-measurements.json {nonce}"

--tamper-dropbear rewrites the dropbear leaf to version 2026.91 with altered
file hashes — simulating image B before it exists.
"""

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pkgintegrity import canonical, merkle  # noqa: E402

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

SIM_KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       ".sim-ak.pem")


def sim_ak():
    if os.path.exists(SIM_KEY):
        with open(SIM_KEY, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    with open(SIM_KEY, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    os.chmod(SIM_KEY, 0o600)
    return key


def build_attest(nonce_hex: str, pcr14: bytes) -> bytes:
    out = struct.pack(">I", 0xFF544347)          # TPM_GENERATED
    out += struct.pack(">H", 0x8018)             # TPM_ST_ATTEST_QUOTE
    signer = b"\x00\x0bsim-ak-name-000000000000"  # arbitrary TPM2B_NAME
    out += struct.pack(">H", len(signer)) + signer
    nonce = bytes.fromhex(nonce_hex)
    out += struct.pack(">H", len(nonce)) + nonce  # extraData
    out += b"\x00" * 17                           # clockInfo
    out += b"\x00" * 8                            # firmwareVersion
    out += struct.pack(">I", 1)                   # TPML_PCR_SELECTION count
    out += struct.pack(">H", 0x000B) + b"\x03" + bytes([0x00, 0x40, 0x00])
    digest = hashlib.sha256(pcr14).digest()
    out += struct.pack(">H", len(digest)) + digest
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--measurements", required=True)
    ap.add_argument("--tamper-dropbear", action="store_true")
    ap.add_argument("--out", default="-", help="output tar (default stdout)")
    ap.add_argument("nonce", help="hex nonce from the verifier")
    args = ap.parse_args()

    doc = canonical.load_measurements_json(args.measurements)
    pkgs = canonical.pkgs_from_measurements(doc)

    if args.tamper_dropbear:
        for p in pkgs:
            if p.name == "dropbear":
                p.version = "2026.91-r0"
                p.files = [(path, hashlib.sha256(
                    ("sim-old-dropbear:" + h).encode()).hexdigest())
                    for path, h in p.files]
                break
        else:
            print("no dropbear package in measurements", file=sys.stderr)
            return 2

    measurement_list = b"".join(p.preimage() for p in pkgs)
    root = canonical.device_tree_root(pkgs)
    pcr14_hex = merkle.expected_pcr14(root)
    pcr14 = bytes.fromhex(pcr14_hex)

    ak = sim_ak()
    quote_msg = build_attest(args.nonce, pcr14)
    quote_sig = ak.sign(quote_msg, ec.ECDSA(SHA256()))
    ak_pub_pem = ak.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    meta = json.dumps({
        "machine": "sim-device", "version": doc.get("version", "sim"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nonce": args.nonce, "status": "ok(sim)"}).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        add("measurement-list", measurement_list)
        add("root.hex", (root + "\n").encode())
        add("pcr14.hex", (pcr14_hex + "\n").encode())
        add("ak.pub.pem", ak_pub_pem)
        add("quote.msg", quote_msg)
        add("quote.sig", quote_sig)
        add("meta.json", meta)
    data = buf.getvalue()
    if args.out == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.out, "wb") as f:
            f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
