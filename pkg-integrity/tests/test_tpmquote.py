import hashlib
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import merkle, tpmquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

_spec = importlib.util.spec_from_file_location(
    "make_bundle",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "sim", "make-bundle.py"))
make_bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_bundle)

NONCE = "ab" * 32
ROOT = hashlib.sha256(b"fake-root").hexdigest()
PCR14_HEX = merkle.expected_pcr14(ROOT)


def _evidence():
    key = ec.generate_private_key(ec.SECP256R1())
    msg = make_bundle.build_attest(NONCE, bytes.fromhex(PCR14_HEX))
    sig = key.sign(msg, ec.ECDSA(SHA256()))
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, msg, sig


def test_quote_ok():
    pem, msg, sig = _evidence()
    assert tpmquote.verify_quote(pem, msg, sig, NONCE, PCR14_HEX, ROOT) == []


def test_quote_raw_rs_signature():
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature)
    pem, msg, sig = _evidence()
    r, s = decode_dss_signature(sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert tpmquote.verify_quote(pem, msg, raw, NONCE, PCR14_HEX, ROOT) == []


def test_quote_bad_nonce():
    pem, msg, sig = _evidence()
    problems = tpmquote.verify_quote(pem, msg, sig, "cd" * 32,
                                     PCR14_HEX, ROOT)
    assert any("nonce" in p for p in problems)


def test_quote_bad_root():
    pem, msg, sig = _evidence()
    other = hashlib.sha256(b"other-root").hexdigest()
    problems = tpmquote.verify_quote(pem, msg, sig, NONCE, PCR14_HEX, other)
    assert any("PCR14" in p for p in problems)


def test_quote_tampered_message():
    pem, msg, sig = _evidence()
    tampered = msg[:-1] + bytes([msg[-1] ^ 1])
    problems = tpmquote.verify_quote(pem, tampered, sig, NONCE,
                                     PCR14_HEX, ROOT)
    assert any("signature" in p for p in problems)


def test_quote_wrong_pcr_selection():
    pem, _, _ = _evidence()
    key = ec.generate_private_key(ec.SECP256R1())
    msg = make_bundle.build_attest(NONCE, bytes.fromhex(PCR14_HEX))
    # flip selection byte from PCR14 (byte1=0x40) to PCR7 (byte0=0x80)
    idx = msg.find(bytes([0x00, 0x40, 0x00]))
    msg = msg[:idx] + bytes([0x80, 0x00, 0x00]) + msg[idx + 3:]
    sig = key.sign(msg, ec.ECDSA(SHA256()))
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    problems = tpmquote.verify_quote(pem, msg, sig, NONCE, PCR14_HEX, ROOT)
    assert any("sha256:14" in p for p in problems)
