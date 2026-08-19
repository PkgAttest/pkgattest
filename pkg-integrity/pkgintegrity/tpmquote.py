"""TPM quote verification (SPEC.md section 5).

Parses a raw marshaled TPMS_ATTEST (tpm2_quote -m) and verifies:
  * ECDSA P-256 / sha256 signature under the AK public key (PEM),
  * extraData == the verifier's nonce,
  * pcrDigest == sha256(PCR14 value) for a sha256:14 selection,
  * PCR14 == sha256(0^32 || merkle_root)  (single extend from reset).

Pure python (`cryptography`) — the presenter laptop has no tpm2-tools.
`tpm2_checkquote` is available as a rehearsal cross-check via
verify.py --engine checkquote.
"""

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B


class QuoteError(Exception):
    pass


@dataclass
class ParsedQuote:
    qualified_signer: bytes
    extra_data: bytes
    pcr_selections: list  # [(alg, select_bytes)]
    pcr_digest: bytes


def _tpm2b(buf: bytes, off: int):
    if off + 2 > len(buf):
        raise QuoteError("truncated TPM2B size")
    (size,) = struct.unpack_from(">H", buf, off)
    off += 2
    if off + size > len(buf):
        raise QuoteError("truncated TPM2B body")
    return buf[off:off + size], off + size


def parse_attest(msg: bytes) -> ParsedQuote:
    off = 0
    (magic,) = struct.unpack_from(">I", msg, off); off += 4
    if magic != TPM_GENERATED_VALUE:
        raise QuoteError("bad TPM_GENERATED magic 0x%08x" % magic)
    (st,) = struct.unpack_from(">H", msg, off); off += 2
    if st != TPM_ST_ATTEST_QUOTE:
        raise QuoteError("not an ATTEST_QUOTE (type 0x%04x)" % st)
    signer, off = _tpm2b(msg, off)
    extra, off = _tpm2b(msg, off)
    off += 17  # clockInfo (8+4+4+1)
    off += 8   # firmwareVersion
    (count,) = struct.unpack_from(">I", msg, off); off += 4
    selections = []
    for _ in range(count):
        (alg,) = struct.unpack_from(">H", msg, off); off += 2
        size_of_select = msg[off]; off += 1
        selections.append((alg, msg[off:off + size_of_select]))
        off += size_of_select
    digest, off = _tpm2b(msg, off)
    if off != len(msg):
        raise QuoteError("%d trailing bytes after TPMS_ATTEST" %
                         (len(msg) - off))
    return ParsedQuote(signer, extra, selections, digest)


def _selects_only_pcr(selections: list, pcr: int) -> bool:
    want_byte, want_bit = pcr // 8, pcr % 8
    seen = False
    for alg, select in selections:
        for i, b in enumerate(select):
            if b == 0:
                continue
            if alg != TPM_ALG_SHA256 or i != want_byte or b != (1 << want_bit):
                return False
            seen = True
    return seen


def _load_signature_der(sig: bytes) -> bytes:
    if sig[:1] == b"\x30":  # already DER
        return sig
    if len(sig) == 64:  # tpm2_quote -f plain ECDSA: r || s
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        return utils.encode_dss_signature(r, s)
    raise QuoteError("unrecognized signature format (%d bytes)" % len(sig))


def verify_quote(ak_pub_pem: bytes, quote_msg: bytes, quote_sig: bytes,
                 nonce_hex: str, pcr14_hex: str, root_hex: str) -> list:
    """Full evidence-chain check; returns a list of failures (empty == OK)."""
    problems = []
    parsed = parse_attest(quote_msg)

    key = serialization.load_pem_public_key(ak_pub_pem)
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(_load_signature_der(quote_sig), quote_msg,
                       ec.ECDSA(hashes.SHA256()))
        else:  # RSA fallback (rsassa/sha256)
            key.verify(quote_sig, quote_msg, padding.PKCS1v15(),
                       hashes.SHA256())
    except Exception as e:
        problems.append("AK signature invalid (%s)" % e.__class__.__name__)

    if parsed.extra_data != bytes.fromhex(nonce_hex):
        problems.append("nonce mismatch (extraData)")

    if not _selects_only_pcr(parsed.pcr_selections, 14):
        problems.append("quote does not select exactly sha256:14")

    pcr14 = bytes.fromhex(pcr14_hex)
    if parsed.pcr_digest != hashlib.sha256(pcr14).digest():
        problems.append("pcrDigest != sha256(PCR14)")

    expected = hashlib.sha256(b"\x00" * 32 + bytes.fromhex(root_hex)).digest()
    if pcr14 != expected:
        problems.append("PCR14 != extend(0, merkle_root)")

    return problems
