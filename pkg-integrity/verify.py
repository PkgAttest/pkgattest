#!/usr/bin/env python3
"""Beats 3/4 — the package-aware attestation verifier.

Flow: fresh nonce -> one ssh round trip to the BMC's collect helper -> full
evidence chain:
  (a) recompute the device merkle root from all fetched leaf preimages,
  (b) PCR14 == extend(0, root),
  (c) TPM quote binds PCR14 + nonce under the device AK,
  (d) every package leaf gets an inclusion proof against the log's signed
      tree head; any package without one is NAMED, with the published
      version for this image line.

Exit codes: 0 all verified, 1 unaccounted packages / evidence failure,
2 operational error.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity import canonical, merkle, tpmquote, transport  # noqa: E402
from pkgintegrity.canonical import abbrev, display_version  # noqa: E402
from pkgintegrity.logclient import LogClient  # noqa: E402


def checkquote_engine(members, nonce_hex):
    """Rehearsal cross-check via tpm2_checkquote (needs tpm2-tools)."""
    with tempfile.TemporaryDirectory() as td:
        paths = {}
        for name in ("ak.pub.pem", "quote.msg", "quote.sig", "pcrs.bin"):
            paths[name] = os.path.join(td, name)
            with open(paths[name], "wb") as f:
                f.write(members[name])
        proc = subprocess.run(
            ["tpm2_checkquote", "-u", paths["ak.pub.pem"], "-g", "sha256",
             "-m", paths["quote.msg"], "-s", paths["quote.sig"],
             "-f", paths["pcrs.bin"], "-q", nonce_hex],
            capture_output=True)
        if proc.returncode != 0:
            return ["tpm2_checkquote failed: %s"
                    % proc.stderr.decode(errors="replace")[-300:]]
    return []


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("PKGI_HOST",
                                                     "raspberrypi3-64.local"))
    ap.add_argument("--user", default="root")
    ap.add_argument("--image-line",
                    default=os.environ.get("PKGI_IMAGE_LINE", "rpi3-openbmc"))
    ap.add_argument("--log", default=os.environ.get("PKGI_LOG",
                                                    "http://127.0.0.1:8799"))
    ap.add_argument("--log-pub", default=os.path.join(base, "keys",
                                                      "log_ed25519.pub"))
    ap.add_argument("--collect-cmd", default=None,
                    help="override the ssh collect command; {nonce} is "
                         "substituted (fake-device/sim mode)")
    ap.add_argument("--engine", choices=["python", "checkquote"],
                    default="python")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--full", action="store_true")
    args = ap.parse_args()

    out = {"host": args.host, "image_line": args.image_line}

    # ---- collect ----
    nonce = secrets.token_hex(32)
    cmd = args.collect_cmd or transport.ssh_collect_cmd(args.host, args.user)
    try:
        members = transport.collect(cmd, nonce)
    except transport.CollectError as e:
        print("pkg-verify: %s" % e, file=sys.stderr)
        return 2
    meta = json.loads(members["meta.json"])
    claimed_root = members["root.hex"].decode().strip()

    # ---- (a) measurement list -> root ----
    problems = []
    try:
        pkgs = canonical.parse_measurement_list(members["measurement-list"])
        computed_root = canonical.device_tree_root(pkgs)
    except ValueError as e:
        print("pkg-verify: bad measurement list: %s" % e, file=sys.stderr)
        return 2
    if computed_root != claimed_root:
        problems.append("recomputed root != device root")
    out["package_count"] = len(pkgs)
    out["merkle_root"] = computed_root

    # ---- (b)+(c) quote chain ----
    quote_bits = []
    have_quote = all(k in members for k in
                     ("pcr14.hex", "ak.pub.pem", "quote.msg", "quote.sig"))
    if have_quote:
        pcr14 = members["pcr14.hex"].decode().strip()
        if args.engine == "checkquote":
            qp = checkquote_engine(members, nonce)
            if merkle.expected_pcr14(claimed_root) != pcr14:
                qp.append("PCR14 != extend(0, merkle root)")
        else:
            qp = tpmquote.verify_quote(
                members["ak.pub.pem"], members["quote.msg"],
                members["quote.sig"], nonce, pcr14, claimed_root)
        problems.extend(qp)
        quote_bits = [
            ("nonce", "nonce" not in " ".join(qp)),
            ("AK sig", not any("signature" in p or "checkquote" in p
                               for p in qp)),
            ("PCR14 == extend(merkle root)",
             not any("PCR14" in p or "pcrDigest" in p for p in qp)),
        ]
    else:
        problems.append("no TPM quote in evidence (device status: %s)"
                        % meta.get("status", "unknown"))

    # ---- (d) inclusion proofs against the signed tree head ----
    client = LogClient(args.log)
    pub = merkle.load_ed25519_public(args.log_pub)
    try:
        sth = client.sth()
    except Exception as e:
        print("pkg-verify: cannot reach log %s (%s)" % (args.log, e),
              file=sys.stderr)
        return 2
    if not merkle.verify_sth(pub, sth):
        problems.append("log STH signature invalid")
    tree_size = sth["tree_size"]
    root_bytes = bytes.fromhex(sth["root_hash"])

    leaf_hashes = {}
    for p in pkgs:
        data = canonical.log_leaf_data(args.image_line, p.name, p.version,
                                       p.arch, p.leaf_hash())
        leaf_hashes[merkle.leaf_hash(data).hex()] = p
    proofs = client.proofs_batch(list(leaf_hashes), tree_size)["proofs"]

    unaccounted = []
    for lh, p in leaf_hashes.items():
        proof = proofs.get(lh)
        ok = bool(proof) and merkle.verify_inclusion(
            bytes.fromhex(lh), proof["index"], tree_size,
            [bytes.fromhex(x) for x in proof["path"]], root_bytes)
        if not ok:
            published = client.lookup(p.name, args.image_line)
            unaccounted.append((p, published))
    unaccounted.sort(key=lambda t: t[0].name)

    out["tree_head"] = sth["root_hash"]
    out["tree_size"] = tree_size
    out["quote_problems"] = problems
    out["unaccounted"] = [
        {"name": p.name, "version": p.version, "leaf_hash": p.leaf_hash(),
         "published": pub_list}
        for p, pub_list in unaccounted]
    ok_overall = not problems and not unaccounted

    if args.json:
        out["ok"] = ok_overall
        print(json.dumps(out, indent=1))
        return 0 if ok_overall else 1

    # ---- frames ----
    head = sth["root_hash"] if args.full else "0x" + sth["root_hash"][:4] + "…"
    print("pkg-verify  %s  image line: %s   [swtpm]"
          % (args.host, args.image_line))
    if quote_bits:
        print("quote: " + " · ".join(
            "%s %s" % (label, "OK" if good else "FAIL")
            for label, good in quote_bits))
    else:
        print("quote: UNAVAILABLE (%s)" % meta.get("status", "unknown"))
    for p in problems:
        print("       ! %s" % p)
    print()
    total = len(pkgs)
    if not unaccounted:
        print("%d / %d packages verified against tree head %s"
              % (total, total, head))
        print("OK" if ok_overall else "EVIDENCE FAIL (see above)")
    else:
        for p, published in unaccounted:
            arrow = "%s %s" % (p.name, display_version(p.version))
            print("%s  ->  no inclusion proof against signed tree head"
                  % arrow)
            pad = " " * (len(arrow) + 6)
            if published:
                versions = ", ".join(sorted(
                    {display_version(e["version"]) for e in published}))
                print("%spublished version for this image line: %s"
                      % (pad, versions))
            else:
                print("%snever published for this image line" % pad)
        print("FAIL: %d of %d packages unaccounted for"
              % (len(unaccounted), total))
    return 0 if ok_overall else 1


if __name__ == "__main__":
    sys.exit(main())
