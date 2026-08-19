#!/usr/bin/env python3
"""Beat 1 — whole-image signature verification of phosphor update payloads.

Verifies signed *.ext4.mmc.tar payloads exactly the way the BMC's
phosphor-software-manager does (RSA/SHA256 PKCS#1 v1.5 detached sigs), and
prints the demo frame: both images signed, both verified, and nothing here
can name a package.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity import imagesig  # noqa: E402
from pkgintegrity.canonical import abbrev  # noqa: E402


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+",
                    help="label=path pairs (e.g. image_A=/path/a.mmc.tar) "
                         "or bare paths")
    ap.add_argument("--pubkey", default=os.path.join(base, "keys",
                                                     "build-rsa4096.pub.pem"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--full", action="store_true",
                    help="print full hashes instead of abbreviated")
    args = ap.parse_args()

    with open(args.pubkey, "rb") as f:
        pinned = f.read()

    results = []
    for spec in args.images:
        label, _, path = spec.rpartition("=")
        if not label:
            label, path = os.path.basename(path), spec
        v = imagesig.verify_mmc_tar(path, pinned)
        results.append((label, v))

    if args.json:
        print(json.dumps(
            [{"label": lab, "path": v.path, "sha384": v.sha384,
              "verified": v.ok, "checks": v.checks}
             for lab, v in results], indent=1))
        return 0 if all(v.ok for _, v in results) else 1

    width = max(len(lab) for lab, _ in results)
    for lab, v in results:
        digest = v.sha384 if args.full else abbrev(v.sha384)
        verdict = "OK" if v.ok else "FAIL"
        print("%-*s  sha384: %s   verified: %s"
              % (width, lab, digest, verdict))
        if not v.ok:
            for name, ok in v.checks.items():
                if not ok:
                    print("%-*s      failed: %s" % (width, "", name))
    return 0 if all(v.ok for _, v in results) else 1


if __name__ == "__main__":
    sys.exit(main())
