#!/usr/bin/env python3
"""Publish an image's per-package measurements to the transparency log.

Hard-gates on recomputing every leaf and the merkle root from the
measurement document (catches canonicalization drift at the earliest
possible moment), then publishes one log-leaf-v1 record per package and
verifies old-STH -> new-STH consistency. Image B is NEVER published — that
is the demo's premise.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity import canonical, merkle  # noqa: E402
from pkgintegrity.logclient import LogClient  # noqa: E402


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--measurements", required=True,
                    help="<image>.pkg-measurements.json")
    ap.add_argument("--log", default="http://127.0.0.1:8799")
    ap.add_argument("--image-line", default=None,
                    help="override the document's image_line")
    ap.add_argument("--receipt", default=None)
    ap.add_argument("--log-pub", default=os.path.join(base, "keys",
                                                      "log_ed25519.pub"))
    args = ap.parse_args()

    doc = canonical.load_measurements_json(args.measurements)
    problems = canonical.verify_measurements_doc(doc)
    if problems:
        for p in problems[:20]:
            print("DRIFT: %s" % p, file=sys.stderr)
        print("refusing to publish: %d canonicalization problem(s)"
              % len(problems), file=sys.stderr)
        return 2
    image_line = args.image_line or doc["image_line"]
    print("measurements OK: %d packages, root %s, image line %s"
          % (len(doc["packages"]), doc["merkle_root"], image_line))

    client = LogClient(args.log)
    pub = merkle.load_ed25519_public(args.log_pub)

    old_sth = client.sth()
    if not merkle.verify_sth(pub, old_sth):
        print("pre-publication STH signature INVALID", file=sys.stderr)
        return 2

    entries = [
        {"name": p["name"], "version": p["version"], "arch": p["arch"],
         "image_line": image_line, "pkg_leaf_hash": p["leaf_hash"]}
        for p in doc["packages"]
    ]
    result = client.add_entries(entries)
    new_sth = result["sth"]
    if not merkle.verify_sth(pub, new_sth):
        print("post-publication STH signature INVALID", file=sys.stderr)
        return 2
    print("published: %d added, %d duplicates -> tree size %d, root %s"
          % (result["added"], result["duplicates"], new_sth["tree_size"],
             new_sth["root_hash"]))

    receipt = {
        "image_line": image_line,
        "image_name": doc.get("image_name"),
        "image_version": doc.get("version"),
        "merkle_root": doc["merkle_root"],
        "package_count": len(doc["packages"]),
        "added": result["added"],
        "duplicates": result["duplicates"],
        "sth": {k: new_sth[k] for k in
                ("tree_size", "root_hash", "timestamp", "signature")},
        "published_at": int(time.time()),
    }
    receipt_path = args.receipt or os.path.join(
        os.path.dirname(os.path.abspath(args.measurements)),
        "publication-receipt.json")
    with open(receipt_path, "w") as f:
        json.dump(receipt, f, indent=1)
    print("receipt -> %s" % receipt_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
