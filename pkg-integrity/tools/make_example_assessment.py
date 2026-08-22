#!/usr/bin/env python3
"""Generate the illustrative assessment scope shipped with the site.

WHAT THIS IS NOT
----------------
This is not an OCP S.A.F.E. Short-Form Report, and the document it writes must
never be mistaken for one. No Security Review Provider reviewed anything here.
No security review of this image has taken place at all. The document exists
to demonstrate a *mechanism* — that an assessment can name the packages it
covered, and that a verifier can then compute whether those packages are the
ones actually running.

Everything about it is deliberately unmistakable: its own schema name, an
`illustrative: true` flag the exporter refuses to drop, an issuer that is not
an SRP, and no signature. A real assessment reference would be signed by the
SRP the way an SFR is accompanied by its .jws.

WHY IT LOOKS LIKE THIS
----------------------
An OCP S.A.F.E. SFR identifies the reviewed artefact with a single hash:

    "device": { "fw_version": "2.5.0.33", "fw_hash_sha2_384": "7e87eed0..." }

For a monolithic RoT firmware that is a fair description of one artefact. For
a Linux BMC image of 2131 packages it answers only "is this bit-identical",
which is a question with almost no useful middle. This document carries the
device merkle root instead — one hash that *decomposes*, because it commits to
every package measurement underneath it.

The selection below is editorial: the packages that make up the externally
reachable attack surface of a BMC, which is roughly what S.A.F.E. Scope 1
describes ("the external attack surface of the firmware, and any interface
that can be attacked from outside the SoC"). The leaf hashes are not
editorial — they are read from the measurement document, so the file cannot
name a package that is not really in the image.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The externally reachable surface of this image: what listens, what
# terminates TLS, what authenticates, and what parses untrusted input on the
# way in. Prefix match, so the PAM and IPMI stacks come along whole.
IN_SCOPE_PREFIXES = (
    "avahi", "bmcweb", "dropbear", "openssh", "openssl", "libssl", "libcrypto",
    "libcurl", "libssh", "phosphor-ipmi", "phosphor-network", "pam", "libpam",
    "shadow", "systemd-networkd", "netbase", "libexpat", "libjson",
    "libfastjson", "libyaml", "libtinyxml", "dbus-broker", "libdbus",
    "libsdbusplus", "libphosphor-dbus",
)

DISCLAIMER = (
    "Illustration only. This is not an OCP S.A.F.E. Short-Form Report and no "
    "Security Review Provider has reviewed this image. It is a worked example "
    "of what an assessment could reference if it named packages instead of a "
    "single firmware hash."
)


def build(measurements_path, image_line, assessment_id, issued_at):
    doc = canonical.load_measurements_json(measurements_path)
    examined = []
    for p in doc["packages"]:
        if p["name"].startswith(IN_SCOPE_PREFIXES):
            examined.append({"name": p["name"], "version": p["version"],
                             "pkg_leaf_hash": p["leaf_hash"]})
    examined.sort(key=lambda e: e["name"])

    return {
        "schema": "pkgattest-assessment-v1",
        "illustrative": True,
        "disclaimer": DISCLAIMER,
        "assessment_id": assessment_id,
        "issuer": {
            "name": "pkgattest (worked example)",
            "kind": "self-issued-example",
        },
        "issued_at": issued_at,
        "subject": {
            "image_line": image_line or doc["image_line"],
            "manifest_type": doc["schema"],
            # The join key. One hash, but a decomposable one: it commits to
            # every package measurement below it, and it is also the value a
            # BMC extends into PCR 14 -- so the artefact an assessment names
            # and the artefact a device attests become directly comparable.
            "device_root": doc["merkle_root"],
            "package_count": len(doc["packages"]),
        },
        "review": {
            "basis": "The externally reachable attack surface: services that "
                     "listen, terminate TLS, authenticate, or parse untrusted "
                     "input on the way in.",
            "aligns_with_safe_scope": 1,
            "methodology": "none - illustrative selection, not a review",
        },
        "examined": examined,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--measurements", default=os.path.join(
        BASE, "artifacts", "A",
        "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json"))
    ap.add_argument("--image-line", default=None)
    ap.add_argument("--id", default="example-scope1")
    ap.add_argument("--issued-at", default="2026-08-22",
                    help="fixed, not today() -- the output must be "
                         "byte-reproducible")
    ap.add_argument("--out", default=os.path.join(
        BASE, "assessments", "example-scope1.json"))
    args = ap.parse_args(argv)

    doc = build(args.measurements, args.image_line, args.id, args.issued_at)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print("wrote %s: %d packages examined of %d in the subject image"
          % (args.out, len(doc["examined"]), doc["subject"]["package_count"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
