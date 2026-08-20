#!/usr/bin/env python3
"""Build site/vendor/pkgcrypto.js from the pinned upstream ESM bundles.

Why this exists
---------------
The site must run from file://, where ES modules and fetch() are both
CORS-blocked, so every script has to be a classic script. Upstream ships ESM.
The conversion is deliberately mechanical and reviewable: each bundle is
self-contained (verified: exactly one `export{...}`, no `export default`, no
`import.meta`, no top-level await), so we wrap each one in an IIFE and rewrite
its single trailing export statement into assignments on a namespace object.
Nothing else about the upstream bytes is touched.

Provenance is checked both ways:
  * the upstream bundles are committed under site/vendor/upstream/ and pinned
    by sha256 here, so a changed CDN build is a loud failure, not a silent one;
  * the generated file is committed too, and `make check-vendor` regenerates it
    and diffs — so the transformation itself cannot drift unnoticed.

Regenerate (needs network) with --fetch; verify offline with --check.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
UPSTREAM = os.path.join(BASE, "site", "vendor", "upstream")
OUT = os.path.join(BASE, "site", "vendor", "pkgcrypto.js")

# Pinned upstream bundles. jsDelivr's `+esm` endpoint inlines dependencies,
# which is what makes each of these a single self-contained file.
MODULES = [
    {
        "id": "@noble/hashes/sha256",
        "version": "1.5.0",
        "file": "noble-hashes-1.5.0-sha256.esm.js",
        "url": "https://cdn.jsdelivr.net/npm/@noble/hashes@1.5.0/sha256/+esm",
        "sha256": "7a29c76ca084ee79af36e48bdb8d4b0b"
                  "8ef78d0c0193c27d105e05ad267b0405",
    },
    {
        "id": "@noble/hashes/sha512",
        "version": "1.5.0",
        "file": "noble-hashes-1.5.0-sha512.esm.js",
        "url": "https://cdn.jsdelivr.net/npm/@noble/hashes@1.5.0/sha512/+esm",
        "sha256": "2559980e8b994366229aadd4e014fb2a"
                  "5e0fc03dbe51618a14201529ec621ff5",
    },
    {
        "id": "@noble/ed25519",
        "version": "2.1.0",
        "file": "noble-ed25519-2.1.0.esm.js",
        "url": "https://cdn.jsdelivr.net/npm/@noble/ed25519@2.1.0/+esm",
        "sha256": "8bcec625f1b8ee2d21756806821ce1ca"
                  "478de92600b3e96b0f1e476ac66f4df8",
    },
]

EXPORT_RE = re.compile(r"export\s*\{([^}]*)\}\s*;?\s*$", re.M)
SOURCEMAP_RE = re.compile(r"^//# sourceMappingURL=.*$", re.M)

# A bare side-effect import: `import"...";` — no bindings are introduced, so
# it can be dropped once we prove the body never uses what it would provide.
BARE_IMPORT_RE = re.compile(r"""import\s*(['"])(?P<spec>.*?)\1\s*;?""")
# Anything that actually binds a name needs real module linking, which this
# converter deliberately does not attempt.
BINDING_IMPORT_RE = re.compile(
    r"""import\s*(\{|\*|[A-Za-z_$][\w$]*\s*(,|\s+from\b))|import\s*\(""")
HAZARDS = ("export default", "import.meta")

# The only module the bundles side-effect-import is noble's crypto shim,
# whose sole purpose is to expose `globalThis.crypto`. Dropping it is safe
# exactly when the body never references that identifier.
ALLOWED_BARE_IMPORTS = {"/npm/@noble/hashes@1.5.0/crypto/+esm": "crypto"}

# Wrapper-local name for a module's export object. Must not collide with the
# minified single-letter identifiers the bundles declare (ed25519 uses `E`).
EXPORTS_VAR = "__pkgi_exports"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_all():
    os.makedirs(UPSTREAM, exist_ok=True)
    for m in MODULES:
        dest = os.path.join(UPSTREAM, m["file"])
        subprocess.run(["curl", "-sSL", "--fail", "-o", dest, m["url"]],
                       check=True)
        got = _sha256(open(dest, "rb").read())
        if got != m["sha256"]:
            raise SystemExit(
                "%s: upstream digest changed\n  pinned %s\n  got    %s\n"
                "If this is an intentional upgrade, review the diff and "
                "update the pin." % (m["id"], m["sha256"], got))
        print("fetched %-24s %s" % (m["id"], got[:16]))


def _convert(src: str, module_id: str):
    """Rewrite one self-contained ESM bundle into an IIFE body.

    Returns (body, stripped_imports). Anything this converter does not
    understand is a hard failure: silently mangling a crypto bundle is far
    worse than refusing to build.
    """
    for hazard in HAZARDS:
        if hazard in src:
            raise SystemExit("%s: unexpected ESM construct %r — this "
                             "converter only handles a single trailing "
                             "export statement" % (module_id, hazard.strip()))
    binding = BINDING_IMPORT_RE.search(src)
    if binding:
        raise SystemExit(
            "%s: found an import that binds names (%r). The bundle is not "
            "self-contained and this converter does not link modules."
            % (module_id, src[binding.start():binding.start() + 60]))

    src = SOURCEMAP_RE.sub("", src).rstrip()

    stripped = []
    for m in list(BARE_IMPORT_RE.finditer(src)):
        spec = m.group("spec")
        if spec not in ALLOWED_BARE_IMPORTS:
            raise SystemExit(
                "%s: unexpected side-effect import %r — review it and add it "
                "to ALLOWED_BARE_IMPORTS if it is genuinely inert."
                % (module_id, spec))
        provides = ALLOWED_BARE_IMPORTS[spec]
        body_without = src[:m.start()] + src[m.end():]
        if re.search(r"\b%s\b" % re.escape(provides), body_without):
            raise SystemExit(
                "%s: side-effect import %r provides %r, and the body "
                "references it — it cannot be dropped."
                % (module_id, spec, provides))
        stripped.append(spec)
        src = body_without

    matches = list(EXPORT_RE.finditer(src))
    if len(matches) != 1:
        raise SystemExit("%s: expected exactly one export statement, found %d"
                         % (module_id, len(matches)))
    match = matches[0]
    body = src[:match.start()].rstrip()

    # The bundles are minified and use single-letter identifiers, so the
    # wrapper's own variable must be one they cannot possibly declare.
    if re.search(r"\b%s\b" % EXPORTS_VAR, body):
        raise SystemExit("%s: body already uses %s — pick another wrapper "
                         "variable name" % (module_id, EXPORTS_VAR))

    assigns = []
    for spec in match.group(1).split(","):
        spec = spec.strip()
        if not spec:
            continue
        if " as " in spec:
            local, _, exported = spec.partition(" as ")
        else:
            local = exported = spec
        assigns.append("    %s[%r] = %s;"
                       % (EXPORTS_VAR, exported.strip(), local.strip()))

    return ("  // ---- %s ----\n"
            "  MOD[%r] = (function () {\n"
            "    var %s = {};\n"
            "%s\n"
            "%s\n"
            "    return %s;\n"
            "  })();\n" % (module_id, module_id, EXPORTS_VAR, body,
                           "\n".join(assigns), EXPORTS_VAR),
            stripped)


def build() -> str:
    parts = []
    provenance = []
    for m in MODULES:
        path = os.path.join(UPSTREAM, m["file"])
        raw = open(path, "rb").read()
        got = _sha256(raw)
        if got != m["sha256"]:
            raise SystemExit("%s: %s digest mismatch\n  pinned %s\n  got    %s"
                             % (m["id"], m["file"], m["sha256"], got))
        body, stripped = _convert(raw.decode("utf-8"), m["id"])
        note = ("\n *     dropped inert side-effect import(s): %s"
                % ", ".join(stripped) if stripped else "")
        provenance.append(" *   %s@%s\n *     %s\n *     sha256 %s%s"
                          % (m["id"], m["version"], m["url"], got, note))
        parts.append(body)

    header = (
        "/* pkgcrypto.js -- verification primitives for the pkgattest site.\n"
        " *\n"
        " * GENERATED by tools/vendor_crypto.py -- do not edit by hand.\n"
        " * Regenerate with `make vendor-crypto`; verify with "
        "`make check-vendor`.\n"
        " *\n"
        " * Vendored from (MIT licensed):\n"
        "%s\n"
        " *\n"
        " * Each upstream bundle is self-contained and is reproduced verbatim\n"
        " * inside an IIFE; only its single trailing `export {...}` statement\n"
        " * is rewritten into assignments, so the site can load classic\n"
        " * scripts (ES modules and fetch() are CORS-blocked on file://).\n"
        " *\n"
        " * This code only VERIFIES. No secret ever reaches the browser, so\n"
        " * constant-time behaviour is not required here. The pkgattest CLI\n"
        " * (OpenSSL via python-cryptography) remains the trust root.\n"
        " */\n" % "\n".join(provenance))

    tail = """
  var sha256 = MOD['@noble/hashes/sha256'].sha256;
  var sha512 = MOD['@noble/hashes/sha512'].sha512;
  var ed = MOD['@noble/ed25519'];

  // noble-ed25519 v2 needs a synchronous sha512 injected; its async path
  // would reach for crypto.subtle, which is undefined on file:// and on
  // plain http:// LAN addresses (neither is a secure context).
  ed.etc.sha512Sync = function () {
    return sha512(ed.etc.concatBytes.apply(null, arguments));
  };

  return {
    sha256: sha256,
    sha512: sha512,
    // verify(signature, message, publicKey) -> boolean, never throws
    ed25519Verify: function (sig, msg, pub) {
      try {
        return ed.verify(sig, msg, pub);
      } catch (e) {
        return false;
      }
    },
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PKGI_CRYPTO;  // lets tests/test_js_parity.py load this
}
"""
    return (header + "var PKGI_CRYPTO = (function () {\n"
            + "  'use strict';\n  var MOD = {};\n\n"
            + "\n".join(parts) + tail)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true",
                    help="re-download the pinned upstream bundles")
    ap.add_argument("--check", action="store_true",
                    help="verify the committed output matches a rebuild")
    args = ap.parse_args(argv)

    if args.fetch:
        fetch_all()

    generated = build()
    if args.check:
        if not os.path.exists(OUT):
            print("check-vendor: %s missing" % OUT, file=sys.stderr)
            return 1
        current = open(OUT, encoding="utf-8").read()
        if current != generated:
            print("check-vendor: %s does not match a rebuild from the pinned "
                  "upstream bundles" % OUT, file=sys.stderr)
            return 1
        print("check-vendor: OK — %d bytes, sha256 %s"
              % (len(generated.encode()),
                 _sha256(generated.encode())[:16]))
        return 0

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(generated)
    print("wrote %s (%d bytes, sha256 %s)"
          % (OUT, len(generated.encode()), _sha256(generated.encode())[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
