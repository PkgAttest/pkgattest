# pkg-integrity — OCP Global Summit 2026 demo

Package-aware integrity for OpenBMC: per-package measurement at build,
boot-time re-measurement into a TPM PCR on the BMC, publication to a
transparency log, and a verifier that **names the package** no one
published. Demo plan: `../demo.md` (Demo A). Formats and trust model:
`SPEC.md`. Yocto side: `../meta-pkg-integrity/`.

## Layout

| path | what |
|---|---|
| `pkgintegrity/` | shared library: merkle (device tree + RFC 6962 log), canonical formats, TPM quote parsing, image signatures — plus `cli.py` (the `pkgattest` command) and `attest.py` (Beats 3/4 verifier) |
| `log_server.py` | transparency log (stdlib HTTP, Ed25519 STH), port 8799, localhost-only; `--writable` to publish |
| `publish.py` | publish image A's measurements (drift-gated) — **never image B** |
| `verify.py` | thin wrapper for `pkgattest attest` (ssh collect → root/PCR/quote/inclusion-proof chain) |
| `verify_image.py` | thin wrapper for `pkgattest verify-image` (Beat 1: mmc-tar signatures) |
| `pyproject.toml` | installable `pkgattest` package (`make venv` does `pip install -e .`) |
| `site/` | the static site: `index.html`, `app.js`, `style.css`, `verify.js` (browser-side verification core) and `vendor/pkgcrypto.js` (pinned, vendored sha256/sha512/ed25519) |
| `site-dist/` (gitignored) | generated bundle — `make site` |
| `tools/` | `vendor_crypto.py` (build the vendored crypto), `parity.js` (JS vs Python), `verify-bundle.js` (check a bundle the way a browser does), `render-check.js` (run the page against a minimal DOM) |
| `build-image.sh {A\|B\|C}` | build the demo images (B: dropbear 2026.91, never published; C: a later build giving the log a second tree head) |
| `demo/` | per-beat frame scripts, env |
| `sim/` | hardware-free path: synthetic evidence bundles, laptop swtpm, e2e |
| `tests/` | pytest (merkle vectors, bash canary, quote, log, e2e frames) |
| `keys/` (gitignored) | signing key, log key, ssh key, pinned build pubkey |
| `artifacts/{A,B}/` (gitignored) | wic.xz, ext4.mmc.tar, manifest, measurements |

## Quickstart

```sh
make venv keys test        # python env + keys + unit tests
make e2e-sim               # both money frames, laptop-only, no Pi, no TPM
make build-a               # image A (~1h first time, then minutes)
make build-b               # image B (dropbear pinned back, ~20-35 min)
make build-c               # image C (later build; second signed tree head)
# flash artifacts/A wic.xz to SD card A, artifacts/B to card B (bmaptool/dd)
make log                   # terminal 1: transparency log (read-only)
make log-writable          # only when publishing; writes are off by default
make publish               # publish image A (image B never gets published)
make wait-device HOST=raspberrypi3-64.local
make xcheck                # three-way root agreement (build/device/fetched)
make beat1 beat2 beat4     # card A frames
make beat3 freeze          # card B: THE frame (+ fallback still)
make closer qr
```

## CLI — `pkgattest`

`make venv` installs this directory as an editable package, providing a
`pkgattest` console command (`.venv/bin/pkgattest`):

```sh
pkgattest verify-image image_A=artifacts/A/….ext4.mmc.tar image_B=…
pkgattest verify-sth [--sth-file saved-sth.json] [--print-payload]
pkgattest verify-package dropbear [--version 2026.92] [--image-line rpi3-openbmc]
pkgattest verify-measurements artifacts/A/….pkg-measurements.json
pkgattest attest --host raspberrypi3-64.local
```

- `verify-image` — phosphor payload signatures, checked the way the BMC
  does: pinned build pubkey → `MANIFEST.sig`/`publickey.sig` → every blob
  sig → `image-full.sig` (RSA/SHA256 PKCS#1 v1.5).
- `verify-sth` — Ed25519 signed tree head of the transparency log; works
  offline against a saved STH with `--sth-file`.
- `verify-package` — fetches the published records for a package and
  verifies an RFC 6962 inclusion proof for each against the signed tree
  head; names unpublished versions.
- `verify-measurements` — recomputes every package leaf and the merkle root
  of a build `pkg-measurements.json` (the publisher's drift gate, run by
  hand).
- `attest` — the full Beat-3/4 device chain (same engine as `verify.py`).

Exit codes: `0` verified, `1` verification failure, `2` operational error.
All commands take `--json` and `--full` (full hashes instead of
abbreviated); log commands honor `PKGI_LOG`.

## The static site

`make site` builds `site-dist/` — a self-contained bundle whose bytes are the
same whether served from HTTPS, from `log_server.py --site`, or opened from
`file://`. It ships every canonical log leaf, and **the reader's browser
rebuilds both Merkle trees and verifies the Ed25519 signed tree head itself**.
There is deliberately no verify API: an endpoint the page trusts is an
endpoint that can lie.

```sh
make site            # export the bundle
make site-serve      # serve it at http://127.0.0.1:8799/site/
make site-verify     # build twice and diff — the output is deterministic
make site-check      # verify it the way a browser will (needs node)
make check-vendor    # the vendored crypto matches its pinned upstream
make parity          # verify.js vs the Python implementation
```

The page opens straight from `site-dist/index.html` with no server at all.
`log_server.py --site DIR` mounts a bundle under `/site/` — deliberately not
at the root, so `GET /` keeps serving the plain-text page the demo's QR code
already points at. Static serving is off unless `--site` is given: that
process holds the log's signing key.

### What the page does

It runs `PKGI_VERIFY.selfTest()` before rendering anything. If a primitive
fails a known-answer check, the page shows that and stops — a verdict drawn
on top of arithmetic that failed is worse than no page. Then it rebuilds the
tree from the records it shipped with, checks the Ed25519 signature, and
reports the real measured timings rather than performing a progress bar.

Typeface carries provenance: monospace is everything this browser computed,
and the sans face appears only where somebody is asserting something nobody
verified — the key's authenticity, the currency of the tree head, and the
fact that a log entry commits to a package and never to an image. Those four
limits get their own page at `#/limits`.

Current cost of a first visit, gzipped:

| | |
|---|---|
| page, verifier and vendored crypto | 34 KB |
| the log's 2,132 records | 104 KB |
| **tree verification total** | **135 KB** |
| per-build package detail (6 files) | 864 KB |
| **everything the landing page loads** | **999 KB** |

Rebuilding the whole 2132-leaf tree in the browser takes about 20 ms.

That last number is larger than it should be, and it is a real cost for
someone scanning a QR code on a phone. The cause is honest rather than
accidental: the landing page's headline — *N of 2,131 unaccounted for* — is
recomputed, which means re-deriving every package's leaf hash from its file
list, which needs the file lists for every build. Using the `leaf_hash` the
bundle already states would drop it to 135 KB and make the headline an
assertion instead of a computation, which is the trade this project exists to
refuse.

The fix is deduplication, not assertion: builds A and C differ by one
package, so their file lists are ~99.95% identical and are currently shipped
three times over. Content-addressing the per-package file lists would collapse
864 KB to roughly 200 KB with no loss of what is verified. Not done yet.

`make site-check` output is the demo, derived rather than asserted:

```
  rebuilt root from 2132 leaves in 20 ms
  root matches the signed head: f1f87542c9ee89c1…
  Ed25519 signature over the head verifies
  consistency 2131 -> 2132 verified (6 nodes)

build B  …-20260819152629
  device root recomputed from 2131 pkg-leaf-v1 preimages: e9367ef25564fa52…
  1 of 2131 packages unaccounted for at tree size 2132:
      dropbear 2026.91
```

### Vendored crypto

`site/vendor/pkgcrypto.js` is generated by `tools/vendor_crypto.py` from three
pinned upstream ESM bundles (`@noble/hashes` sha256 + sha512, `@noble/ed25519`),
committed under `site/vendor/upstream/`. ES modules and `fetch()` are both
CORS-blocked on `file://`, so each bundle is wrapped in an IIFE with its single
trailing `export {...}` rewritten — a mechanical change the converter refuses
to make if it meets anything it does not understand. `make check-vendor`
regenerates and diffs, so neither the upstream bytes nor the transformation can
drift unnoticed.

Every generated `.js` file is pure ASCII on purpose: loaded over `file://`
there is no charset header, and a mis-guessed byte in a path would silently
change a leaf hash.

## Recording plan (per demo.md production rules)

1. Two SD cards, labeled A and B, flashed once each. The verifier ssh key
   is baked into both images; host keys are per-boot (tmpfs /etc/dropbear).
2. Take order ≠ narrative order:
   - Session 1 (host only): `beat1`, `closer`, `qr`.
   - Session 2 (card A booted, `wait-device`): `beat2`, then `beat4`.
   - Session 3 (card B booted): `beat3` — hold the FAIL frame ≥ 1 s;
     screenshot at presentation resolution → static fallback slide
     (`make freeze` saves the text frame).
3. Terminal 80×24, large font tested at presentation resolution, `PS1='$ '`,
   no typing on camera. `[swtpm]` label is embedded in every relevant frame.
4. Full offline rehearsal (laptop + Pi on direct ethernet, venue wifi
   nowhere) is the go/no-go gate.

## Troubleshooting

- **mDNS flaky** → set `PKGI_HOST` to a static IP (see `demo/env.sh`).
- **Agent still running** → `make wait-device`; it hashes ~86 MB and ~2100
  preimages on an A53, expect ~20–35 s after boot.
- **ssh refused** → serial console (root / 0penBmc), check
  `systemctl status pkg-witness etc-dropbear-tmpfs dropbear.socket` and
  `/run/pkg-integrity/agent.log`.
- **Root mismatch in xcheck** → diff the first differing preimage between
  the fetched `measurement-list` and the build's
  `.pkg-measurements.json` — it names the drifting implementation.
- **Quote engine cross-check** → `pacman -S tpm2-tools`, then
  `verify.py --engine checkquote` once against a real device quote.
