# PkgAttest

Package-aware integrity for OpenBMC: per-package measurement at build time,
boot-time re-measurement into a TPM PCR on the BMC, publication of package
records to a transparency log with a signed tree head, and a verifier that
does per-package inclusion-proof checking — so attestation can **name the
package** nobody published, instead of reporting one opaque image hash.

Demonstrated at the OCP Global Summit 2026 (Security track): two validly
signed BMC images differing in exactly one package (`dropbear` 2026.92 vs
2026.91); whole-image signature verification passes for both, the
package-aware verifier names the delta:

```
dropbear 2026.91  ->  no inclusion proof against signed tree head
                      published version for this image line: 2026.92
FAIL: 1 of 2131 packages unaccounted for
```

## Layout

| dir | what |
|---|---|
| `meta-pkg-integrity/` | Yocto layer: `pkg-measurements.bbclass` (canonical per-package leaf preimages + merkle root, baked into the image and deployed as `<image>.pkg-measurements.json`), `pkg-witness` boot agent (re-measures, extends the root into swtpm PCR 14 via kernel vtpm-proxy, serves evidence over ssh), kernel config fragment, signing enablement, and the pinned-back `dropbear` recipe for the demo's image B |
| `pkg-integrity/` | Host tooling (Python): transparency log (RFC 6962 + Ed25519 signed tree head), drift-gated publisher, the installable `pkgattest` CLI (image-signature, tree-head, per-package inclusion-proof, measurement-doc and full-attestation verifiers), demo frame scripts, hardware-free simulation path, tests |

`pkg-integrity/SPEC.md` is the **binding byte-level spec** shared by the three
format implementations (build class / target bash agent / host python) —
change all three together. `pkg-integrity/README.md` has the full quickstart,
Makefile map, and recording plan.

## Wiring into an OpenBMC tree

Requires an [OpenBMC](https://github.com/openbmc/openbmc) checkout with
`meta-security` in-tree (it is, upstream). Tested against MACHINE
`raspberrypi3-64` with the phosphor-mmc image type.

```sh
git clone https://github.com/PkgAttest/pkgattest.git
cd pkgattest/pkg-integrity
make venv keys              # python env + signing/log/ssh keys (never committed)
make test                   # 43 tests, no hardware needed
.venv/bin/pkgattest --help  # CLI: verify-image / verify-sth / verify-package /
                            #      verify-measurements / attest
make e2e-sim                # both demo frames, laptop-only
OEROOT=/path/to/openbmc ./build-image.sh A    # baseline image
OEROOT=/path/to/openbmc ./build-image.sh B    # one package back, never published
```

The build script generates `bblayers.conf`/`local.conf` (adds
`meta-security`, `meta-security/meta-tpm`, and this repo's layer), builds
`obmc-phosphor-image`, and collects artifacts under
`pkg-integrity/artifacts/{A,B}/`.

Keys (`pkg-integrity/keys/`), built images (`artifacts/`), and the log store
(`log/`) are gitignored by design: keys stay private, images go to Releases
if shared at all.

## License

Apache-2.0 (see `LICENSE`). Recipe metadata copied from
[openembedded-core](https://git.openembedded.org/openembedded-core/)
(`meta-pkg-integrity/recipes-demo/dropbear/`) retains its upstream MIT
license.
