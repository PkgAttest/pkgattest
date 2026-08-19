# pkg-integrity — OCP Global Summit 2026 demo

Package-aware integrity for OpenBMC: per-package measurement at build,
boot-time re-measurement into a TPM PCR on the BMC, publication to a
transparency log, and a verifier that **names the package** no one
published. Demo plan: `../demo.md` (Demo A). Formats and trust model:
`SPEC.md`. Yocto side: `../meta-pkg-integrity/`.

## Layout

| path | what |
|---|---|
| `pkgintegrity/` | shared library: merkle (device tree + RFC 6962 log), canonical formats, TPM quote parsing, image signatures |
| `log_server.py` | transparency log (stdlib HTTP, Ed25519 STH), port 8799 |
| `publish.py` | publish image A's measurements (drift-gated) — **never image B** |
| `verify.py` | Beats 3/4: ssh collect → root/PCR/quote/inclusion-proof chain |
| `verify_image.py` | Beat 1: phosphor mmc-tar signature verification |
| `build-image.sh {A\|B}` | build the two demo images (B: dropbear 2026.91) |
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
# flash artifacts/A wic.xz to SD card A, artifacts/B to card B (bmaptool/dd)
make log                   # terminal 1: transparency log
make publish               # publish image A (image B never gets published)
make wait-device HOST=raspberrypi3-64.local
make xcheck                # three-way root agreement (build/device/fetched)
make beat1 beat2 beat4     # card A frames
make beat3 freeze          # card B: THE frame (+ fallback still)
make closer qr
```

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
