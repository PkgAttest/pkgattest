# pkg-integrity — formats and trust model (v1)

Binding spec for the OCP Global Summit 2026 "Package-Aware Integrity" demo.
Three implementations must produce byte-identical results and all three must
change together: `meta-pkg-integrity/classes/pkg-measurements.bbclass`
(build, python), `meta-pkg-integrity/.../pkg-measure.sh` (target, bash), and
`pkgintegrity/canonical.py` (host, python).

## 1. Package leaf preimage — `pkg-leaf-v1`

One ASCII byte string per installed package, LF line endings, no trailing
blank line:

```
pkg-leaf-v1
name=<opkg package name>
version=<opkg version, incl. epoch and -rN suffix>
arch=<opkg architecture>
files=<N>
<path> <sha256hex>          (N lines)
```

Rules:
- File lines: absolute path, ONE space, 64 lowercase hex chars. Emit with
  `printf '%s %s\n'` — never raw `sha256sum` output (two-space separator).
- File set: the package's installed **regular, non-symlink** files, from the
  build's pkgdata FILES_INFO, minus `PKG_MEASUREMENTS_EXCLUDE`
  (`/etc/machine-id /etc/version`; both unowned in this image anyway) and
  minus files absent from the final rootfs. `files=0` (header-only) is legal.
- Sort: file lines ascending bytewise (`LC_ALL=C`). Paths are unique, so
  line sort == path sort. Paths are UTF-8 (real example in this image:
  ca-certificates' `…_Főtanúsítvány.crt`); python codepoint sort equals
  bytewise UTF-8 sort because UTF-8 is order-preserving. The build fails on
  newline or tab in a path (framing/TSV safety).
- Leaves measure INSTALLED state: postinst-modified files hash as-installed.
- `leaf_hash = sha256(preimage_bytes)` (plain; preimages are self-labeled).

### 1a. The unowned-files leaf

Every regular file in the image that no package claims is covered by one
further leaf, so that nothing in the rootfs sits outside the device root.
Without it `/etc/passwd`, `/etc/shadow`, `/etc/ld.so.cache` and the indexes
`depmod` writes are in no leaf, therefore no root, therefore no PCR — and
adding a root user would change nothing the mechanism commits to.

It is an ordinary `pkg-leaf-v1`, not a new format:

```
name=(unowned)   version=1.0   arch=all
```

- The name is one no opkg package can have (opkg names cannot contain
  parentheses), so it cannot collide, and `(` is 0x28 — below every letter
  and digit — so it sorts first under the §2 ordering with no special rule.
- Metadata is constant so the leaf is a pure function of the file set: two
  builds whose unowned files match produce one leaf and deduplicate in the
  log, exactly as an unchanged package does.
- File set: every regular, non-symlink file not claimed by a package, minus
  `PKG_MEASUREMENTS_EXCLUDE` and minus anything under
  `${PKG_MEASUREMENTS_ROOTFS_DIR}` — the agent inputs, which cannot be
  measured by the pass that writes them.
- Because it is an ordinary leaf, the on-device agent, `canonical.py`,
  `verify.js` and `publish.py` need no special case: it arrives through
  `pkgs.tsv`/`files.tsv` and the `packages` array like anything else.

Excluded by `PKG_MEASUREMENTS_EXCLUDE` and therefore still measured by
nothing: `/etc/machine-id`, `/etc/version`, `/etc/timestamp`. They change
every boot or every build, so measuring them would make the root unstable
rather than meaningful. A deliberate, named gap.

## 2. Device tree — `pkg-merkle-v1`

- Leaf order: ascending bytewise sort of package name (unique per image).
- Node: `sha256(b"pkg-node-v1\n" + L_hex + b"\n" + R_hex + b"\n")` over the
  **lowercase hex** child digests; odd node promoted to the next level.
- Deliberately not RFC 6962: it is recomputed in bash on the BMC and the
  hex/text form is exactly reproducible with busybox `sha256sum`. Domain
  separation holds because leaf inputs start `pkg-leaf-v1` and node inputs
  start `pkg-node-v1` (fixed 130+12 byte shape).
- `measurement-list` = byte-exact concatenation of all preimages in tree
  order (self-delimiting via the `files=<N>` header).

## 3. PCR binding

PCR **14**, sha256 bank, exactly one
`tpm2_pcrextend 14:sha256=<root_hex>` per boot (PCR14 resets to zeros):
`expected_pcr14 = sha256(b"\x00"*32 + bytes.fromhex(root_hex))`.

## 4. Transparency log — `log-leaf-v1`

Leaf data = canonical JSON, no trailing LF:
`json.dumps({"arch":…,"image_line":…,"name":…,"pkg_leaf_hash":…,
"schema":"log-leaf-v1","version":…}, sort_keys=True, separators=(",",":"))`
where `pkg_leaf_hash` is the §1 leaf hash — the log commits to file-level
content without storing file lists. Same package published for two image
lines yields distinct leaves ("published version for THIS image line").

Log tree = **RFC 6962**: `leaf = sha256(0x00 || data)`,
`node = sha256(0x01 || l || r)`, MTH split at the largest power of two < n;
standard inclusion and consistency proofs.

Signed tree head payload (deterministic, not JSON):
`b"pkg-log-sth-v1 <size> <root_hex> <unix_ts>\n"`, Ed25519
(`keys/log_ed25519.key`).

## 5. Evidence collection (device → verifier)

`/usr/libexec/pkg-integrity/collect <nonce_hex>` (1–64 lowercase hex; the
verifier sends 32 random bytes) streams one uncompressed tar to stdout:

| member | content |
|---|---|
| `measurement-list` | §2 concatenation, as re-measured at boot |
| `root.hex` | 64 lowercase hex + LF — the value extended into PCR14 |
| `pcr14.hex` | PCR14 sha256-bank readout, 64 lowercase hex + LF |
| `ak.pub.pem` | `tpm2_readpublic -c ak.ctx -f pem` |
| `quote.msg` | `tpm2_quote -m` — raw marshaled TPMS_ATTEST |
| `quote.sig` | `tpm2_quote -s … -f plain` — raw ECDSA signature |
| `pcrs.bin` | `tpm2_quote -o` PCR dump (tpm2_checkquote cross-check only) |
| `meta.json` | {machine, version, timestamp, nonce, status} |

AK/EK: ECC P-256, `ecdsa`/`sha256`, created fresh each boot under the EK
hierarchy (swtpm state is per-boot).

## 6. Build output — `pkg-measurements-v1`

`<image>.pkg-measurements.json` in the deploy dir:
`{"schema":"pkg-measurements-v1","image_line","machine","image_name",
"version","timestamp","merkle_root","packages":[{"name","version","arch",
"leaf_hash","files":[{"path","sha256"}]}]}`, packages sorted by name.
`publish.py` recomputes every leaf and the root and refuses to publish on
mismatch.

## 7. Trust model (stated honestly)

- The TPM is **swtpm** (labeled on screen): software root of trust, no
  hardware anchoring. The demo's claim is about *granularity*, not HW RoT.
- The AK is accepted TOFU (no EK certificate chain) — quote verification
  proves freshness (nonce) and that PCR14 matches the claimed root under
  that AK.
- The boot agent is part of the measured image; a compromised image could
  lie. Production integration would move the measurement earlier in the
  boot chain — out of demo scope.
- The log guarantees append-only publication (Ed25519-pinned STH,
  consistency proofs). The detection claim is precisely: *"this device
  attests to running a package for which no publication record exists in
  the log for its image line."*
- Image signatures (Beat 1) are the stock OpenBMC flow
  (`image_types_phosphor.bbclass`): detached RSA-4096/SHA256 per blob +
  `image-full.sig` over the concatenated `.sig` files **in en_US.UTF-8
  collation order** (`image-kernel.sig image-rofs.sig image-rwfs.sig
  image-u-boot.sig MANIFEST.sig publickey.sig`) — empirically verified;
  C-locale order does not verify.
