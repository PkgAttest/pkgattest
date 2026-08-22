#!/bin/bash
# build-image.sh {A|B|C|D} — build the OCP-2026 demo images.
#   A: baseline image (dropbear 2026.92), package-aware measurement enabled.
#   B: identical except dropbear pinned back to 2026.91. Never published.
#   D: first build carrying the (unowned) leaf, so that files no package
#      claims -- /etc/passwd, /etc/shadow, ld.so.cache -- are inside the
#      device root. Published.
#   C: a later build of the same line (new BUILD_ID). Published, so the log
#      gets a second signed tree head — consistency proofs need two. C must
#      never alter A or B: their artifacts are already copied into
#      artifacts/{A,B}/ and are not rebuilt.
#
# Replicates rpi3-build.sh's conf generation (the meta-evb-raspberrypi
# template has no layer.conf, so conf files are pre-generated), then adds the
# integrity layers, the demo signing key, and the tpm2 machine include.
# Artifacts land in pkg-integrity/artifacts/{A,B}/.
set -e

VARIANT="${1:-}"
case "$VARIANT" in A|B|C|D) ;; *) echo "usage: $0 {A|B|C|D}" >&2; exit 2 ;; esac

# BUILD_ID pins os-release's BUILD_ID (a measured file). C uses a distinct one
# so it is a genuinely different build of the same source.
case "$VARIANT" in
    A|B) BUILD_ID_VAL="ocp2026-demo" ;;
    C)   BUILD_ID_VAL="ocp2026-demo-c" ;;
    D)   BUILD_ID_VAL="ocp2026-demo-d" ;;
esac

# DEMO_ROOT = parent of this script's dir (works from any clone location);
# OEROOT = the openbmc tree (override via env when the demo repo lives
# outside it).
DEMO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OEROOT="${OEROOT:-/home/zimmerle/obmc/openbmc}"
BUILD="$OEROOT/build/rpi3-64"
ART="$DEMO_ROOT/pkg-integrity/artifacts/$VARIANT"
cd "$OEROOT"

# Force python3 -> 3.13 (host default 3.14 unsupported by this BitBake)
mkdir -p "$OEROOT/.pyshim"
ln -sf /usr/bin/python3.13 "$OEROOT/.pyshim/python3"
export PATH="$OEROOT/.pyshim:$PATH"
echo "python3 -> $(command -v python3) ($(python3 --version))"

# Clean git config for fetches (user's gitconfig rewrites https->ssh)
export GIT_CONFIG_GLOBAL="$OEROOT/.gitconfig-build"
export RUST_MIN_STACK=16777216

TMPL=meta-evb/meta-evb-raspberrypi/conf/templates/default
mkdir -p "$BUILD/conf"

# bblayers.conf from template + integrity layers
sed "s|##OEROOT##|$OEROOT|g" "$TMPL/bblayers.conf.sample" > "$BUILD/conf/bblayers.conf"
cat >> "$BUILD/conf/bblayers.conf" <<EOF
BBLAYERS += " \\
  $OEROOT/meta-security \\
  $OEROOT/meta-security/meta-tpm \\
  $DEMO_ROOT/meta-pkg-integrity \\
  "
EOF

# local.conf from template: MACHINE, mmc image type, licenses, kernel type
sed -e "s|##OEROOT##|$OEROOT|g" \
    -e 's|^MACHINE .*|MACHINE = "raspberrypi3-64"|' \
    "$TMPL/local.conf.sample" > "$BUILD/conf/local.conf"
sed -i 's|^require conf/machine/include/obmc-bsp-common.inc|require conf/distro/include/phosphor-mmc.inc\n&|' \
    "$BUILD/conf/local.conf"
cat >> "$BUILD/conf/local.conf" <<EOF
LICENSE_FLAGS_ACCEPTED = "synaptics-killswitch"
KERNEL_IMAGETYPE = "Image"
KERNEL_IMAGETYPES = "Image"

# --- pkg-integrity demo configuration ---
require conf/machine/include/tpm2.inc
SIGNING_KEY = "$DEMO_ROOT/pkg-integrity/keys/konasense-demo.priv"
BUILD_ID = "$BUILD_ID_VAL"
EOF

if [ "$VARIANT" = "B" ]; then
    echo 'PREFERRED_VERSION_dropbear = "2026.91"' >> "$BUILD/conf/local.conf"
fi

unset TEMPLATECONF
source oe-init-build-env "$BUILD"

echo "=== variant $VARIANT | MACHINE ==="; grep '^MACHINE' conf/local.conf
[ "$VARIANT" = "B" ] && bitbake dropbear -c fetch   # fail fast on old tarball

bitbake obmc-phosphor-image
echo "BITBAKE_DONE variant=$VARIANT"

# Collect the per-variant artifacts (resolve the timestamped names)
DEPLOY="$BUILD/tmp/deploy/images/raspberrypi3-64"
BASE=obmc-phosphor-image-raspberrypi3-64
mkdir -p "$ART"
for ext in wic.xz ext4.mmc.tar manifest pkg-measurements.json; do
    src="$DEPLOY/$BASE.$ext"
    [ -e "$src" ] || { echo "MISSING artifact: $src" >&2; exit 1; }
    cp -L "$src" "$ART/$BASE.$ext"
done
sha256sum "$ART"/* | tee "$ART/SHA256SUMS"
echo "ARTIFACTS_OK variant=$VARIANT -> $ART"
