# Shared demo environment. Source from the beat scripts.
export PKGI_HOST="${PKGI_HOST:-raspberrypi3-64.local}"
# export PKGI_HOST=192.168.7.2          # static-IP fallback (direct ethernet)
export PKGI_IMAGE_LINE="${PKGI_IMAGE_LINE:-rpi3-openbmc}"
export PKGI_LOG="${PKGI_LOG:-http://127.0.0.1:8799}"

PKGI_BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PKGI_BASE
export PKGI_A="$PKGI_BASE/artifacts/A/obmc-phosphor-image-raspberrypi3-64.ext4.mmc.tar"
export PKGI_B="$PKGI_BASE/artifacts/B/obmc-phosphor-image-raspberrypi3-64.ext4.mmc.tar"
export PKGI_A_WIC="$PKGI_BASE/artifacts/A/obmc-phosphor-image-raspberrypi3-64.wic.xz"
export PKGI_A_MEAS="$PKGI_BASE/artifacts/A/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json"
export PKGI_B_MEAS="$PKGI_BASE/artifacts/B/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json"
PY="$PKGI_BASE/.venv/bin/python3"
[ -x "$PY" ] || PY=python3
export PY

frame_begin() { clear; tput civis 2>/dev/null; trap 'tput cnorm 2>/dev/null' EXIT; }
