#!/bin/bash
# 10-second closer — one package rebuilt: payload size + one changed branch.
. "$(dirname "$0")/env.sh"
frame_begin

IPK=$(ls /home/zimmerle/obmc/openbmc/build/rpi3-64/tmp/deploy/ipk/cortexa53-nocrypto/dropbear_*.ipk 2>/dev/null | head -1)
WIC_BYTES=$(stat -c%s "$PKGI_A_WIC" 2>/dev/null || echo 66060608)
IPK_BYTES=$(stat -c%s "$IPK" 2>/dev/null || echo 214294)
RATIO=$((WIC_BYTES / IPK_BYTES))

ROOT_A=$("$PY" -c "import json;print(json.load(open('$PKGI_A_MEAS'))['merkle_root'])" 2>/dev/null || echo "")
ROOT_B=$("$PY" -c "import json;print(json.load(open('$PKGI_B_MEAS'))['merkle_root'])" 2>/dev/null || echo "")

fmt() { printf "%'d" "$1"; }
ab() { echo "${1:0:4}…${1: -4}"; }

echo "── update payload: one package changed ────────────────────────────"
echo
printf "  full image update:   %12s bytes   (wic.xz)\n" "$(fmt "$WIC_BYTES")"
printf "  dropbear package:    %12s bytes   (ipk)  — ~%dx smaller\n" \
       "$(fmt "$IPK_BYTES")" "$RATIO"
echo
echo "            root_A $( [ -n "$ROOT_A" ] && ab "$ROOT_A" )        root_B $( [ -n "$ROOT_B" ] && ab "$ROOT_B" )"
echo "               ├────────┐                  ├────────┐"
echo "               ○        ○                  ○        ●   <- one branch"
echo "              ╱ ╲      ╱ ╲                ╱ ╲      ╱ ╲     changed"
echo "             ○   ○    ○   ○              ○   ○    ○   ●"
echo "                                                 dropbear"
