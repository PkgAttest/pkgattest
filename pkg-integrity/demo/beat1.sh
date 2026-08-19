#!/bin/bash
# Beat 1 — Today: both images signed, both verified. Nothing names a package.
. "$(dirname "$0")/env.sh"
frame_begin
echo "── today: whole-image signature verification ─────────────────────"
echo
"$PY" "$PKGI_BASE/verify_image.py" "image_A=$PKGI_A" "image_B=$PKGI_B"
echo
echo "Both signed. Both verified."
echo "Which one carries the old package? Nothing here can answer that."
