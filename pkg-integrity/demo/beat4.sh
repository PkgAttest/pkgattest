#!/bin/bash
# Beat 4 — the good image. Run against the Pi booted from card A.
. "$(dirname "$0")/env.sh"
frame_begin
"$PY" "$PKGI_BASE/verify.py" --host "$PKGI_HOST"
