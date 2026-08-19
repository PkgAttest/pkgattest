#!/bin/bash
# Beat 3 — THE detection. Run against the Pi booted from card B.
# Ends holding the FAIL frame (freeze >= 1s in the recording).
. "$(dirname "$0")/env.sh"
frame_begin
"$PY" "$PKGI_BASE/verify.py" --host "$PKGI_HOST"
