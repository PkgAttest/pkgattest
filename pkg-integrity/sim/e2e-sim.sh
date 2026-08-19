#!/bin/bash
# Full laptop-only end-to-end: log -> publish A -> verify OK frame ->
# verify tampered-dropbear FAIL frame. Produces both money frames with no
# Pi and no TPM. Uses a scratch log store so the real one is untouched.
set -e
cd "$(dirname "$0")/.."
PY=.venv/bin/python3; [ -x "$PY" ] || PY=python3

MEAS="${1:-artifacts/A/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json}"
if [ ! -f "$MEAS" ]; then
    echo "no $MEAS — generating a synthetic 6-package document"
    MEAS=$(mktemp --suffix=.json)
    "$PY" -c "import sys; sys.path.insert(0,'tests'); sys.path.insert(0,'.'); \
      import json, conftest; \
      json.dump(conftest.make_measurements_doc(), open('$MEAS','w'))"
fi

STORE=$(mktemp -d)
"$PY" log_server.py --port 8807 --bind 127.0.0.1 --store "$STORE" &
LOGPID=$!
trap 'kill $LOGPID 2>/dev/null; rm -rf "$STORE"' EXIT
sleep 1

"$PY" publish.py --measurements "$MEAS" --log http://127.0.0.1:8807 \
    --receipt "$STORE/receipt.json"

echo; echo "================ Beat 4 (good image) ================"
"$PY" verify.py --host sim-device --log http://127.0.0.1:8807 \
    --collect-cmd "$PY sim/make-bundle.py --measurements $MEAS {nonce}" \
    || true
echo; echo "================ Beat 3 (image B, tampered) ================"
"$PY" verify.py --host sim-device --log http://127.0.0.1:8807 \
    --collect-cmd "$PY sim/make-bundle.py --measurements $MEAS --tamper-dropbear {nonce}" \
    || true
