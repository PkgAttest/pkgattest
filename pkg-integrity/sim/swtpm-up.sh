#!/bin/bash
# Rehearsal-only: a real swtpm on the LAPTOP (socket TCTI) so the full
# tpm2-tools path can be exercised without the Pi.
# Needs: pacman -S swtpm tpm2-tools
set -e
STATE=${1:-/tmp/pkgi-swtpm}
mkdir -p "$STATE"
pkill -f "swtpm socket.*$STATE" 2>/dev/null || true
swtpm socket --tpm2 --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 --tpmstate dir="$STATE" --daemon
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
echo "swtpm up; export TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI"
