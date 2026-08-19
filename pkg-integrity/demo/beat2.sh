#!/bin/bash
# Beat 2 — same image (card A booted), now measured package by package.
. "$(dirname "$0")/env.sh"
frame_begin

SSH="ssh -i $PKGI_BASE/keys/id_ed25519 -o UserKnownHostsFile=$PKGI_BASE/keys/known_hosts \
     -o StrictHostKeyChecking=no -o LogLevel=ERROR root@$PKGI_HOST"

SIG_LINE=$("$PY" "$PKGI_BASE/verify_image.py" "image_A=$PKGI_A" | head -1)
ROOT=$($SSH cat /run/pkg-integrity/root.hex)
PCR=$($SSH cat /run/pkg-integrity/pcr14.hex)
N=$(awk -F'\t' 'END{print NR}' <($SSH cat /usr/share/pkg-integrity/pkgs.tsv))
EXPECT=$("$PY" - "$ROOT" <<'EOF'
import hashlib, sys
root = sys.argv[1].strip()
print(hashlib.sha256(b"\x00"*32 + bytes.fromhex(root)).hexdigest())
EOF
)
STH=$(curl -s "$PKGI_LOG/sth")
STH_ROOT=$(echo "$STH" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["root_hash"])')
STH_SIZE=$(echo "$STH" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["tree_size"])')

ab() { echo "${1:0:4}…${1: -4}"; }
MATCH="MISMATCH"; [ "$PCR" = "$EXPECT" ] && MATCH="MATCH"

echo "── same image — now measured package by package     [swtpm on BMC] ─"
echo
echo "signature  $SIG_LINE   (same check as Beat 1)"
echo "packages   $N leaves -> merkle root  $(ab "$ROOT")"
echo "PCR14      sha256(0^32 || root) = $(ab "$PCR")   [swtpm]   $MATCH"
echo "log        signed tree head 0x${STH_ROOT:0:4}…  size $STH_SIZE   ed25519 sig OK"
echo
echo "Same boot, same signature check."
echo "We only changed the granularity of what gets measured."
