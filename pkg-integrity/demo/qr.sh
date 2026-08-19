#!/bin/bash
# Q&A flourish — QR pointing at the log's signed tree head on the LAN.
# Backup material only; never on the talk's critical path.
. "$(dirname "$0")/env.sh"

LAN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
URL="http://${LAN_IP:-127.0.0.1}:8799/"
echo "STH page: $URL"
command -v qrencode >/dev/null && qrencode -t ANSIUTF8 "$URL"
"$PY" - "$URL" "$PKGI_BASE/demo/frames/sth-qr.png" <<'EOF'
import sys
import qrcode
img = qrcode.make(sys.argv[1])
img.save(sys.argv[2])
print("saved", sys.argv[2])
EOF
