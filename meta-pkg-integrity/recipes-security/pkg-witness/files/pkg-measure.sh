#!/bin/bash
# pkg-measure.sh — boot-time per-package integrity measurement.
#
# Re-hashes every installed package's files (from the baked build manifest in
# /usr/share/pkg-integrity), rebuilds pkg-leaf-v1 preimages and the
# pkg-merkle-v1 root, and extends the root into TPM PCR 14 (swtpm behind the
# kernel vtpm proxy).  Byte-format twin of pkg-measurements.bbclass and
# pkg-integrity/pkgintegrity/canonical.py — see pkg-integrity/SPEC.md.
#
# Evidence left in /run/pkg-integrity for the collect helper:
#   measurement-list  concatenated preimages in tree order
#   root.hex          merkle root as extended
#   pcr14.hex         PCR14 (sha256 bank) after the extend
#   ak.pub.pem        attestation key (ECC P-256, created fresh each boot)
#   status            "ok" or "degraded:<reason>"

set -u
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

RUN=/run/pkg-integrity
SHARE=/usr/share/pkg-integrity
MNT=$RUN/root
export TPM2TOOLS_TCTI=device:/dev/tpmrm0

mkdir -p "$RUN" "$RUN/work" "$RUN/pre" "$MNT"
LOG=$RUN/agent.log
exec 2>>"$LOG"
log() { echo "pkg-measure[$SECONDS s]: $*" >>"$LOG"; }
DEGRADED=""

# ---------------------------------------------------------------- swtpm ----
start_tpm() {
    modprobe tpm_vtpm_proxy 2>>"$LOG" || true
    for _ in $(seq 1 50); do [ -e /dev/vtpmx ] && break; sleep 0.2; done
    if [ ! -e /dev/vtpmx ]; then
        DEGRADED="no-vtpmx"
        log "ERROR: /dev/vtpmx missing (tpm_vtpm_proxy)"
        return 1
    fi
    mkdir -p "$RUN/tpmstate"
    swtpm chardev --vtpm-proxy --tpm2 \
        --tpmstate dir="$RUN/tpmstate" --daemon >>"$LOG" 2>&1
    for _ in $(seq 1 50); do [ -e /dev/tpmrm0 ] && break; sleep 0.2; done
    if [ ! -e /dev/tpmrm0 ]; then
        DEGRADED="no-tpmrm0"
        log "ERROR: /dev/tpmrm0 did not appear"
        return 1
    fi
    log "swtpm up (/dev/tpmrm0, vtpm-proxy)"
}

# ------------------------------------------------- private ro re-mount ----
# Hash the on-disk bytes, bypassing runtime overmounts (machine-id bind,
# /etc/dropbear tmpfs, ...).  Root device from /proc/cmdline, fallback to
# /proc/mounts.
mount_ro_root() {
    local dev=""
    for tok in $(cat /proc/cmdline); do
        case "$tok" in root=*) dev=${tok#root=} ;; esac
    done
    case "$dev" in
        PARTLABEL=*) dev=/dev/disk/by-partlabel/${dev#PARTLABEL=} ;;
        PARTUUID=*)  dev=/dev/disk/by-partuuid/${dev#PARTUUID=} ;;
    esac
    if [ -z "$dev" ] || [ ! -b "$dev" ]; then
        dev=$(awk '$2 == "/" && $1 ~ /^\/dev\// {print $1; exit}' /proc/mounts)
    fi
    if [ -n "$dev" ] && [ -b "$dev" ] && mount -o ro "$dev" "$MNT" 2>>"$LOG"; then
        log "measuring under $MNT ($dev)"
        return 0
    fi
    log "WARN: private ro mount failed (dev='$dev'); measuring live rootfs"
    DEGRADED="${DEGRADED:+$DEGRADED,}no-private-mount"
    MNT=/
    return 0
}

# ----------------------------------------------------------- measurement ----
measure() {
    local W=$RUN/work
    [ -r "$SHARE/pkgs.tsv" ] && [ -r "$SHARE/files.tsv" ] || {
        log "ERROR: baked manifest missing under $SHARE"; return 1; }

    # 1. hash every listed path (relative to $MNT), batched
    awk -F'\t' '{print $2}' "$SHARE/files.tsv" | sort -u | sed 's|^/||' \
        > "$W/paths.rel"
    ( cd "$MNT" && tr '\n' '\0' < "$W/paths.rel" \
        | xargs -0 -r sha256sum ) > "$W/hashes.raw" 2>>"$LOG"
    # "<hash>  <relpath>" -> "<abspath>\t<hash>" (paths may contain spaces)
    awk '{h=$1; sub(/^[0-9a-f]+  /,""); printf "/%s\t%s\n", $0, h}' \
        "$W/hashes.raw" > "$W/hashmap.tsv"

    # 2. join build file list with live hashes: name\tpath\tlivehash
    awk -F'\t' 'NR==FNR {H[$1]=$2; next} {print $1 "\t" $2 "\t" H[$2]}' \
        "$W/hashmap.tsv" "$SHARE/files.tsv" > "$W/joined.tsv"
    if grep -q $'\t$' "$W/joined.tsv"; then
        log "WARN: $(grep -c $'\t$' "$W/joined.tsv") file(s) missing on disk"
    fi

    # 3. one preimage file per package, in pkgs.tsv (tree) order
    rm -f "$RUN"/pre/*
    awk -F'\t' -v dir="$RUN/pre" '
        NR==FNR { L[$1] = L[$1] $2 " " $3 "\n"; C[$1]++; next }
        { idx++; out = sprintf("%s/%06d", dir, idx)
          printf "pkg-leaf-v1\nname=%s\nversion=%s\narch=%s\nfiles=%d\n%s", \
                 $1, $2, $3, C[$1]+0, L[$1] > out
          close(out) }' "$W/joined.tsv" "$SHARE/pkgs.tsv"

    # 4. leaves (batched sha256 over the preimage files, tree order)
    ( cd "$RUN/pre" && ls | sort | tr '\n' '\0' | xargs -0 -r sha256sum ) \
        | awk '{print $1}' > "$W/leaves.txt"
    ( cd "$RUN/pre" && ls | sort | tr '\n' '\0' | xargs -0 -r cat ) \
        > "$RUN/measurement-list"

    # 5. pkg-merkle-v1 root: sha256("pkg-node-v1\n<L>\n<R>\n"), odd promoted
    cp "$W/leaves.txt" "$W/lvl"
    while [ "$(wc -l < "$W/lvl")" -gt 1 ]; do
        rm -rf "$W/nodes" "$W/odd"; mkdir "$W/nodes"
        awk -v dir="$W/nodes" '
            NR % 2 == 1 { L = $0; have = 1; next }
            { i++; out = sprintf("%s/%06d", dir, i)
              printf "pkg-node-v1\n%s\n%s\n", L, $0 > out; close(out); have = 0 }
            END { if (have) print L > (dir "/odd") }' "$W/lvl"
        ( cd "$W/nodes" && ls | grep -v '^odd$' | sort | tr '\n' '\0' \
            | xargs -0 -r sha256sum ) | awk '{print $1}' > "$W/lvl.next"
        [ -f "$W/nodes/odd" ] && cat "$W/nodes/odd" >> "$W/lvl.next"
        mv "$W/lvl.next" "$W/lvl"
    done
    ROOT=$(cat "$W/lvl")
    printf '%s\n' "$ROOT" > "$RUN/root.hex"

    local baked
    baked=$(cat "$SHARE/root.sha256" 2>/dev/null || echo "?")
    if [ "$ROOT" = "$baked" ]; then
        log "root $ROOT matches baked build root"
    else
        log "NOTE: measured root $ROOT != baked $baked (measurement stands)"
    fi
    local n
    n=$(wc -l < "$W/leaves.txt")
    log "measured $n packages"
}

# ------------------------------------------------------------------ TPM ----
extend_and_keys() {
    cd "$RUN"
    tpm2_pcrextend "14:sha256=$ROOT" >>"$LOG" 2>&1 || {
        DEGRADED="${DEGRADED:+$DEGRADED,}extend-failed"; return 1; }
    tpm2_pcrread sha256:14 2>>"$LOG" \
        | awk '/14[ ]*:/{v=$NF; sub(/^0x/,"",v); print tolower(v)}' > pcr14.hex
    log "PCR14 = $(cat pcr14.hex)"

    tpm2_createek -c ek.ctx -G ecc >>"$LOG" 2>&1 &&
    tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa \
        -u ak.pub -n ak.name >>"$LOG" 2>&1 &&
    tpm2_readpublic -c ak.ctx -f pem -o ak.pub.pem >>"$LOG" 2>&1 || {
        DEGRADED="${DEGRADED:+$DEGRADED,}ak-failed"; return 1; }
    log "EK/AK ready (ECC P-256, ecdsa/sha256)"
}

# ------------------------------------------------------------------ main ----
log "start"
start_tpm || true
mount_ro_root
if measure; then
    if [ -e /dev/tpmrm0 ]; then
        extend_and_keys || true
    fi
else
    DEGRADED="${DEGRADED:+$DEGRADED,}measure-failed"
fi
[ "$MNT" != "/" ] && umount "$MNT" 2>/dev/null
if [ -z "$DEGRADED" ]; then
    echo ok > "$RUN/status"
else
    echo "degraded:$DEGRADED" > "$RUN/status"
fi
touch "$RUN/done"
log "done status=$(cat "$RUN/status")"
exit 0
