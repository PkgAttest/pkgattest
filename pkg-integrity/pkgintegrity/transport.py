"""Evidence collection from the BMC (SPEC.md section 5).

One ssh round trip: run the on-device collect helper with a fresh nonce and
read a single uncompressed tar from its stdout. `--collect-cmd` (with a
`{nonce}` placeholder) substitutes any local command for the fake-device /
sim paths.
"""

import io
import os
import shlex
import subprocess
import tarfile

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "keys")


class CollectError(Exception):
    pass


def ssh_collect_cmd(host: str, user: str = "root") -> str:
    key = os.path.join(KEYS_DIR, "id_ed25519")
    known = os.path.join(KEYS_DIR, "known_hosts")
    # Host keys are per-boot on the demo image (tmpfs /etc/dropbear); ssh
    # transport is not the trust anchor here — the TPM quote is.
    return (
        "ssh -i %s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=no "
        "-o LogLevel=ERROR -o ConnectTimeout=10 %s@%s "
        "/usr/libexec/pkg-integrity/collect {nonce}"
        % (shlex.quote(key), shlex.quote(known), user, host)
    )


def collect(cmd_template: str, nonce_hex: str) -> dict:
    cmd = cmd_template.format(nonce=nonce_hex)
    proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise CollectError("collect failed (%d): %s"
                           % (proc.returncode,
                              proc.stderr.decode(errors="replace")[-500:]))
    members = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
            for m in tar.getmembers():
                if m.isfile():
                    members[os.path.basename(m.name)] = \
                        tar.extractfile(m).read()
    except tarfile.TarError as e:
        raise CollectError("bad evidence tar: %s" % e)
    for required in ("measurement-list", "root.hex", "meta.json"):
        if required not in members:
            raise CollectError("evidence bundle missing %r" % required)
    return members
