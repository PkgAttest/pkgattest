import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical, merkle

PKG = canonical.PkgLeaf(
    "dropbear", "2026.92-r0", "cortexa53-nocrypto",
    [("/usr/sbin/dropbear", "aa" * 32),
     ("/usr/bin/dropbearkey", "bb" * 32),
     ("/usr/libexec/dropbear/migrate-key-location", "cc" * 32)])


def test_preimage_bytes():
    pre = PKG.preimage()
    assert pre == (
        b"pkg-leaf-v1\n"
        b"name=dropbear\n"
        b"version=2026.92-r0\n"
        b"arch=cortexa53-nocrypto\n"
        b"files=3\n"
        b"/usr/bin/dropbearkey " + b"bb" * 32 + b"\n"
        b"/usr/libexec/dropbear/migrate-key-location " + b"cc" * 32 + b"\n"
        b"/usr/sbin/dropbear " + b"aa" * 32 + b"\n")


def test_zero_file_preimage():
    p = canonical.PkgLeaf("packagegroup-x", "1.0-r0", "all", [])
    assert p.preimage().endswith(b"files=0\n")


def test_parse_roundtrip():
    pkgs = [PKG, canonical.PkgLeaf("zlib", "1.3-r0", "cortexa53-nocrypto",
                                   [("/usr/lib/libz.so.1.3", "dd" * 32)])]
    blob = b"".join(p.preimage() for p in pkgs)
    parsed = canonical.parse_measurement_list(blob)
    assert [p.name for p in parsed] == ["dropbear", "zlib"]
    assert parsed[0].files == sorted(PKG.files)
    # corrupted blob must raise
    try:
        canonical.parse_measurement_list(blob + b"garbage\n")
        assert False, "should have raised"
    except ValueError:
        pass


def test_bash_canary():
    """The cross-language canary: the same preimage + leaf + node hashing
    produced with the exact shell recipe the target agent uses (printf,
    LC_ALL=C sort, sha256sum)."""
    script = r"""
set -e
export LC_ALL=C
pre=$(mktemp)
{
  printf 'pkg-leaf-v1\n'
  printf 'name=%s\n' dropbear
  printf 'version=%s\n' 2026.92-r0
  printf 'arch=%s\n' cortexa53-nocrypto
  printf 'files=%d\n' 3
  {
    printf '%s %s\n' /usr/sbin/dropbear \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    printf '%s %s\n' /usr/bin/dropbearkey \
      bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    printf '%s %s\n' /usr/libexec/dropbear/migrate-key-location \
      cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  } | sort
} > "$pre"
leaf=$(sha256sum "$pre" | awk '{print $1}')
echo "LEAF=$leaf"
node=$(printf 'pkg-node-v1\n%s\n%s\n' "$leaf" "$leaf" | sha256sum | awk '{print $1}')
echo "NODE=$node"
rm -f "$pre"
"""
    out = subprocess.run(["bash", "-c", script], capture_output=True,
                         text=True, check=True).stdout
    values = dict(line.split("=", 1) for line in out.split() if "=" in line)
    assert values["LEAF"] == PKG.leaf_hash()
    assert values["NODE"] == merkle.device_node_hash(PKG.leaf_hash(),
                                                     PKG.leaf_hash())


def test_utf8_path_canary():
    """Real-world case: ca-certificates ships a non-ASCII filename. The
    python preimage must byte-match the shell recipe (bash is byte-
    transparent; LC_ALL=C sort == python codepoint sort under UTF-8)."""
    path = ("/usr/share/ca-certificates/mozilla/"
            "NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt")
    pkg = canonical.PkgLeaf("ca-certificates", "20260401-r0", "all",
                            [(path, "ee" * 32),
                             ("/usr/sbin/update-ca-certificates", "ff" * 32)])
    pre = pkg.preimage()
    assert pre.decode("utf-8")  # valid UTF-8
    script = (
        "set -e\nexport LC_ALL=C\npre=$(mktemp)\n"
        "{\n"
        "  printf 'pkg-leaf-v1\\n'\n"
        "  printf 'name=%s\\n' ca-certificates\n"
        "  printf 'version=%s\\n' 20260401-r0\n"
        "  printf 'arch=%s\\n' all\n"
        "  printf 'files=%d\\n' 2\n"
        "  {\n"
        "    printf '%s %s\\n' '" + path + "' " + "ee" * 32 + "\n"
        "    printf '%s %s\\n' /usr/sbin/update-ca-certificates "
        + "ff" * 32 + "\n"
        "  } | sort\n"
        "} > \"$pre\"\nsha256sum \"$pre\" | awk '{print $1}'\nrm -f \"$pre\"\n")
    out = subprocess.run(["bash", "-c", script], capture_output=True,
                         text=True, check=True).stdout.strip()
    assert out == pkg.leaf_hash()
    parsed = canonical.parse_measurement_list(pre)
    assert parsed[0].files[1][0] == path or parsed[0].files[0][0] == path


def test_measurements_doc_verify(measurements_doc):
    assert canonical.verify_measurements_doc(measurements_doc) == []
    bad = dict(measurements_doc)
    bad["merkle_root"] = "0" * 64
    assert canonical.verify_measurements_doc(bad)


def test_display_helpers():
    assert canonical.display_version("2026.92-r0") == "2026.92"
    assert canonical.display_version("1:259.5-r0") == "1:259.5"
    h = "4b1f" + "0" * 56 + "9d02"
    assert canonical.abbrev(h) == "4b1f…9d02"
