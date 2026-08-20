import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_server  # noqa: E402
from pkgintegrity import cli  # noqa: E402
from pkgintegrity.logclient import LogClient  # noqa: E402

from conftest import make_measurements_doc  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(BASE, "keys", "log_ed25519.key")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
A_TAR = os.path.join(BASE, "artifacts", "A",
                     "obmc-phosphor-image-raspberrypi3-64.ext4.mmc.tar")
BUILD_PUB = os.path.join(BASE, "keys", "build-rsa4096.pub.pem")


@pytest.fixture
def server(tmp_path):
    log_server.LOG = log_server.Log(str(tmp_path), KEY, PUB)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), log_server.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()


def _publish_doc(url, doc):
    records = [{"name": p["name"], "version": p["version"],
                "arch": p["arch"], "image_line": doc["image_line"],
                "pkg_leaf_hash": p["leaf_hash"]}
               for p in doc["packages"]]
    return LogClient(url).add_entries(records)


# ------------------------------------------------------------------ verify-sth
def test_verify_sth_ok(server, capsys):
    _publish_doc(server, make_measurements_doc())
    rc = cli.main(["verify-sth", "--log", server, "--log-pub", PUB,
                   "--print-payload"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "signature: OK" in out
    assert "payload:   pkg-log-sth-v1 " in out
    assert "size:      6" in out


def test_verify_sth_json(server, capsys):
    rc = cli.main(["verify-sth", "--log", server, "--log-pub", PUB,
                   "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["signature_ok"] is True
    assert doc["sth"]["tree_size"] == 0


def test_verify_sth_tampered_file(server, tmp_path, capsys):
    _publish_doc(server, make_measurements_doc())
    sth = LogClient(server).sth()
    sth["root_hash"] = ("00" * 32)
    f = tmp_path / "sth.json"
    f.write_text(json.dumps(sth))
    rc = cli.main(["verify-sth", "--log-pub", PUB,
                   "--sth-file", str(f)])
    assert rc == 1
    assert "signature: FAIL" in capsys.readouterr().out


def test_verify_sth_unreachable_log():
    rc = cli.main(["verify-sth", "--log", "http://127.0.0.1:1",
                   "--log-pub", PUB])
    assert rc == 2


# -------------------------------------------------------------- verify-package
def test_verify_package_ok(server, capsys):
    _publish_doc(server, make_measurements_doc())
    rc = cli.main(["verify-package", "dropbear", "zlib",
                   "--log", server, "--log-pub", PUB])
    out = capsys.readouterr().out
    assert rc == 0
    assert "STH signature OK" in out
    assert "dropbear 2026.92 (cortexa53-nocrypto)" in out
    assert out.count("inclusion proof: OK") == 2


def test_verify_package_unpublished(server, capsys):
    _publish_doc(server, make_measurements_doc())
    rc = cli.main(["verify-package", "nonexistent",
                   "--log", server, "--log-pub", PUB])
    assert rc == 1
    assert "no published record" in capsys.readouterr().out


def test_verify_package_version_filter(server, capsys):
    _publish_doc(server, make_measurements_doc())
    rc = cli.main(["verify-package", "dropbear", "--version", "2026.91",
                   "--log", server, "--log-pub", PUB])
    assert rc == 1
    assert "no published record" in capsys.readouterr().out
    # display version (without -rN) also matches
    rc = cli.main(["verify-package", "dropbear", "--version", "2026.92",
                   "--log", server, "--log-pub", PUB])
    capsys.readouterr()
    assert rc == 0


def test_verify_package_json(server, capsys):
    _publish_doc(server, make_measurements_doc())
    rc = cli.main(["verify-package", "dropbear", "--json",
                   "--log", server, "--log-pub", PUB])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["ok"] is True
    (rec,) = doc["packages"]["dropbear"]
    assert rec["inclusion_ok"] is True and rec["version"] == "2026.92-r0"


# --------------------------------------------------------- verify-measurements
def test_verify_measurements_ok(measurements_file, capsys):
    rc = cli.main(["verify-measurements", measurements_file])
    out = capsys.readouterr().out
    assert rc == 0 and ": OK" in out


def test_verify_measurements_tampered(tmp_path, capsys):
    doc = make_measurements_doc()
    doc["packages"][0]["files"][0]["sha256"] = "00" * 32
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(doc))
    rc = cli.main(["verify-measurements", str(f)])
    out = capsys.readouterr().out
    assert rc == 1 and "FAIL" in out and "leaf mismatch" in out


def test_verify_measurements_not_a_doc(tmp_path):
    f = tmp_path / "x.json"
    f.write_text("{}")
    assert cli.main(["verify-measurements", str(f)]) == 2


# ---------------------------------------------------------------- verify-image
@pytest.mark.skipif(not (os.path.exists(A_TAR)
                         and os.path.exists(BUILD_PUB)),
                    reason="built image A artifacts not present")
def test_verify_image_real_artifact(capsys):
    rc = cli.main(["verify-image", "image_A=%s" % A_TAR,
                   "--pubkey", BUILD_PUB])
    out = capsys.readouterr().out
    assert rc == 0 and "verified: OK" in out


# --------------------------------------------------------------------- plumbing
def test_unknown_command_exits_2():
    with pytest.raises(SystemExit) as e:
        cli.main(["frobnicate"])
    assert e.value.code == 2


def test_attest_dispatch_help():
    # 'attest' routes to pkgintegrity.attest's own parser
    with pytest.raises(SystemExit) as e:
        cli.main(["attest", "--help"])
    assert e.value.code == 0


CONSOLE = os.path.join(BASE, ".venv", "bin", "pkgattest")


@pytest.mark.skipif(not os.path.exists(CONSOLE),
                    reason="pkgattest not installed in .venv")
def test_console_script():
    p = subprocess.run([CONSOLE, "--help"], capture_output=True, text=True)
    assert p.returncode == 0
    for cmdname in ("verify-image", "verify-sth", "verify-package",
                    "verify-measurements", "attest"):
        assert cmdname in p.stdout
