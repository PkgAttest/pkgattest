"""End-to-end without hardware: log in-thread, publish a synthetic image A,
verify a sim collect bundle (good -> Beat-4 OK frame; tampered dropbear ->
Beat-3 FAIL frame naming the package)."""

import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_server  # noqa: E402
from pkgintegrity.logclient import LogClient  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(BASE, "keys", "log_ed25519.key")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
PY = sys.executable


@pytest.fixture
def stack(tmp_path, measurements_file):
    log_server.LOG = log_server.Log(str(tmp_path / "log"), KEY, PUB)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), log_server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % httpd.server_address[1]

    publish = subprocess.run(
        [PY, os.path.join(BASE, "publish.py"),
         "--measurements", measurements_file, "--log", url,
         "--receipt", str(tmp_path / "receipt.json")],
        capture_output=True, text=True)
    assert publish.returncode == 0, publish.stderr
    yield url, measurements_file
    httpd.shutdown()


def _run_verify(url, measurements_file, tamper=False, extra=()):
    collect = "%s %s --measurements %s %s{nonce}" % (
        PY, os.path.join(BASE, "sim", "make-bundle.py"), measurements_file,
        "--tamper-dropbear " if tamper else "")
    return subprocess.run(
        [PY, os.path.join(BASE, "verify.py"), "--host", "sim-device",
         "--log", url, "--collect-cmd", collect, *extra],
        capture_output=True, text=True)


def test_good_image_verifies(stack):
    url, mf = stack
    r = _run_verify(url, mf)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "packages verified against tree head" in r.stdout
    assert r.stdout.strip().endswith("OK")
    assert "nonce OK" in r.stdout


def test_tampered_dropbear_named(stack):
    url, mf = stack
    r = _run_verify(url, mf, tamper=True)
    assert r.returncode == 1
    assert "dropbear 2026.91" in r.stdout
    assert "no inclusion proof against signed tree head" in r.stdout
    assert "published version for this image line: 2026.92" in r.stdout
    assert "FAIL: 1 of" in r.stdout
    # quote chain still holds — the *packages* are the problem
    assert "nonce OK" in r.stdout


def test_json_mode(stack):
    url, mf = stack
    r = _run_verify(url, mf, tamper=True, extra=("--json",))
    doc = json.loads(r.stdout)
    assert doc["ok"] is False
    assert doc["unaccounted"][0]["name"] == "dropbear"


def test_publish_rejects_drift(tmp_path, measurements_file):
    doc = json.load(open(measurements_file))
    doc["packages"][0]["leaf_hash"] = "0" * 64
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    r = subprocess.run(
        [PY, os.path.join(BASE, "publish.py"), "--measurements", str(bad),
         "--log", "http://127.0.0.1:1"],  # log never reached
        capture_output=True, text=True)
    assert r.returncode == 2
    assert "DRIFT" in r.stderr
