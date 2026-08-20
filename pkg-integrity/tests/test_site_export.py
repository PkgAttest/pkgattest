"""Tests for the static site exporter.

The exporter is the last place a wrong number can enter the bundle unchecked,
so most of these tests are about it *refusing* to export: drift in a
measurement document, a non-canonical log entry, or a bad tree-head signature
must all abort rather than ship a page that asserts something nobody
recomputed.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_server  # noqa: E402
from pkgintegrity import canonical, merkle, site_export  # noqa: E402

from conftest import make_measurements_doc  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(BASE, "keys", "log_ed25519.key")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
NODE = shutil.which("node")
REAL_LOG = os.path.join(BASE, "log", "log.jsonl")
REAL_ART = os.path.join(BASE, "artifacts")


def _fixture_tree(tmp_path, publish_all=True):
    """A miniature but complete world: a log store plus one artifact dir."""
    base = tmp_path / "base"
    store = base / "log"
    art = base / "artifacts" / "A"
    art.mkdir(parents=True)
    store.mkdir(parents=True)

    doc = make_measurements_doc()
    (art / "test.pkg-measurements.json").write_text(json.dumps(doc))

    # The bundle needs the real static assets (verify.js and the vendored
    # crypto) for the browser-path checks to mean anything.
    if os.path.isdir(os.path.join(BASE, "site")):
        shutil.copytree(os.path.join(BASE, "site"), str(base / "site"))

    log = log_server.Log(str(store), KEY, PUB)
    pkgs = doc["packages"] if publish_all else doc["packages"][:-1]
    log.append([{"name": p["name"], "version": p["version"],
                 "arch": p["arch"], "image_line": doc["image_line"],
                 "pkg_leaf_hash": p["leaf_hash"]} for p in pkgs])
    return base, doc


def _export(base, out):
    return site_export.export(str(base), str(out),
                              store_dir=str(base / "log"),
                              artifacts_dir=str(base / "artifacts"),
                              pub_path=PUB)


def _load_data(out, key):
    """Parse a `PKGI_DATA["key"] = <json>;` data file."""
    for name in os.listdir(os.path.join(out, "data")):
        pass
    path = None
    for root, _dirs, files in os.walk(os.path.join(out, "data")):
        for f in files:
            text = open(os.path.join(root, f), encoding="utf-8").read()
            m = re.search(r'PKGI_DATA\[%s\] = (.*);\n\Z'
                          % re.escape(json.dumps(key)), text, re.S)
            if m:
                path = os.path.join(root, f)
                return json.loads(m.group(1))
    raise AssertionError("no data file defines %r (looked in %s)" % (key, path))


# ------------------------------------------------------------------ happy path
def test_export_writes_a_complete_bundle(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    manifest = _export(base, out)

    assert manifest["records"] == len(doc["packages"])
    assert manifest["tree_size"] == len(doc["packages"])
    for required in ("data/snapshot.js", "data/leaves.js",
                     "data/sth-history.js", "data/builds-index.js",
                     "SNAPSHOT.txt", "sha256sums.txt", ".nojekyll"):
        assert (out / required).exists(), required

    snap = _load_data(str(out), "snapshot")
    assert snap["schema"] == site_export.SCHEMA
    assert snap["tree_size"] == manifest["tree_size"]
    assert snap["root_hash"] == manifest["root_hash"]
    assert snap["snapshot_id"].startswith("%d-" % manifest["tree_size"])


def test_export_is_deterministic(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    a, b = tmp_path / "a", tmp_path / "b"
    _export(base, a)
    _export(base, b)
    for root, _dirs, files in os.walk(a):
        for name in files:
            p = os.path.join(root, name)
            rel = os.path.relpath(p, a)
            assert open(p, "rb").read() == open(os.path.join(b, rel),
                                                "rb").read(), rel


def test_sha256sums_covers_every_file_and_is_correct(tmp_path):
    import hashlib
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)

    listed = {}
    for line in open(out / "sha256sums.txt"):
        digest, rel = line.split()
        listed[rel] = digest

    on_disk = set()
    for root, _dirs, files in os.walk(out):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), out)
            if rel != "sha256sums.txt":
                on_disk.add(rel)
    assert on_disk == set(listed)
    for rel, digest in listed.items():
        with open(out / rel, "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == digest, rel


def test_unpublished_build_is_named_not_hidden(tmp_path):
    """The build whose packages are not all in the log must be reported as
    unpublished, with a count — this is the demo's whole point."""
    base, doc = _fixture_tree(tmp_path, publish_all=False)
    out = tmp_path / "dist"
    manifest = _export(base, out)
    (build,) = manifest["builds"]
    assert build["status"] == "unpublished"
    assert build["unpublished_count"] == 1


def test_absolute_paths_never_reach_the_bundle(tmp_path):
    """SHA256SUMS records absolute paths from the machine that built the
    image; a public bundle must carry basenames only."""
    base, doc = _fixture_tree(tmp_path)
    art = base / "artifacts" / "A"
    (art / "SHA256SUMS").write_text(
        "%s  /home/somebody/secret/path/test.pkg-measurements.json\n"
        % ("11" * 32))
    out = tmp_path / "dist"
    _export(base, out)

    for root, _dirs, files in os.walk(out):
        for name in files:
            text = open(os.path.join(root, name), encoding="utf-8",
                        errors="replace").read()
            assert "/home/somebody" not in text, name

    build = _load_data(str(out), "build_A")
    assert "test.pkg-measurements.json" in build["artifacts"]
    assert build["artifacts"]["test.pkg-measurements.json"]["sha256"] == \
        "11" * 32


# ---------------------------------------------------------------- refusals
def test_bundle_javascript_is_pure_ascii(tmp_path):
    """Scripts are loaded classically, and over file:// there is no charset
    header — so the browser guesses. A mis-guessed byte in a path silently
    changes a leaf hash. Pure ASCII removes the guess."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)

    checked = 0
    for root, _dirs, files in os.walk(out):
        for name in sorted(files):
            if not name.endswith(".js"):
                continue
            p = os.path.join(root, name)
            with open(p, "rb") as f:
                raw = f.read()
            try:
                raw.decode("ascii")
            except UnicodeDecodeError as e:
                raise AssertionError("%s is not ASCII: %s"
                                     % (os.path.relpath(p, out), e))
            checked += 1
    assert checked >= 4, "expected several .js files, checked %d" % checked


def test_export_refuses_on_measurement_drift(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    art = base / "artifacts" / "A" / "test.pkg-measurements.json"
    bad = json.loads(art.read_text())
    bad["packages"][0]["files"][0]["sha256"] = "00" * 32
    art.write_text(json.dumps(bad))

    with pytest.raises(site_export.ExportError, match="canonicalisation"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_non_canonical_log_entry(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    store = base / "log" / "log.jsonl"
    lines = store.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["leaf"] = rec["leaf"].replace('{"arch"', '{ "arch"')
    lines[0] = json.dumps(rec)
    store.write_text("\n".join(lines) + "\n")

    with pytest.raises(site_export.ExportError, match="not canonical"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_forged_tree_head(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    hist = base / "log" / "sth-history.jsonl"
    recs = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
    recs[-1]["signature"] = "00" * 64
    hist.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                            for r in recs))

    with pytest.raises(site_export.ExportError, match="signature"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_head_that_does_not_match_the_log(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    store = base / "log" / "log.jsonl"
    lines = store.read_text().splitlines()
    store.write_text("\n".join(lines[:-1]) + "\n")   # drop an entry

    with pytest.raises(site_export.ExportError, match="does not match"):
        _export(base, tmp_path / "dist")


def test_export_refuses_without_a_signed_head(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    (base / "log" / "sth-history.jsonl").unlink()
    (base / "log" / "sth.json").unlink()
    with pytest.raises(site_export.ExportError, match="no signed tree head"):
        _export(base, tmp_path / "dist")


# ------------------------------------------------------------ the real bundle
@pytest.mark.skipif(not os.path.exists(REAL_LOG),
                    reason="production log store not present")
def test_real_export_reproduces_the_demo(tmp_path):
    out = tmp_path / "dist"
    manifest = site_export.export(BASE, str(out), pub_path=PUB)
    by_label = {b["label"]: b for b in manifest["builds"]}

    # These are derived by the exporter, never hardcoded in the site.
    assert by_label["A"]["status"] == "published"
    assert by_label["A"]["unpublished_count"] == 0
    assert by_label["B"]["status"] == "unpublished"
    assert by_label["B"]["unpublished_count"] == 1


@pytest.mark.skipif(NODE is None or not os.path.exists(REAL_LOG),
                    reason="node or production log store not present")
def test_browser_path_verifies_the_real_bundle(tmp_path):
    """Load the bundle with the same classic scripts a page loads, rebuild
    every tree and check every signature — no server involved."""
    out = tmp_path / "dist"
    site_export.export(BASE, str(out), pub_path=PUB)
    proc = subprocess.run(
        [NODE, os.path.join(BASE, "tools", "verify-bundle.js"), str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "bundle OK" in proc.stdout
    # The punchline must be derived, and named.
    assert "dropbear 2026.91" in proc.stdout
    assert "1 of 2131 packages unaccounted for" in proc.stdout


@pytest.mark.skipif(NODE is None, reason="node not present")
def test_browser_path_rejects_a_tampered_bundle(tmp_path):
    """A bundle whose leaves were altered must fail, not silently re-root."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)

    leaves_js = out / "data" / "leaves.js"
    text = leaves_js.read_text()
    tampered = text.replace("dropbear", "dr0pbear", 1)
    assert tampered != text
    leaves_js.write_text(tampered)

    proc = subprocess.run(
        [NODE, os.path.join(BASE, "tools", "verify-bundle.js"), str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1
    assert "BUNDLE INVALID" in proc.stdout
