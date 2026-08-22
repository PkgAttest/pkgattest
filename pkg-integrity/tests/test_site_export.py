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
    assert build["status"] == "packages-missing"
    assert build["unpublished_count"] == 1


def test_absolute_paths_never_reach_the_bundle(tmp_path):
    """SHA256SUMS records absolute paths from the machine that built the
    image; a public bundle must carry basenames only."""
    import hashlib
    base, doc = _fixture_tree(tmp_path)
    art = base / "artifacts" / "A"
    doc_path = art / "test.pkg-measurements.json"
    real = hashlib.sha256(doc_path.read_bytes()).hexdigest()
    (art / "SHA256SUMS").write_text(
        "%s  /home/somebody/secret/path/test.pkg-measurements.json\n" % real)
    out = tmp_path / "dist"
    _export(base, out)

    for root, _dirs, files in os.walk(out):
        for name in files:
            text = open(os.path.join(root, name), encoding="utf-8",
                        errors="replace").read()
            assert "/home/somebody" not in text, name

    build = _load_data(str(out), "build_A")
    assert "test.pkg-measurements.json" in build["artifacts"]
    # The digest the page shows is taken from the bytes, not copied from
    # SHA256SUMS — that file is only ever a cross-check.
    assert build["artifacts"]["test.pkg-measurements.json"]["sha256"] == real


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


def test_export_refuses_leaves_beyond_the_signed_head(tmp_path):
    """The blocking one: a record past `tree_size` is covered by no signature,
    so if the exporter resolved membership over the whole store, appending one
    line to log.jsonl would make an unpublished package look published — no
    signing key needed."""
    base, doc = _fixture_tree(tmp_path, publish_all=False)
    missing = doc["packages"][-1]
    forged = canonical.log_leaf_data(
        doc["image_line"], missing["name"], missing["version"],
        missing["arch"], missing["leaf_hash"]).decode("ascii")
    store = base / "log" / "log.jsonl"
    with open(store, "a") as f:
        f.write(json.dumps({"index": 999, "leaf": forged}) + "\n")

    with pytest.raises(site_export.ExportError, match="signed by nothing"):
        _export(base, tmp_path / "dist")


def test_export_takes_the_largest_head_not_the_last_line(tmp_path):
    """Reordering sth-history.jsonl must not change what gets exported."""
    base, _ = _fixture_tree(tmp_path)
    hist = base / "log" / "sth-history.jsonl"
    recs = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
    assert len(recs) >= 2
    hist.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                            for r in reversed(recs)))
    manifest = _export(base, tmp_path / "dist")
    assert manifest["tree_size"] == max(r["tree_size"] for r in recs)


def test_export_refuses_a_wrong_artifact_digest(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    (base / "artifacts" / "A" / "SHA256SUMS").write_text(
        "%s  test.pkg-measurements.json\n" % ("11" * 32))
    with pytest.raises(site_export.ExportError, match="hashes to"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_receipt_that_disagrees(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    (base / "artifacts" / "A" / "publication-receipt.json").write_text(
        json.dumps({"merkle_root": "22" * 32}))
    with pytest.raises(site_export.ExportError, match="publication receipt"):
        _export(base, tmp_path / "dist")


def test_export_refuses_two_measurement_documents(tmp_path):
    """Picking the alphabetically-first would let a stale document win, and
    its device root and PCR14 would go on the page."""
    base, doc = _fixture_tree(tmp_path)
    stale = dict(doc, image_name="STALE-IMAGE")
    (base / "artifacts" / "A" / "AAA-stale.pkg-measurements.json").write_text(
        json.dumps(stale))
    with pytest.raises(site_export.ExportError,
                       match="exactly one measurement document"):
        _export(base, tmp_path / "dist")


def test_export_refuses_an_unusable_build_label(tmp_path):
    """The label becomes a filename and a URL segment on the page."""
    base, doc = _fixture_tree(tmp_path)
    bad = base / "artifacts" / 'a" onerror=x'
    bad.mkdir()
    (bad / "test.pkg-measurements.json").write_text(json.dumps(doc))
    with pytest.raises(site_export.ExportError, match="not a usable label"):
        _export(base, tmp_path / "dist")


def test_export_refuses_packages_that_are_not_name_sorted(tmp_path):
    """SPEC.md section 2 requires name-sorted leaves and the on-device bash
    sorts, so an unsorted document yields a root no BMC can reproduce.
    verify_measurements_doc hashes in document order and cannot catch it."""
    base, doc = _fixture_tree(tmp_path)
    shuffled = dict(doc)
    shuffled["packages"] = list(reversed(doc["packages"]))
    shuffled["merkle_root"] = merkle.device_root(
        [p["leaf_hash"] for p in shuffled["packages"]])
    (base / "artifacts" / "A" / "test.pkg-measurements.json").write_text(
        json.dumps(shuffled))
    with pytest.raises(site_export.ExportError, match="name-sorted"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_receipt_citing_an_unsigned_head(tmp_path):
    """A receipt carries a full signed tree head. Shipping it unchecked would
    put a tree_size, root and signature on the page beside numbers that were
    genuinely recomputed, with nothing to tell them apart."""
    base, doc = _fixture_tree(tmp_path)
    (base / "artifacts" / "A" / "publication-receipt.json").write_text(
        json.dumps({"merkle_root": doc["merkle_root"],
                    "sth": {"tree_size": 999999, "root_hash": "ff" * 32,
                            "timestamp": 1, "signature": "ee" * 64}}))
    with pytest.raises(site_export.ExportError, match="signed history"):
        _export(base, tmp_path / "dist")


def test_export_refuses_a_receipt_that_rewrites_a_real_head(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    hist = [json.loads(l) for l
            in (base / "log" / "sth-history.jsonl").read_text().splitlines()
            if l.strip()]
    real = hist[-1]
    (base / "artifacts" / "A" / "publication-receipt.json").write_text(
        json.dumps({"merkle_root": doc["merkle_root"],
                    "sth": dict(real, signature="ee" * 64)}))
    with pytest.raises(site_export.ExportError, match="disagrees with the"):
        _export(base, tmp_path / "dist")


def test_export_refuses_an_empty_measurement_document(tmp_path):
    """Must name the build at fault, not surface a bare ValueError from deep
    inside merkle.device_root."""
    base, doc = _fixture_tree(tmp_path)
    (base / "artifacts" / "A" / "test.pkg-measurements.json").write_text(
        json.dumps(dict(doc, packages=[])))
    with pytest.raises(site_export.ExportError, match="no packages"):
        _export(base, tmp_path / "dist")


def test_working_tree_junk_stays_out_of_the_bundle(tmp_path):
    """sha256sums.txt is what "reproduce the published bytes" rests on, so it
    must not depend on whether someone left an editor backup lying around."""
    base, _ = _fixture_tree(tmp_path)
    site = base / "site"
    (site / ".verify.js.swp").write_text("junk")
    (site / "notes~").write_text("junk")
    (site / "__pycache__").mkdir(exist_ok=True)
    (site / "__pycache__" / "x.pyc").write_text("junk")

    out = tmp_path / "dist"
    _export(base, out)
    listed = [line.split()[1] for line in
              (out / "sha256sums.txt").read_text().splitlines()]
    for junk in (".verify.js.swp", "notes~", "__pycache__/x.pyc"):
        assert junk not in listed, "%s reached the bundle" % junk
    assert not (out / "__pycache__").exists()


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
    assert by_label["A"]["status"] == "all-packages-published"
    assert by_label["A"]["unpublished_count"] == 0
    assert by_label["B"]["status"] == "packages-missing"
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


def _patch_data(path, key, mutate):
    """Rewrite a `PKGI_DATA["key"] = <json>;` file in place."""
    text = path.read_text()
    m = re.search(r'PKGI_DATA\[%s\] = (.*);\n\Z'
                  % re.escape(json.dumps(key)), text, re.S)
    assert m, "no assignment for %r in %s" % (key, path)
    value = mutate(json.loads(m.group(1)))
    path.write_text(text[:m.start(1)]
                    + json.dumps(value, separators=(",", ":"), sort_keys=True)
                    + ";\n")


@pytest.mark.skipif(NODE is None, reason="node not present")
def test_appending_an_unsigned_leaf_is_caught(tmp_path):
    """The attack that motivated scoping membership to the signed head.

    Every leaf past `tree_size` is covered by no signature, so if membership
    were decided over the whole leaf array, appending one unsigned line to
    leaves.js would be enough to make an unpublished package look published —
    no key required, and it would defeat the demo's entire punchline.
    """
    base, doc = _fixture_tree(tmp_path, publish_all=False)
    out = tmp_path / "dist"
    _export(base, out)

    # Whatever package was withheld, forge a log entry for it.
    missing = doc["packages"][-1]
    forged = canonical.log_leaf_data(
        doc["image_line"], missing["name"], missing["version"],
        missing["arch"], missing["leaf_hash"]).decode("ascii")

    _patch_data(out / "data" / "leaves.js", "leaves",
                lambda arr: arr + [forged])
    _patch_data(out / "data" / "builds-index.js", "builds",
                lambda builds: [dict(b, status="all-packages-published",
                                     unpublished_count=0) for b in builds])

    proc = subprocess.run(
        [NODE, os.path.join(BASE, "tools", "verify-bundle.js"), str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1, proc.stdout
    assert "BUNDLE INVALID" in proc.stdout
    assert "signed by nothing" in proc.stdout


@pytest.mark.skipif(NODE is None, reason="node not present")
def test_unpinned_key_is_declared_not_hidden(tmp_path):
    """The bundle ships the key it verifies against, so a re-signed bundle
    verifies against itself. That limit must be printed, and --expect-key
    must close it."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)
    tool = os.path.join(BASE, "tools", "verify-bundle.js")

    plain = subprocess.run([NODE, tool, str(out)], capture_output=True,
                           text=True, timeout=300)
    assert plain.returncode == 0
    assert "UNPINNED" in plain.stdout and "caveat:" in plain.stdout

    from cryptography.hazmat.primitives import serialization
    raw = merkle.load_ed25519_public(PUB).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    pinned = subprocess.run([NODE, tool, str(out), "--expect-key", raw],
                            capture_output=True, text=True, timeout=300)
    assert pinned.returncode == 0
    assert "matches the one supplied out of band" in pinned.stdout
    assert "caveat:" not in pinned.stdout

    wrong = subprocess.run([NODE, tool, str(out), "--expect-key", "aa" * 32],
                           capture_output=True, text=True, timeout=300)
    assert wrong.returncode == 1
    assert "BUNDLE INVALID" in wrong.stdout


@pytest.mark.skipif(NODE is None, reason="node not present")
@pytest.mark.parametrize("field,value,expect", [
    ("tree_size", -1, "non-negative integer"),
    ("tree_size", "5", "non-negative integer"),
    ("root_hash", "zz" * 32, "64 lowercase hex"),
    ("log_pubkey_hex", "aa" * 31, "64 lowercase hex"),
    ("signature", "ab", "128 lowercase hex"),
])
def test_malformed_snapshot_reports_instead_of_crashing(
        tmp_path, field, value, expect):
    """A bundle under suspicion is exactly the one carrying a negative
    tree_size or a truncated key. Those must come out as BUNDLE INVALID, not
    as a stack trace on top of a half-printed, green-looking transcript —
    and a browser would hit the same paths and die mid-render."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)
    _patch_data(out / "data" / "snapshot.js", "snapshot",
                lambda snap: dict(snap, **{field: value}))

    proc = subprocess.run(
        [NODE, os.path.join(BASE, "tools", "verify-bundle.js"), str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "BUNDLE INVALID" in proc.stdout
    assert expect in proc.stdout
    assert "Maximum call stack" not in proc.stderr
    assert proc.stderr.strip() == "", "crashed instead of reporting"


@pytest.mark.skipif(NODE is None, reason="node not present")
def test_per_build_record_must_agree_with_the_index(tmp_path):
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)
    # The fixture publishes everything, so flip the index the other way to
    # create a genuine disagreement with the per-build record.
    _patch_data(out / "data" / "builds-index.js", "builds",
                lambda builds: [dict(b, status="packages-missing",
                                     unpublished_count=99) for b in builds])
    # The per-build file still says what the exporter derived, so the two
    # now disagree — which must be a failure, not a silent preference.
    proc = subprocess.run(
        [NODE, os.path.join(BASE, "tools", "verify-bundle.js"), str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 1
    assert "differs between builds-index.js" in proc.stdout


def test_snapshot_ships_what_its_recipe_needs(tmp_path):
    """SNAPSHOT.txt tells the reader to re-check the head offline. The files
    that recipe names have to actually be in the bundle."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)

    text = (out / "SNAPSHOT.txt").read_text()
    assert "verify-sth --sth-file sth.json" in text
    assert "--log-pub log_ed25519.pub" in text
    assert (out / "sth.json").exists()
    assert (out / "log_ed25519.pub").exists()

    sth = json.loads((out / "sth.json").read_text())
    assert merkle.verify_sth(merkle.load_ed25519_public(
        str(out / "log_ed25519.pub")), sth)

    # And the honest caveats must survive edits to the template.
    assert "does NOT prove that key is the log's" in text
    assert "No entry commits to" in text


def test_key_id_matches_the_cli_fingerprint(tmp_path):
    """A reader comparing the page's key_id against `pkgattest verify-sth`
    must see the same digest — two definitions would read as a mismatch."""
    from pkgintegrity import cli
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)
    snap = _load_data(str(out), "snapshot")
    cli_fp = cli._key_fingerprint(merkle.load_ed25519_public(PUB))
    assert snap["key_id"] == "sha256:" + cli_fp


@pytest.mark.skipif(NODE is None, reason="node not present")
def test_forged_member_indices_are_caught(tmp_path):
    """member_indices is a build's claimed footprint in the log, and a detail
    page will render it. Each index must land inside the signed head AND name
    a leaf this build actually contains."""
    base, _ = _fixture_tree(tmp_path)
    out = tmp_path / "dist"
    _export(base, out)
    tool = os.path.join(BASE, "tools", "verify-bundle.js")

    ok = subprocess.run([NODE, tool, str(out)], capture_output=True,
                        text=True, timeout=300)
    assert ok.returncode == 0
    assert "claimed log indices resolve" in ok.stdout

    # An index past the signed head, and one naming somebody else's leaf.
    _patch_data(out / "data" / "builds" / "A.js", "build_A",
                lambda b: dict(b, member_indices=[0, 99999]))
    bad = subprocess.run([NODE, tool, str(out)], capture_output=True,
                         text=True, timeout=300)
    assert bad.returncode == 1
    assert "member_indices do not name a leaf" in bad.stdout


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


# --------------------------------------------------------------- assessments
def _assessment(doc, examined_names, **over):
    """A minimal, valid assessment document over a fixture measurement doc."""
    by_name = {p["name"]: p for p in doc["packages"]}
    a = {
        "schema": "pkgattest-assessment-v1",
        "illustrative": True,
        "disclaimer": "Illustration only. Not an OCP S.A.F.E. report.",
        "assessment_id": "t1",
        "issuer": {"name": "test (worked example)",
                   "kind": "self-issued-example"},
        "issued_at": "2026-08-22",
        "subject": {"image_line": doc["image_line"],
                    "manifest_type": doc["schema"],
                    "device_root": doc["merkle_root"],
                    "package_count": len(doc["packages"])},
        "review": {"basis": "test", "aligns_with_safe_scope": 1,
                   "methodology": "none"},
        "examined": [{"name": n, "version": by_name[n]["version"],
                      "pkg_leaf_hash": by_name[n]["leaf_hash"]}
                     for n in examined_names],
    }
    a.update(over)
    return a


def _write_assessment(base, a):
    d = base / "assessments"
    d.mkdir(exist_ok=True)
    (d / "a.json").write_text(json.dumps(a))


def test_assessment_is_exported_and_checked(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    _write_assessment(base, _assessment(doc, ["dropbear", "bash"]))
    out = tmp_path / "dist"
    manifest = _export(base, out)

    (a,) = manifest["assessments"]
    assert a["examined"] == 2
    assert a["illustrative"] is True
    assert a["subject"] == "A"

    shipped = _load_data(str(out), "assessments")
    assert shipped[0]["disclaimer"]
    assert {e["name"] for e in shipped[0]["examined"]} == {"dropbear", "bash"}


def test_assessment_must_name_a_real_image(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"])
    a["subject"]["device_root"] = "ff" * 32
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="not any build"):
        _export(base, tmp_path / "dist")


def test_assessment_cannot_name_a_package_that_is_not_there(tmp_path):
    """An assessment claiming to have examined something absent from the
    image would put an unearned claim on the page."""
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"])
    a["examined"][0]["pkg_leaf_hash"] = "aa" * 32
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="not in the subject"):
        _export(base, tmp_path / "dist")


def test_assessment_name_and_measurement_must_agree(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"])
    a["examined"][0]["version"] = "9.9-r9"
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="but that measurement"):
        _export(base, tmp_path / "dist")


def test_illustrative_assessment_cannot_lose_its_disclaimer(tmp_path):
    """The label is enforced, not merely expected. A worked example must not
    be able to shed the words that say it is one."""
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"], disclaimer="")
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="must carry a disclaimer"):
        _export(base, tmp_path / "dist")


def test_assessment_must_declare_whether_it_is_illustrative(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"])
    del a["illustrative"]
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="illustrative"):
        _export(base, tmp_path / "dist")


def test_assessment_package_count_must_match(tmp_path):
    base, doc = _fixture_tree(tmp_path)
    a = _assessment(doc, ["dropbear"])
    a["subject"]["package_count"] = 999
    _write_assessment(base, a)
    with pytest.raises(site_export.ExportError, match="claims 999 packages"):
        _export(base, tmp_path / "dist")


def test_real_example_assessment_is_generated_reproducibly(tmp_path):
    """The committed example must be exactly what the generator produces --
    otherwise the selection could drift from the leaf hashes it names."""
    src = os.path.join(BASE, "assessments", "example-scope1.json")
    if not os.path.exists(src) or not os.path.exists(REAL_LOG):
        pytest.skip("the example assessment or the real data is not present")
    sys.path.insert(0, os.path.join(BASE, "tools"))
    import make_example_assessment as gen

    out = tmp_path / "regenerated.json"
    assert gen.main(["--out", str(out)]) == 0
    assert out.read_text() == open(src, encoding="utf-8").read()

    a = json.loads(out.read_text())
    assert a["illustrative"] is True
    assert "not an OCP S.A.F.E." in a["disclaimer"]
    # The demo hinges on dropbear being inside the reviewed area and
    # os-release being outside it.
    names = {e["name"] for e in a["examined"]}
    assert "dropbear" in names
    assert "os-release" not in names


def test_unowned_leaf_covers_the_files_no_package_claims(tmp_path):
    """Image D's whole reason for existing: /etc/passwd and friends are
    inside the device root, so changing them changes what PCR 14 commits to."""
    doc_path = os.path.join(
        REAL_ART, "D", "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")
    if not os.path.exists(doc_path):
        pytest.skip("image D is not built")
    doc = canonical.load_measurements_json(doc_path)

    # It is an ordinary leaf: the drift gate and the root need no special case.
    assert canonical.verify_measurements_doc(doc) == []
    names = [p["name"] for p in doc["packages"]]
    assert names == sorted(names)
    assert names[0] == "(unowned)", "the leaf must sort first, with no rule"

    (u,) = [p for p in doc["packages"] if p["name"] == "(unowned)"]
    assert u["version"] == "1.0" and u["arch"] == "all", (
        "constant metadata, so the leaf is a pure function of the file set")

    covered = {f["path"] for f in u["files"]}
    for path in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                 "/etc/ld.so.cache", "/etc/ssl/certs/ca-certificates.crt"):
        assert path in covered, "%s is still outside every leaf" % path

    # The residue is only what is excluded on purpose.
    for path in ("/etc/machine-id", "/etc/version", "/etc/timestamp"):
        assert path not in covered
    assert not any(f["path"].startswith("/usr/share/pkg-integrity/")
                   for f in u["files"]), (
        "the measurement pass cannot measure its own output")


def test_unowned_leaf_is_a_pure_function_of_its_files(tmp_path):
    """No timestamp or build id in the metadata, so two builds with the same
    unowned files produce one leaf and deduplicate in the log."""
    import hashlib
    doc_path = os.path.join(
        REAL_ART, "D", "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")
    if not os.path.exists(doc_path):
        pytest.skip("image D is not built")
    doc = canonical.load_measurements_json(doc_path)
    (u,) = [p for p in doc["packages"] if p["name"] == "(unowned)"]

    rebuilt = canonical.PkgLeaf(
        u["name"], u["version"], u["arch"],
        [(f["path"], f["sha256"]) for f in u["files"]])
    assert rebuilt.leaf_hash() == u["leaf_hash"]

    pre = rebuilt.preimage().decode()
    assert pre.startswith("pkg-leaf-v1\nname=(unowned)\nversion=1.0\n")
    assert doc["image_name"] not in pre and doc["timestamp"] not in pre
