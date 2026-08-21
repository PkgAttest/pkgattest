"""Tests for the page itself — what a reader actually sees.

These run app.js against a minimal DOM (tools/render-check.js) rather than a
browser, so they run in the ordinary test suite and skip cleanly without node.
They are not about pixels. They check the two rules the page exists to
enforce:

  1. A verdict is never drawn on top of a failed self-test.
  2. Every value shown was recomputed here, and the things that were not are
     said out loud.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import site_export  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RENDER = os.path.join(BASE, "tools", "render-check.js")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
REAL_LOG = os.path.join(BASE, "log", "log.jsonl")
NODE = shutil.which("node")

needs = pytest.mark.skipif(
    NODE is None or not os.path.exists(REAL_LOG),
    reason="node (test-only) or the production log store is not present")


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    site_export.export(BASE, str(out), pub_path=PUB)
    return str(out)


def render(bundle, *extra):
    proc = subprocess.run([NODE, RENDER, bundle] + list(extra),
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


# ------------------------------------------------------------------ the page
@needs
def test_landing_page_states_the_case(bundle):
    out = render(bundle)

    # The thesis, and the answer it promises.
    assert "Both images carry a valid signature." in out
    assert "One package was never published." in out
    assert "dropbear 2026.91-r0" in out

    # The receipt reports work that actually happened.
    assert "What this browser just did" in out
    assert "matches the signed head" in out
    assert "signature valid" in out
    assert re.search(r"\d+(\.\d+)? ms", out), "no measured timing shown"
    assert "4,263 sha256" in out          # 2*2132 - 1
    assert "Nothing above was asked of a server" in out


@needs
def test_absence_is_scoped_to_a_tree_size(bundle):
    """"Never published" without a tree size is a claim the page cannot
    support: it only knows the head it shipped with."""
    out = render(bundle)
    assert "at tree size 2,132" in out
    assert "under image line rpi3-openbmc" in out


@needs
def test_the_full_root_is_shown_not_an_abbreviation(bundle):
    """An abbreviated hash leaves the reader nothing to check."""
    out = render(bundle)
    with open(os.path.join(bundle, "sth.json")) as f:
        root = json.load(f)["root_hash"]
    groups = [root[i:i + 8] for i in range(0, 64, 8)]
    for g in groups:
        assert g in out, "root group %s missing from the page" % g


@needs
def test_the_key_is_shown_with_its_caveat(bundle):
    """The key ships alongside the signatures it checks, so the page must say
    so and tell the reader what would actually settle it."""
    out = render(bundle)
    assert "arrived in the same download as the signatures" in out
    assert "not that the key is the log's" in out
    assert "Compare it against a value you got somewhere else" in out
    assert "pkgattest verify-sth --sth-file sth.json" in out


@needs
def test_limits_page_lists_what_is_not_proved(bundle):
    out = render(bundle, "--hash", "#/limits")
    for claim in ("The key is the log's key.",
                  "This tree head is current.",
                  "This image was published.",
                  "The images are correctly signed."):
        assert claim in out, claim
    # The image-attestation limit is the one a hostile reader reaches for.
    assert "never to an image" in out
    assert "including a downgrade" in out


# ---------------------------------------------------------------- the refusal
@needs
@pytest.mark.parametrize("primitive", ["sha256", "sha512", "ed25519"])
def test_a_broken_primitive_blocks_every_verdict(bundle, primitive):
    """The self-test gate. With any primitive broken, the page must show the
    failure and nothing else — no thesis, no receipt, and above all no
    accusation naming a package."""
    out = render(bundle, "--break", primitive)

    assert "Verification is not possible in this browser" in out
    assert primitive in out.lower()

    for forbidden in ("matches the signed head", "signature valid",
                      "every package published", "dropbear",
                      "One package was never published."):
        assert forbidden not in out, (
            "a broken %s still rendered %r" % (primitive, forbidden))


@needs
def test_a_bundle_whose_records_disagree_is_refused(bundle, tmp_path):
    """If the shipped records do not fold to the signed root, the page says
    so instead of showing a page built on them."""
    poisoned = tmp_path / "poisoned"
    shutil.copytree(bundle, poisoned)
    leaves = poisoned / "data" / "leaves.js"
    text = leaves.read_text()
    m = re.search(r'PKGI_DATA\["leaves"\] = (.*);\n\Z', text, re.S)
    arr = json.loads(m.group(1))
    arr[0] = arr[0].replace('"name":"', '"name":"x', 1)
    leaves.write_text(text[:m.start(1)]
                      + json.dumps(arr, separators=(",", ":")) + ";\n")

    out = render(str(poisoned))
    assert "This bundle does not verify" in out
    assert "dropbear" not in out
    assert "matches the signed head" not in out


# ------------------------------------------------------------- page structure
def test_page_assets_are_in_the_bundle(bundle):
    for name in ("index.html", "app.js", "style.css", "verify.js",
                 "vendor/pkgcrypto.js"):
        assert os.path.exists(os.path.join(bundle, name)), name


def test_page_declares_a_csp_and_no_inline_code(bundle):
    html = open(os.path.join(bundle, "index.html"), encoding="utf-8").read()
    csp = re.search(
        r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', html)
    assert csp, "no CSP meta tag"
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    # frame-ancestors is ignored in a meta CSP; putting it in the policy would
    # imply a protection that does not exist.
    assert "frame-ancestors" not in policy
    # An inline script or handler would be blocked by that CSP at runtime;
    # catch it here instead of on stage.
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), \
        "inline <script> in index.html"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler"
    assert 'style="' not in html, "inline style attribute"


def test_app_js_builds_dom_rather_than_markup(bundle):
    app = open(os.path.join(bundle, "app.js"), encoding="utf-8").read()
    code = re.sub(r"/\*.*?\*/", "", app, flags=re.S)
    code = re.sub(r"^\s*//.*$", "", code, flags=re.M)
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                   "document.write", "eval("):
        assert banned not in code, "app.js uses %s" % banned


# --------------------------------------------------------- the lookup views
@needs
def test_a_package_name_is_a_valid_query(bundle):
    """The most natural thing a reader types is a name. Demanding 64 hex
    would be a discoverability bug on the one control the page exists for."""
    out = render(bundle, "--hash", "#/hash/dropbear")
    assert "Packages" in out
    assert "dropbear" in out


@needs
def test_a_log_index_resolves(bundle):
    out = render(bundle, "--hash", "#/hash/18")
    assert "log record" in out
    assert "dropbear 2026.92-r0" in out
    assert "leaf 18 of 2,132" in out


@needs
def test_every_meaning_of_a_hash_is_reported(bundle):
    """sha256 of the empty string is simultaneously the RFC 6962 empty-tree
    root and the digest of every empty file in the image. A reader shown only
    one of those has been told something misleading."""
    empty = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e"
             "4649b934ca495991b7852b855")
    out = render(bundle, "--hash", "#/hash/" + empty)
    assert "matches, all shown" in out
    assert "signed tree head" in out
    assert "the empty tree (size 0)" in out
    assert "measured file" in out
    assert "base-files" in out and "shadow" in out
    assert "sha256 of nothing at all" in out


@needs
def test_an_unknown_hash_is_not_the_punchline_screen(bundle):
    """A random digest must look different from a package whose version was
    never published — otherwise the demo's finding is indistinguishable from
    a typo."""
    out = render(bundle, "--hash", "#/hash/" + "ab" * 32)
    assert "Unknown value." in out
    assert "simply not here at all" in out

    # The distinction is structural, not lexical: an unknown hash produces no
    # result cards at all. (The copy does name the namespaces it is not found
    # in, so substring checks would match that explanation.) A card renders
    # its kind on a line of its own.
    lines = [l.strip() for l in out.splitlines()]
    for kind in ("log record", "package measurement", "device root",
                 "signed tree head", "measured file", "artifact"):
        assert kind not in lines, "unknown hash rendered a %r card" % kind
    assert "Not present at tree size" not in out

    # And it explains the one namespace deliberately left out.
    assert "Internal tree nodes are not indexed" in out


@needs
def test_an_unpublished_measurement_is_found_and_named(bundle):
    """Looking up image B's dropbear measurement by hash must say plainly
    that no log record covers it."""
    import subprocess as sp
    doc = os.path.join(
        BASE, "artifacts", "B",
        "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")
    if not os.path.exists(doc):
        pytest.skip("image B artifacts not present")
    with open(doc) as f:
        leaf = [p for p in json.load(f)["packages"]
                if p["name"] == "dropbear"][0]["leaf_hash"]

    out = render(bundle, "--hash", "#/hash/" + leaf)
    assert "package measurement" in out
    assert "dropbear 2026.91-r0" in out
    assert "no log record for this measurement at this tree size" in out
    del sp


# ------------------------------------------------------------ the proof view
@needs
def test_package_page_shows_the_whole_chain(bundle):
    """Preimage bytes, the canonical record, the folded proof, the signature.
    Each step has to show the input, not just assert the output."""
    out = render(bundle, "--hash", "#/pkg/dropbear")

    assert "One \\u2014 what was measured" in out or "One" in out
    assert "pkg-leaf-v1\nname=dropbear" in out       # the real preimage bytes
    assert '"schema":"log-leaf-v1"' in out           # the real record bytes
    assert "sha256(preimage)" in out
    assert "sha256(0x00 || record)" in out
    assert "Published \\u2014 leaf 18 of 2,132" in out or "leaf 18 of 2,132" in out

    # The ladder, and the fact that it was derived rather than fetched.
    assert "sibling on the" in out
    assert "The server was not asked for a proof." in out
    assert "this is the root the tree head is signed over" in out
    assert "valid over the tree head above" in out


@needs
def test_package_page_folds_to_the_real_signed_root(bundle):
    """The ladder's final value must be the actual signed root, shown whole."""
    out = render(bundle, "--hash", "#/pkg/dropbear")
    with open(os.path.join(bundle, "sth.json")) as f:
        root = json.load(f)["root_hash"]
    for g in [root[i:i + 8] for i in range(0, 64, 8)]:
        assert g in out, "root group %s missing from the ladder" % g


@needs
def test_unpublished_package_page_scopes_its_claim(bundle):
    """Absence is always "not at this tree size", never "never"."""
    out = render(bundle, "--hash", "#/pkg/dropbear?build=B")
    assert "dropbear 2026.91-r0" in out
    assert "Not present at tree size 2,132" in out
    assert "No leaf in this log matches that record." in out
    assert "not about all time" in out
    # And it says what IS published, so the reader is not left guessing.
    assert "What is published for dropbear" in out
    assert "2026.92-r0" in out


@needs
def test_missing_package_does_not_error(bundle):
    out = render(bundle, "--hash", "#/pkg/nosuchpackage")
    assert "No package by that name." in out


# -------------------------------------------------------------------- stats
@needs
def test_stats_are_computed_and_honest(bundle):
    out = render(bundle, "--hash", "#/stats")

    # Coverage, per build, derived rather than stated.
    assert "2,131 / 2,131" in out
    assert "2,130 / 2,131" in out

    # The awkward facts, stated rather than buried.
    assert "41 packages measure zero files" in out
    assert "constrain nothing" in out.lower()
    assert "87.8%" in out and "49.9%" in out
    assert "Counting packages is not the same as measuring attack surface" in out

    # And the number that cannot be computed is refused, not invented.
    assert "denominator is not in this data" in out


@needs
def test_a_malformed_route_lands_on_a_page(bundle):
    """location.hash is attacker-controlled and survives being shared."""
    out = render(bundle, "--hash", "#/hash/%ZZ")
    # Any of these is a page; a stack trace or a blank screen is not.
    assert ("could not be read" in out
            or "Unknown value" in out
            or "lookup" in out)
    assert "Traceback" not in out
