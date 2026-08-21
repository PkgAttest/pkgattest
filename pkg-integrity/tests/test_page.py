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
