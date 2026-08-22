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


def snapshot(bundle):
    """The tree grows every time a build is published, so tests derive the
    numbers they assert instead of pinning them."""
    with open(os.path.join(bundle, "sth.json")) as f:
        return json.load(f)


def n(x):
    return "{:,}".format(x)


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
    size = snapshot(bundle)["tree_size"]
    assert n(2 * size - 1) + " sha256" in out
    assert "Nothing above was asked of a server" in out


@needs
def test_absence_is_scoped_to_a_tree_size(bundle):
    """"Never published" without a tree size is a claim the page cannot
    support: it only knows the head it shipped with."""
    out = render(bundle)
    assert "at tree size " + n(snapshot(bundle)["tree_size"]) in out
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
    assert "leaf 18 of " + n(snapshot(bundle)["tree_size"]) in out


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
    assert "leaf 18 of " + n(snapshot(bundle)["tree_size"]) in out

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
    assert "Not present at tree size " + n(snapshot(bundle)["tree_size"]) in out
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


# ------------------------------------------------------------ the proof tabs
@needs
def test_proof_has_two_tabs_with_the_ladder_first(bundle):
    """The ladder is the arithmetic and stays the default view; the tree is a
    second tab, present in the DOM but not shown until selected."""
    visible = render(bundle, "--hash", "#/pkg/dropbear")
    assert "Each step" in visible and "The shape" in visible   # both buttons

    # Ladder visible by default.
    assert "sibling on the right" in visible
    # Tree hidden by default: its triangle labels are not on screen.
    assert "1,024 records" not in visible

    everything = render(bundle, "--hash", "#/pkg/dropbear", "--show-hidden")
    assert "1,024 records" in everything


@needs
def test_tree_triangles_account_for_every_other_record(bundle):
    """Each triangle is one hash standing for a whole subtree. Their counts
    are the argument for why twelve hashes cover 2,132 records, so they have
    to be right and they have to add up."""
    out = render(bundle, "--hash", "#/pkg/dropbear", "--show-hidden")
    size = snapshot(bundle)["tree_size"]

    # Sizes double all the way up to the largest power of two below the tree.
    p2 = 1
    while p2 * 2 < size:
        p2 *= 2
    for label in ("1 record", "2 records", "4 records", "1,024 records"):
        assert label in out, "missing triangle label %r" % label

    # The triangles must account for every other record in the log, and the
    # caption must say so with the real number.
    m = re.search(r"(\d+) triangles, ([\d,]+) records between them", out)
    assert m, "no triangle tally in the caption"
    assert int(m.group(2).replace(",", "")) == size - 1
    assert "every record in the log except this one" in out

    # And the subtree that breaks the doubling pattern is explained, not hidden.
    assert "is not a power of two" in out
    assert n(size - p2) + " records, because " + n(size) in out


@needs
def test_tree_and_ladder_describe_the_same_proof(bundle):
    """inclusionSpans and inclusionSteps come from different recursions. If
    they ever disagreed the picture would illustrate a proof that is not the
    one being verified."""
    script = (
        "const V=require(%s);"
        "const size=2132, idx=18;"
        "const proof=V.inclusionProof("
        "  [...Array(size)].map((_,i)=>V.sha256(V.utf8('x'+i))), idx, size);"
        "const steps=V.inclusionSteps(idx,size,proof);"
        "const spans=V.inclusionSpans(idx,size);"
        "const sides=steps.map(s=>s.side).join(',');"
        "const sspan=spans.map(s=>s.side).join(',');"
        "const covered=spans.reduce((a,s)=>a+(s.hi-s.lo),0);"
        "console.log(JSON.stringify({n:proof.length,m:spans.length,"
        "  sidesAgree:sides===sspan,covered:covered}));"
        % json.dumps(os.path.join(BASE, "site", "verify.js")))
    proc = subprocess.run(["node", "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    r = json.loads(proc.stdout)
    assert r["n"] == r["m"], "one span per proof node"
    assert r["sidesAgree"], "the drawing would show the wrong side"
    assert r["covered"] == 2131, "spans must partition every other leaf"


@needs
def test_tree_is_svg_not_markup(bundle):
    """The diagram is built with createElementNS; the shim throws on
    innerHTML, so reaching here at all proves it."""
    app = open(os.path.join(bundle, "app.js"), encoding="utf-8").read()
    assert "createElementNS" in app
    assert "http://www.w3.org/2000/svg" in app
    out = render(bundle, "--hash", "#/pkg/dropbear", "--show-hidden")
    assert "root  " + snapshot(bundle)["root_hash"][:8] in out
    assert "this record" in out


# ------------------------------------------------------- the assessment view
@needs
def test_assessment_page_is_unmistakably_an_example(bundle):
    """This is the one page where a fabricated artefact would do real damage:
    it discusses audits, so it must never look like one."""
    out = render(bundle, "--hash", "#/assessment")
    assert "Worked example" in out
    assert "not an OCP S.A.F.E. Short-Form Report" in out
    assert "no Security Review Provider has reviewed this image" in out
    assert "pkgattest (worked example)" in out

    # It must not name a real review provider as having assessed anything.
    for srp in ("Keysight", "Riscure", "NCC", "Atredis", "IOActive"):
        assert srp not in out, "named a real SRP: %s" % srp

    # Nor imply endorsement or submission.
    assert "not a submission" in out
    assert "nothing here is endorsed by OCP" in out


@needs
def test_assessment_page_states_the_gap(bundle):
    out = render(bundle, "--hash", "#/assessment")
    assert "fw_hash_sha2_384" in out
    assert "Security Review Provider" in out
    # The vocabulary table, with the two blanks that are the point.
    assert "Reference Value Provider" in out
    assert "Cloud Service Provider" in out
    assert "(no term)" in out


@needs
def test_assessment_distinguishes_a_meaningful_change_from_a_cosmetic_one(
        bundle):
    """The whole argument: a firmware hash fails identically for image B
    (a reviewed package swapped) and image C (a build identifier changed).
    Naming packages tells them apart."""
    out = render(bundle, "--hash", "#/assessment")

    assert "This is the image the assessment names." in out       # A
    assert "dropbear 2026.91-r0" in out                            # B
    assert "reviewed build was 2026.92-r0" in out
    assert "inside the reviewed area but not the reviewed build" in out
    assert "57 examined" in out and "56 examined" in out
    assert "including the one whose only change was a build identifier" in out


@needs
@pytest.mark.parametrize("route,expect", [
    ("#/pkg/dropbear", "This exact measurement is named as examined"),
    ("#/pkg/dropbear?build=B", "Inside the reviewed area, but not the reviewed build."),
    ("#/pkg/os-release", "Not in the scope named by"),
])
def test_package_page_states_where_it_sits_in_the_assessment(
        bundle, route, expect):
    out = render(bundle, "--hash", route)
    assert expect in out
    # The disclaimer travels with the claim, wherever it is shown.
    assert "not an OCP S.A.F.E. Short-Form Report" in out


# ----------------------------------------------------------- the impact view
@needs
def test_impact_separates_what_transfers_from_what_does_not(bundle):
    out = render(bundle, "--hash", "#/impact")
    assert "property of bytes" in out
    assert "property of the review effort, and follows nothing" in out
    assert "do not carry forward the fact that nothing else was" in out


@needs
def test_impact_escalates_when_a_reviewed_package_changed(bundle):
    """A -> B swaps dropbear, which the assessment examined."""
    out = render(bundle, "--hash", "#/impact")
    assert "Assessed image A  ->  image B" in out
    assert "Reasons to re-review" in out
    assert "1 package inside the reviewed area changed" in out
    assert "dropbear  2026.92-r0 -> 2026.91-r0" in out
    assert "2,130" in out                      # identical measurements


@needs
def test_impact_never_clears_a_build(bundle):
    """A -> C changes only os-release, outside the reviewed area. The page
    must report that it found nothing WITHOUT calling the change minor —
    that classification belongs to a reviewer, as Common Criteria has it."""
    out = render(bundle, "--hash", "#/impact")
    assert "Assessed image A  ->  image C" in out
    assert "No reason to re-review found in the reviewed area." in out
    assert "That is not clearance, and this page will not offer any." in out
    assert "belongs to a reviewer" in out

    # The words a tool must never print about a change it did not judge.
    for forbidden in ("assurance maintained", "minor change",
                      "no re-review required", "still assured",
                      "remains valid", "safe to deploy"):
        assert forbidden.lower() not in out.lower(), (
            "the impact page claimed %r" % forbidden)


@needs
def test_impact_shows_a_version_that_did_not_move_but_bytes_that_did(bundle):
    """os-release keeps version 1.0-r0 across A and C while its measurement
    changes. Rendering that as "1.0-r0 -> 1.0-r0" would read as a bug; it is
    in fact the reason the join is on the leaf hash."""
    out = render(bundle, "--hash", "#/impact")
    assert "os-release  1.0-r0  (same version, different measurement)" in out
    assert "1.0-r0 -> 1.0-r0" not in out


@needs
def test_impact_states_its_own_blind_spots(bundle):
    out = render(bundle, "--hash", "#/impact")
    # Files no package owns.
    assert "25 regular files" in out
    assert "/etc/ld.so.cache" in out
    assert "not derivable from this bundle" in out
    # The dependency-graph hole, named as the largest one.
    assert "largest hole in the analysis" in out
    assert "dependency graph" in out
    # And the prior art for who makes the call.
    assert "Assurance Continuity" in out
    assert "Impact Analysis Report" in out


# ------------------------------------------------------- the objections view
@needs
def test_objections_page_states_the_unanswerable_ones_as_unanswerable(bundle):
    """A page listing only the objections it can rebut is an advertisement.
    The headline count must match the tags, whatever that count currently is,
    so closing an objection cannot quietly leave the page overstating."""
    out = render(bundle, "--hash", "#/objections")
    assert "Objections that stand" in out

    tags = out.count("\nno answer\n")
    m = re.search(r"^(One|\d+) of these ha[sv]e? no answer\.$", out, re.M)
    assert m, "no headline count of unanswered objections"
    claimed = 1 if m.group(1) == "One" else int(m.group(1))
    assert claimed == tags, (
        "headline says %d unanswered, %d are tagged so" % (claimed, tags))
    assert tags >= 1, "a page with nothing unanswered needs re-reading"

    # The two that no build can close.
    assert "Measuring files at rest says nothing about what is running." in out
    assert "One log with one key is not a transparency ecosystem." in out


@needs
def test_objections_page_reports_the_unowned_gap_per_build(bundle):
    """The gap is closed from image D on. The page must say so from the data
    rather than by assertion, keep saying it was a way through rather than a
    rough edge, and still name the files that remain outside on purpose."""
    out = render(bundle, "--hash", "#/objections")
    assert "Files that belong to no package are invisible to it." in out

    # It does not pretend the gap never existed.
    assert "it was a way through rather than a rough edge" in out
    assert "changed nothing the mechanism committed to" in out

    # Coverage is stated per build, computed from the bundle.
    assert re.search(r"image D covers [\d,]+ such files", out)
    assert "predate" in out          # A, B and C do not carry the leaf

    # The residue is named, not glossed.
    for f in ("/etc/machine-id", "/etc/version", "/etc/timestamp"):
        assert f in out, f
    assert "named gap, not an oversight" in out


@needs
def test_objections_page_concedes_where_it_should(bundle):
    out = render(bundle, "--hash", "#/objections")
    assert "Objections that are simply right" in out
    assert "Why not build this on Rekor?" in out
    assert "a demonstration, not a proposal" in out
    assert "CoRIM already carries per-component reference values." in out
    assert "the right implementation target" in out


@needs
def test_objections_page_scopes_the_claim_honestly(bundle):
    """The IMA rebuttal is real but partial, and the page must say where it
    stops rather than claim a clean win."""
    out = render(bundle, "--hash", "#/objections")
    assert "This is Linux IMA with extra steps." in out
    assert "differs on every boot" in out
    assert "The limit of the rebuttal, stated plainly" in out
    assert "not that IMA cannot get there" in out

    # And the through-line that scopes the whole project.
    assert "worth exactly nothing against the first" in out


@needs
def test_objections_page_cites_its_sources(bundle):
    out = render(bundle, "--hash", "#/objections")
    for src in ("IMA concepts", "TOCTOU Problem in Remote Attestation",
                "Sigstore Rekor", "CoRIM-based reference measurement"):
        assert src in out, src
    assert "will not resolve from the offline copy" in out
