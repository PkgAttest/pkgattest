"""Export the static, self-verifying site bundle.

`make site` turns the log store and the built artifacts into
`pkg-integrity/site-dist/` — a directory whose bytes are identical whether
they are served from GitHub Pages, from `log_server.py --site`, or opened
straight off disk with file://.

Two properties this module exists to guarantee:

**It re-derives instead of copying.** Every package leaf, every device root
and every log leaf is recomputed here and compared against what the source
documents claim. A mismatch aborts the export, exactly as publish.py refuses
to publish on drift. The site must never be able to show a number nobody
recomputed.

**It is deterministic.** No wall-clock timestamp, hostname, build path or
tool version reaches the output; iteration order is sorted; the only time in
the bundle is the one inside a signed tree head. So `make site-verify` can
build twice and diff, and a third party can reproduce the published bytes.

Data ships as classic scripts assigning into a global, because ES modules and
fetch() are both CORS-blocked on file://.
"""

import hashlib
import json
import os
import re
import shutil

from . import canonical, merkle

SCHEMA = "pkgattest-site-v1"

# Bootstrap idiom: every data file is independently loadable, and later files
# must not clobber the object earlier ones populated.
_PRELUDE = ("var PKGI_DATA = typeof PKGI_DATA === 'undefined' "
            "? {} : PKGI_DATA;\n")


class ExportError(RuntimeError):
    pass


def _js(path, key, value):
    """Write one data file: `PKGI_DATA["<key>"] = <json>;`

    Output is pure ASCII on purpose. Loaded over file:// there is no HTTP
    Content-Type header, so the browser guesses the encoding of a script it
    fetches — and a mis-guessed byte silently changes a path, and therefore a
    leaf hash. `ensure_ascii=True` removes the guess entirely: the only
    non-ASCII path in the image (ca-certificates' Főtanúsítvány.crt) ships as
    \\uXXXX escapes and decodes identically under any guess.

    `</` is additionally escaped as `<\\/` (a valid JSON escape) so the payload
    stays inert if it is ever inlined into an HTML <script> block rather than
    loaded as a separate file.
    """
    body = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).replace("</", "<\\/")
    text = _PRELUDE + "PKGI_DATA[%s] = %s;\n" % (json.dumps(key), body)
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    return len(text.encode("ascii"))


def _read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _key_id(pub_pem_path):
    from cryptography.hazmat.primitives import serialization
    with open(pub_pem_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(der).hexdigest(), raw.hex()


LABEL_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")

# Never copy these into the bundle: they would appear in sha256sums.txt and
# make byte-reproducibility depend on the state of someone's working tree.
_IGNORED = shutil.ignore_patterns(
    "__pycache__", "*.py[co]", ".*.sw?", "*~", ".DS_Store", "*.orig", "*.rej")


def _read_sha256sums(path):
    """Parse SHA256SUMS, keeping only basenames.

    The file records absolute paths from whoever ran the build, so it leaks a
    home directory into what is meant to be a public artifact. It is used only
    to cross-check digests we compute ourselves — never as their source.
    """
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            digest, sep, name = line.strip().partition("  ")
            if sep and len(digest) == 64:
                out[os.path.basename(name)] = digest
    return out


def _digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_builds(artifacts_dir):
    """Discover builds from artifacts/*/ — one per measurement document."""
    builds = []
    if not os.path.isdir(artifacts_dir):
        return builds
    for label in sorted(os.listdir(artifacts_dir)):
        d = os.path.join(artifacts_dir, label)
        if not os.path.isdir(d):
            continue
        docs = sorted(n for n in os.listdir(d)
                      if n.endswith(".pkg-measurements.json"))
        if not docs:
            continue
        # The label becomes a filename and a URL segment on the page. Reject
        # anything that is not a plain identifier rather than discovering it
        # later as a broken link or an attribute injection.
        if not LABEL_RE.match(label):
            raise ExportError("artifact directory %r is not a usable label "
                              "(expected [A-Za-z0-9._-])" % label)
        # Picking docs[0] would let a stale document win silently, and its
        # device root and PCR14 would go on the page.
        if len(docs) != 1:
            raise ExportError("%s: expected exactly one measurement document, "
                              "found %d: %s" % (label, len(docs), docs))
        doc = canonical.load_measurements_json(os.path.join(d, docs[0]))
        if not doc["packages"]:
            raise ExportError("%s: measurement document contains "
                              "no packages" % label)

        problems = canonical.verify_measurements_doc(doc)
        if problems:
            raise ExportError(
                "%s: refusing to export, %d canonicalisation problem(s): %s"
                % (label, len(problems), problems[0]))

        # verify_measurements_doc hashes packages in document order. SPEC.md
        # section 2 requires the device tree's leaves to be name-sorted, and
        # the on-device bash sorts — so an unsorted document would yield a
        # root no BMC can ever reproduce. canonical.py is frozen, so the
        # check belongs here.
        names = [p["name"] for p in doc["packages"]]
        if names != sorted(names):
            raise ExportError("%s: packages are not name-sorted, so the "
                              "device root cannot match the one the BMC "
                              "computes" % label)
        if len(set(names)) != len(names):
            raise ExportError("%s: duplicate package names" % label)

        # Digests are computed from the bytes, never read out of SHA256SUMS;
        # that file is only a cross-check. A digest the page presents as an
        # artifact's fingerprint must have been taken from the artifact.
        sums = _read_sha256sums(os.path.join(d, "SHA256SUMS"))
        artifacts = {}
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p) or name == "SHA256SUMS":
                continue
            digest = _digest_file(p)
            claimed = sums.get(name)
            if claimed is not None and claimed != digest:
                raise ExportError(
                    "%s/%s: SHA256SUMS says %s but the file hashes to %s"
                    % (label, name, claimed, digest))
            artifacts[name] = {"size": os.path.getsize(p), "sha256": digest}

        receipt_path = os.path.join(d, "publication-receipt.json")
        receipt = None
        if os.path.exists(receipt_path):
            with open(receipt_path, encoding="utf-8") as f:
                receipt = json.load(f)
            if receipt.get("merkle_root") != doc["merkle_root"]:
                raise ExportError(
                    "%s: publication receipt claims merkle_root %s but the "
                    "measurement document says %s"
                    % (label, receipt.get("merkle_root"), doc["merkle_root"]))
            if receipt.get("package_count") not in (None, len(doc["packages"])):
                raise ExportError(
                    "%s: publication receipt claims %s packages, the "
                    "measurement document has %d"
                    % (label, receipt.get("package_count"),
                       len(doc["packages"])))
            if receipt.get("image_line") not in (None, doc["image_line"]):
                raise ExportError(
                    "%s: publication receipt image_line %r != %r"
                    % (label, receipt.get("image_line"), doc["image_line"]))

        builds.append({
            "label": label,
            "build_id": doc["image_name"],
            "image_line": doc["image_line"],
            "machine": doc["machine"],
            "version": doc["version"],
            "built_at": doc["timestamp"],
            "device_root": doc["merkle_root"],
            "pcr14": merkle.expected_pcr14(doc["merkle_root"]),
            "package_count": len(doc["packages"]),
            "file_count": sum(len(p["files"]) for p in doc["packages"]),
            "artifacts": artifacts,
            "receipt": receipt,
            "_doc": doc,
        })
    return builds


def collect_assessments(assess_dir, builds):
    """Load assessment-scope documents and check every claim they make.

    An assessment says "these packages were examined, in the image with this
    device root". Both halves are checkable against data already in the
    bundle, so both are checked: an assessment cannot name an image that does
    not exist here, and it cannot name a package that is not in that image.
    Copying it through unverified would put an unearned claim on the page
    beside numbers that were recomputed.

    The illustrative labelling is enforced, not merely present. A worked
    example must not be able to lose the words that say it is one.
    """
    out = []
    if not os.path.isdir(assess_dir):
        return out

    by_root = {}
    for b in builds:
        by_root.setdefault(b["device_root"], b)

    for name in sorted(os.listdir(assess_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(assess_dir, name), encoding="utf-8") as f:
            a = json.load(f)

        if a.get("schema") != "pkgattest-assessment-v1":
            raise ExportError("%s: not a pkgattest-assessment-v1 document"
                              % name)
        if not isinstance(a.get("illustrative"), bool):
            raise ExportError("%s: must state illustrative true or false"
                              % name)
        if a.get("illustrative") and not str(a.get("disclaimer", "")).strip():
            raise ExportError(
                "%s: an illustrative assessment must carry a disclaimer the "
                "page can print" % name)

        subject = a.get("subject") or {}
        root = subject.get("device_root")
        build = by_root.get(root)
        if build is None:
            raise ExportError(
                "%s: names device root %s, which is not any build in this "
                "snapshot" % (name, root))
        if subject.get("package_count") != build["package_count"]:
            raise ExportError(
                "%s: claims %s packages, the image has %d"
                % (name, subject.get("package_count"), build["package_count"]))

        # Every examined package must really be in that image, with that
        # version and that measurement.
        doc = build["_doc"]
        by_leaf = {p["leaf_hash"]: p for p in doc["packages"]}
        seen = set()
        for e in a.get("examined", []):
            leaf = e.get("pkg_leaf_hash")
            pkg = by_leaf.get(leaf)
            if pkg is None:
                raise ExportError(
                    "%s: examined package %r has measurement %s, which is not "
                    "in the subject image" % (name, e.get("name"), leaf))
            if pkg["name"] != e.get("name") or pkg["version"] != e.get("version"):
                raise ExportError(
                    "%s: examined entry says %s %s but that measurement is "
                    "%s %s" % (name, e.get("name"), e.get("version"),
                               pkg["name"], pkg["version"]))
            if leaf in seen:
                raise ExportError("%s: duplicate examined package %s"
                                  % (name, e.get("name")))
            seen.add(leaf)

        a["_subject_label"] = build["label"]
        out.append(a)
    return out


def export(base, out_dir, store_dir=None, artifacts_dir=None, pub_path=None):
    """Build the bundle. Returns a manifest describing what was written."""
    store_dir = store_dir or os.path.join(base, "log")
    artifacts_dir = artifacts_dir or os.path.join(base, "artifacts")
    pub_path = pub_path or os.path.join(base, "keys", "log_ed25519.pub")

    history = _read_jsonl(os.path.join(store_dir, "sth-history.jsonl"))
    entries = _read_jsonl(os.path.join(store_dir, "log.jsonl"))
    if not history:
        raise ExportError("no signed tree head in %s — start log_server.py "
                          "once, or publish, before exporting" % store_dir)

    # The head to publish is the largest, not whichever line happens to be
    # last: reordering sth-history.jsonl must not change what gets exported.
    current = max(history, key=lambda h: h["tree_size"])

    # Everything past the signed head is covered by no signature. Shipping
    # such a record would let anyone with write access to the log store —
    # a CI runner, a bad merge, a stale file — make an unpublished package
    # look published, with no key involved. Refuse rather than truncate: a
    # store larger than its own head is a fault, not a detail to paper over.
    if len(entries) > current["tree_size"]:
        raise ExportError(
            "log store holds %d entries but the newest signed head covers "
            "only %d — the surplus records are signed by nothing"
            % (len(entries), current["tree_size"]))
    if len(entries) < current["tree_size"]:
        raise ExportError(
            "the newest signed head covers %d entries but the log store "
            "holds only %d — it does not match the log store"
            % (current["tree_size"], len(entries)))

    # --- re-derive the log ------------------------------------------------
    leaves, leaf_hashes, by_leaf_hash = [], [], {}
    for i, rec in enumerate(entries):
        leaf_str = rec["leaf"]
        obj = json.loads(leaf_str)
        rebuilt = canonical.log_leaf_data(
            obj["image_line"], obj["name"], obj["version"], obj["arch"],
            obj["pkg_leaf_hash"]).decode("ascii")
        if rebuilt != leaf_str:
            raise ExportError(
                "log entry %d is not canonical — refusing to export" % i)
        leaves.append(leaf_str)
        lh = merkle.leaf_hash(leaf_str.encode("ascii"))
        leaf_hashes.append(lh)
        by_leaf_hash[lh.hex()] = i

    tree = merkle.MerkleTree()
    tree.leaves = list(leaf_hashes)

    pub = merkle.load_ed25519_public(pub_path)
    for head in history:
        if head["tree_size"] > tree.size:
            raise ExportError(
                "tree head at size %d does not match the log store, which "
                "holds only %d entries" % (head["tree_size"], tree.size))
        if tree.root(head["tree_size"]).hex() != head["root_hash"]:
            raise ExportError(
                "tree head at size %d does not match the log store"
                % head["tree_size"])
        if not merkle.verify_sth(pub, head):
            raise ExportError("tree head at size %d has a bad signature"
                              % head["tree_size"])
    key_id, pub_raw_hex = _key_id(pub_path)

    # --- builds -----------------------------------------------------------
    builds = collect_builds(artifacts_dir)
    heads_by_size = {h["tree_size"]: h for h in history}
    for b in builds:
        # A receipt carries a full signed tree head. Shipping it unchecked
        # would put a tree_size, root and signature on the page beside numbers
        # that genuinely were recomputed, with nothing to tell them apart —
        # so it has to match a head we already verified, or not ship at all.
        receipt = b.get("receipt")
        if receipt and isinstance(receipt.get("sth"), dict):
            claimed = receipt["sth"]
            head = heads_by_size.get(claimed.get("tree_size"))
            if head is None:
                raise ExportError(
                    "%s: publication receipt cites tree size %s, which is not "
                    "in the log's signed history"
                    % (b["label"], claimed.get("tree_size")))
            for field in ("root_hash", "timestamp", "signature"):
                if claimed.get(field) != head[field]:
                    raise ExportError(
                        "%s: publication receipt's %s disagrees with the "
                        "signed head at size %d"
                        % (b["label"], field, head["tree_size"]))
    for b in builds:
        doc = b["_doc"]
        indices, missing = [], 0
        for p in doc["packages"]:
            data = canonical.log_leaf_data(
                doc["image_line"], p["name"], p["version"], p["arch"],
                p["leaf_hash"])
            idx = by_leaf_hash.get(merkle.leaf_hash(data).hex())
            if idx is None:
                missing += 1
            else:
                indices.append(idx)
        b["member_indices"] = sorted(indices)
        b["unpublished_count"] = missing
        # Deliberately NOT called "published". A log-leaf-v1 leaf commits to a
        # package -- name, version, arch, image line, file digests -- and
        # carries no merkle_root, so nothing in the log attests an image as a
        # whole. All this can honestly say is whether every constituent
        # package appears in the log for this image line; an image assembled
        # entirely from already-published packages (a downgrade, for instance)
        # would satisfy it. Attesting the image itself needs a leaf that binds
        # the device root, which this schema does not yet have.
        b["status"] = ("all-packages-published" if missing == 0
                       else "packages-missing")
        b["image_attested"] = False

    # --- write ------------------------------------------------------------
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    data_dir = os.path.join(out_dir, "data")
    os.makedirs(data_dir)
    os.makedirs(os.path.join(data_dir, "builds"))

    # Static assets, whatever exists so far. Editor backups and bytecode
    # caches must not become part of a bundle whose reproducibility other
    # people are invited to check — otherwise "reproduce the published bytes"
    # silently means "have the same junk in your working tree".
    site_src = os.path.join(base, "site")
    if os.path.isdir(site_src):
        for name in sorted(os.listdir(site_src)):
            if _IGNORED(site_src, [name]):
                continue
            src = os.path.join(site_src, name)
            dst = os.path.join(out_dir, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=_IGNORED)
            else:
                shutil.copy2(src, dst)

    snapshot_id = "%d-%s" % (current["tree_size"], current["root_hash"][:12])
    written = {}

    written["data/snapshot.js"] = _js(
        os.path.join(data_dir, "snapshot.js"), "snapshot", {
            "schema": SCHEMA,
            "snapshot_id": snapshot_id,
            "tree_size": current["tree_size"],
            "root_hash": current["root_hash"],
            "timestamp": current["timestamp"],
            "signature": current["signature"],
            "key_id": key_id,
            "log_pubkey_hex": pub_raw_hex,
            "package_records": len(leaves),
            "build_count": len(builds),
        })

    written["data/leaves.js"] = _js(
        os.path.join(data_dir, "leaves.js"), "leaves", leaves)

    written["data/sth-history.js"] = _js(
        os.path.join(data_dir, "sth-history.js"), "sth_history", [
            {k: h[k] for k in ("tree_size", "root_hash", "timestamp",
                               "signature", "prev_size", "prev_root")
             if k in h}
            for h in history])

    assessments = collect_assessments(
        os.path.join(base, "assessments"), builds)
    written["data/assessments.js"] = _js(
        os.path.join(data_dir, "assessments.js"), "assessments",
        [{k: a[k] for k in a if not k.startswith("_")} |
         {"subject_label": a["_subject_label"]} for a in assessments])

    written["data/builds-index.js"] = _js(
        os.path.join(data_dir, "builds-index.js"), "builds", [
            {k: b[k] for k in
             ("label", "build_id", "image_line", "machine", "version",
              "built_at", "device_root", "pcr14", "package_count",
              "file_count", "status", "unpublished_count", "image_attested")}
            for b in builds])

    for b in builds:
        doc = b["_doc"]
        root = b["device_root"]
        rel = "data/builds/%s.js" % b["label"]
        written[rel] = _js(
            os.path.join(data_dir, "builds", "%s.js" % b["label"]),
            "build_" + b["label"], {
                k: b[k] for k in
                ("label", "build_id", "image_line", "machine", "version",
                 "built_at", "device_root", "pcr14", "package_count",
                 "file_count", "status", "unpublished_count",
                 "image_attested", "member_indices", "artifacts",
                 "receipt")})

        rel = "data/pkgs-%s.js" % root[:16]
        written[rel] = _js(
            os.path.join(data_dir, "pkgs-%s.js" % root[:16]),
            "pkgs_" + root[:16],
            [[p["name"], p["version"], p["arch"], p["leaf_hash"],
              len(p["files"])] for p in doc["packages"]])

        rel = "data/files-%s.js" % root[:16]
        written[rel] = _js(
            os.path.join(data_dir, "files-%s.js" % root[:16]),
            "files_" + root[:16],
            [[p["name"], [[f["path"], f["sha256"]] for f in p["files"]]]
             for p in doc["packages"]])

    # Pages must not run Jekyll over the bundle.
    with open(os.path.join(out_dir, ".nojekyll"), "w") as f:
        f.write("")

    # Ship the material a reader needs to re-check the head without this page
    # or any server: the public key (a public key — safe to publish) and the
    # head as plain JSON.
    shutil.copy2(pub_path, os.path.join(out_dir, "log_ed25519.pub"))
    with open(os.path.join(out_dir, "sth.json"), "w", newline="\n") as f:
        json.dump({k: current[k] for k in
                   ("tree_size", "root_hash", "timestamp", "signature")},
                  f, indent=1, sort_keys=True)
        f.write("\n")

    snapshot_txt = (
        "pkgattest site snapshot\n"
        "=======================\n\n"
        "This bundle is an archived, citable snapshot of one signed tree\n"
        "head. It is not a live mirror: it says what the log looked like at\n"
        "the head below, and nothing about what it looks like now.\n\n"
        "  schema      %s\n"
        "  snapshot    %s\n"
        "  tree_size   %d\n"
        "  root_hash   %s\n"
        "  timestamp   %d\n"
        "  signature   %s\n"
        "  key_id      %s\n"
        "  records     %d\n"
        "  builds      %d\n\n"
        "Re-check the head yourself, offline, without this page:\n\n"
        "  pkgattest verify-sth --sth-file sth.json \\\n"
        "                       --log-pub log_ed25519.pub\n\n"
        "That proves the head is signed by the key in this directory. It\n"
        "does NOT prove that key is the log's: compare key_id above against\n"
        "a value you obtained elsewhere.\n\n"
        "What a log entry does and does not say\n"
        "--------------------------------------\n"
        "Each entry commits to one PACKAGE (name, version, architecture,\n"
        "image line, and the digest of its file list). No entry commits to\n"
        "an image, so 'every package is published' does not mean anyone\n"
        "published this image -- an image built only from already-published\n"
        "packages, including a downgrade, would also satisfy it.\n"
        % (SCHEMA, snapshot_id, current["tree_size"], current["root_hash"],
           current["timestamp"], current["signature"], key_id, len(leaves),
           len(builds)))
    with open(os.path.join(out_dir, "SNAPSHOT.txt"), "w", newline="\n") as f:
        f.write(snapshot_txt)

    # sha256sums.txt last, over everything else, in sorted order.
    sums = []
    for root_dir, dirs, files in os.walk(out_dir):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(root_dir, name)
            rel = os.path.relpath(p, out_dir)
            if rel == "sha256sums.txt":
                continue
            with open(p, "rb") as f:
                sums.append((rel, hashlib.sha256(f.read()).hexdigest()))
    sums.sort()
    with open(os.path.join(out_dir, "sha256sums.txt"), "w",
              newline="\n") as f:
        for rel, digest in sums:
            f.write("%s  %s\n" % (digest, rel))

    return {
        "snapshot_id": snapshot_id,
        "tree_size": current["tree_size"],
        "root_hash": current["root_hash"],
        "records": len(leaves),
        "builds": [{k: b[k] for k in ("label", "build_id", "status",
                                      "package_count", "unpublished_count",
                                      "device_root")}
                   for b in builds],
        "assessments": [{"id": a["assessment_id"],
                         "subject": a["_subject_label"],
                         "examined": len(a.get("examined", [])),
                         "illustrative": a["illustrative"]}
                        for a in assessments],
        "files": len(sums) + 1,
        "bytes": sum(os.path.getsize(os.path.join(out_dir, rel))
                     for rel, _ in sums),
    }
