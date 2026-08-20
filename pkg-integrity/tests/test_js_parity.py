"""Prove the browser verifier (site/verify.js) agrees with the Python one.

The site's whole claim is that the reader's browser — not a server — does the
verification. That claim is only worth anything if the JS reproduces
pkgintegrity/{merkle,canonical}.py byte for byte, so this generates vectors
from the real data and re-derives every one of them under node.

node is a *test* dependency only: nothing at runtime needs it, CI does not
install it, and these tests skip when it is absent. The golden vectors are
written next to the test so a reviewer can diff them without running anything.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical, merkle  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARITY_JS = os.path.join(BASE, "tools", "parity.js")
VERIFY_JS = os.path.join(BASE, "site", "verify.js")
PUB = os.path.join(BASE, "keys", "log_ed25519.pub")
LOG_STORE = os.path.join(BASE, "log", "log.jsonl")
HISTORY = os.path.join(BASE, "log", "sth-history.jsonl")
MEAS_A = os.path.join(
    BASE, "artifacts", "A",
    "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")

NODE = shutil.which("node")

requires_node = pytest.mark.skipif(
    NODE is None or not os.path.exists(VERIFY_JS),
    reason="node (test-only dependency) or site/verify.js not present")


def _pubkey_raw_hex():
    from cryptography.hazmat.primitives import serialization
    pub = merkle.load_ed25519_public(PUB)
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw).hex()


def _synthetic_mth_vectors():
    """RFC 6962 sizes that catch a careless port: n=1 (the `1 << -1` trap),
    n=2, the odd cases where the split is not in the middle, and the real
    tree size."""
    out = []
    for n in (1, 2, 3, 5, 6, 7, 8, 2048, 2049, 2131):
        leaves = [hashlib.sha256(b"leaf-%d" % i).digest() for i in range(n)]
        tree = merkle.MerkleTree()
        tree.leaves = list(leaves)
        out.append({"n": n, "leaves": [b.hex() for b in leaves],
                    "root": tree.root(n).hex()})
    return out


def build_vectors(limit_packages=None):
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}

    # Every package of image A, so the ca-certificates UTF-8 path is covered.
    if os.path.exists(MEAS_A):
        doc = canonical.load_measurements_json(MEAS_A)
        pkgs = doc["packages"]
        if limit_packages:
            names = {"ca-certificates", "dropbear", "systemd", "os-release"}
            pkgs = ([p for p in pkgs if p["name"] in names]
                    + pkgs[:limit_packages])
        vectors["packages"] = [
            {"name": p["name"], "version": p["version"], "arch": p["arch"],
             "files": [{"path": f["path"], "sha256": f["sha256"]}
                       for f in p["files"]],
             "preimage_hex": canonical.PkgLeaf(
                 p["name"], p["version"], p["arch"],
                 [(f["path"], f["sha256"]) for f in p["files"]]
             ).preimage().hex(),
             "leaf_hash": p["leaf_hash"]}
            for p in pkgs]
        vectors["device_trees"] = [{
            "label": "image-A",
            "leaf_hashes": [p["leaf_hash"] for p in doc["packages"]],
            "root": doc["merkle_root"],
            "pcr14": merkle.expected_pcr14(doc["merkle_root"]),
        }]

    if os.path.exists(LOG_STORE):
        records, leaf_hashes = [], []
        with open(LOG_STORE) as f:
            for i, line in enumerate(f):
                leaf_str = json.loads(line)["leaf"]
                obj = json.loads(leaf_str)
                data = canonical.log_leaf_data(
                    obj["image_line"], obj["name"], obj["version"],
                    obj["arch"], obj["pkg_leaf_hash"])
                assert data.decode() == leaf_str, "store is not canonical"
                records.append({
                    "index": i, "arch": obj["arch"],
                    "image_line": obj["image_line"], "name": obj["name"],
                    "version": obj["version"],
                    "pkg_leaf_hash": obj["pkg_leaf_hash"],
                    "data_hex": data.hex(),
                    "leaf_hash": merkle.leaf_hash(data).hex()})
                leaf_hashes.append(merkle.leaf_hash(data))
        vectors["log_records"] = records

        tree = merkle.MerkleTree()
        tree.leaves = list(leaf_hashes)

        heads = []
        if os.path.exists(HISTORY):
            with open(HISTORY) as f:
                heads = [json.loads(line) for line in f if line.strip()]
        vectors["heads"] = [
            {k: h[k] for k in
             ("tree_size", "root_hash", "timestamp", "signature")}
            for h in heads]

        size = tree.size
        sample = sorted({0, 1, 18, size // 2, size - 1})
        vectors["inclusion"] = [
            {"index": i, "tree_size": size,
             "path": [p.hex() for p in tree.inclusion_proof(i, size)],
             "root": tree.root(size).hex()}
            for i in sample if i < size]

        vectors["consistency"] = [
            {"old_size": h["tree_size"], "new_size": size,
             "old_root": h["root_hash"], "new_root": tree.root(size).hex(),
             "proof": [p.hex() for p in
                       tree.consistency_proof(h["tree_size"], size)]}
            for h in heads if 0 < h["tree_size"] < size]

    return vectors


def _run_parity(vectors, tmp_path):
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps(vectors))
    proc = subprocess.run([NODE, PARITY_JS, str(path)],
                          capture_output=True, text=True, timeout=300)
    return proc


@requires_node
def test_js_matches_python_on_real_data(tmp_path):
    vectors = build_vectors()
    if not vectors.get("log_records"):
        pytest.skip("no production log store to compare against")
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "parity OK" in proc.stdout


@requires_node
def test_js_matches_python_on_synthetic_vectors(tmp_path):
    """Runs with no built artifacts — the case a fresh clone hits."""
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_node
def test_parity_harness_detects_a_mismatch(tmp_path):
    """The parity test must be able to fail — a harness that always passes
    proves nothing."""
    vectors = {"log_pubkey_hex": _pubkey_raw_hex(),
               "mth_sizes": _synthetic_mth_vectors()}
    vectors["mth_sizes"][0]["root"] = "00" * 32
    proc = _run_parity(vectors, tmp_path)
    assert proc.returncode == 1
    assert "PARITY FAILED" in proc.stdout


@requires_node
def test_utf8_path_is_the_live_trap(tmp_path):
    """Encoding, not sorting, is what breaks: the one non-ASCII path in the
    image must hash as UTF-8, not via charCode truncation."""
    p = ("/usr/share/ca-certificates/mozilla/"
         "NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt")
    assert hashlib.sha256(p.encode("utf-8")).hexdigest().startswith(
        "ebca1496dd1a66c2ddf84eee")
    wrong = hashlib.sha256(bytes(ord(c) & 0xFF for c in p)).hexdigest()
    assert not wrong.startswith("ebca1496")

    script = (
        "const V=require(%s);"
        "const p=%s;"
        "console.log(V.hex(V.sha256(V.utf8(p))));"
        % (json.dumps(VERIFY_JS), json.dumps(p)))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == hashlib.sha256(p.encode("utf-8")).hexdigest()


@requires_node
def test_utf8_byte_sort_not_utf16(tmp_path):
    """Array.sort() ranks by UTF-16 code unit and disagrees with Python's
    codepoint order for astral characters. No such path exists in today's
    image, which is precisely why the comparator must be tested directly."""
    items = ["a\U0001F600b", "aﬀb", "aÿb"]
    expected = sorted(items)          # Python codepoint order
    script = (
        "const V=require(%s);"
        "const it=%s;"
        "console.log(JSON.stringify(it.slice().sort(V.compareUtf8)));"
        "console.log(JSON.stringify(it.slice().sort()));"
        % (json.dumps(VERIFY_JS), json.dumps(items)))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    utf8_sorted, naive_sorted = proc.stdout.strip().splitlines()
    assert json.loads(utf8_sorted) == expected
    # And prove the naive sort really would have differed.
    assert json.loads(naive_sorted) != expected


@requires_node
def test_canonical_json_escaping_matches_python_everywhere(tmp_path):
    """The real data is 100% ASCII, so the parity vectors cannot exercise
    pyJsonString at all. Fuzz it against Python across the character space —
    control characters, DEL, U+2028/U+2029, the surrogate range boundaries and
    astral characters, where Python emits a surrogate *pair* of \\uXXXX
    escapes from one codepoint."""
    import random
    random.seed(11)
    cases = [chr(cp) for cp in
             list(range(0, 0x90)) + [0x7f, 0xa0, 0xe9, 0x151, 0x2028, 0x2029,
                                     0xd7ff, 0xe000, 0xfffd, 0xffff,
                                     0x10000, 0x1f600, 0x10ffff]]
    cases += ["", '"', "\\", "</script>", 'a"b\\c', "tab\there", "nl\nhere",
              "\x00\x01\x1f"]
    alpha = [chr(c) for c in (0x41, 0x7f, 0xe9, 0x151, 0x2028, 0x1f600,
                              0x10ffff, 0x22, 0x5c, 0x0a)]
    for _ in range(300):
        cases.append("".join(random.choice(alpha)
                             for _ in range(random.randint(0, 8))))

    payload = tmp_path / "cases.json"
    payload.write_text(json.dumps(
        {"cases": cases,
         "expected": [json.dumps(c, ensure_ascii=True) for c in cases]}))

    script = (
        "const V=require(%s);const d=require(%s);let bad=[];"
        "d.cases.forEach((c,i)=>{if(V.pyJsonString(c)!==d.expected[i])"
        "bad.push(i);});"
        "console.log(JSON.stringify({n:d.cases.length,bad:bad.slice(0,5),"
        "count:bad.length}));"
        % (json.dumps(VERIFY_JS), json.dumps(str(payload))))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["count"] == 0, (
        "pyJsonString diverged from Python on %d/%d cases (first: %r)"
        % (result["count"], result["n"],
           [cases[i] for i in result["bad"]]))


@requires_node
def test_sort_order_matches_python_and_the_naive_sort_would_not(tmp_path):
    """compareUtf8 must equal Python's codepoint order. The same test proves
    the guard is load-bearing: plain Array.sort() gets a large fraction of
    these wrong."""
    import random
    random.seed(23)
    alpha = [chr(c) for c in (0x20, 0x21, 0x30, 0x41, 0x5a, 0x61, 0x7a, 0x7f,
                              0xa0, 0xe9, 0x151, 0x7ff, 0x800, 0xd7ff, 0xe000,
                              0xfffd, 0xffff, 0x10000, 0x1f600, 0x10ffff)]
    lists = [["".join(random.choice(alpha)
                      for _ in range(random.randint(0, 6)))
              for _ in range(random.randint(2, 10))] for _ in range(200)]
    lists += [["", "\U0001F600"], ["￿", "\U00010000"],
              ["ab", "a\U0001F600b"]]

    payload = tmp_path / "lists.json"
    payload.write_text(json.dumps(
        {"lists": lists, "sorted": [sorted(l) for l in lists]}))

    script = (
        "const V=require(%s);const d=require(%s);let bad=0,naive=0;"
        "d.lists.forEach((l,i)=>{"
        " if(JSON.stringify(l.slice().sort(V.compareUtf8))!=="
        "    JSON.stringify(d.sorted[i])) bad++;"
        " if(JSON.stringify(l.slice().sort())!==JSON.stringify(d.sorted[i]))"
        "    naive++;});"
        "console.log(JSON.stringify({bad:bad,naive:naive,n:d.lists.length}));"
        % (json.dumps(VERIFY_JS), json.dumps(str(payload))))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["bad"] == 0, (
        "compareUtf8 diverged from Python on %d/%d lists"
        % (result["bad"], result["n"]))
    assert result["naive"] > 0, (
        "Array.sort() agreed everywhere, so this test is not proving the "
        "comparator is needed — strengthen the corpus")


@requires_node
def test_bad_tree_sizes_raise_rather_than_exhaust_the_stack(tmp_path):
    """A verifier is handed a tree size straight out of a snapshot it does not
    yet trust. Without a guard, subtree() recurses on an interval that never
    shrinks: '0', null, -1 and 2.5 all die with RangeError instead of a clear
    error. Python raises IndexError on the same inputs."""
    script = (
        "const V=require(%s);"
        "const L=[...Array(6)].map((_,i)=>V.sha256(V.utf8('x'+i)));"
        "const cases={'string-zero':'0','null':null,'negative':-1,"
        "'fraction':2.5,'beyond-tree':7,'huge':1e20,'unsafe':2**53+2};"
        "const out={};"
        "for (const k of Object.keys(cases)) {"
        "  try { V.mth(L, cases[k]); out[k]='ok'; }"
        "  catch(e){ out[k]=e.constructor.name; } }"
        "try { V.inclusionProof(L, 0, -1); out['proof']='ok'; }"
        "catch(e){ out['proof']=e.constructor.name; }"
        "try { V.inclusionProof(L, 2.5, 6); out['proof-index']='ok'; }"
        "catch(e){ out['proof-index']=e.constructor.name; }"
        "try { V.consistencyProof(L, 1, -1); out['consistency']='ok'; }"
        "catch(e){ out['consistency']=e.constructor.name; }"
        "console.log(JSON.stringify(out));" % json.dumps(VERIFY_JS))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)

    # null means "the whole tree", matching Python's size=None.
    assert out["null"] == "ok", out
    for bad in ("string-zero", "negative", "fraction", "beyond-tree", "huge",
                "unsafe", "proof", "proof-index", "consistency"):
        assert out[bad] == "Error", (
            "%s gave %s, expected a clean Error (RangeError means the stack "
            "was exhausted)" % (bad, out[bad]))


@requires_node
def test_selftest_catches_a_broken_primitive(tmp_path):
    """A self-test that cannot fail is decoration.

    sha512 and Ed25519 are reachable only through the signature path, so if
    they broke — a vendored-crypto upgrade that renamed the sha512 hook, say —
    every genuine tree head would report "signature INVALID", the most
    alarming thing this site can say, while a self-test covering only sha256
    stayed green. Load verify.js against deliberately broken primitives and
    require it to notice each one."""
    vendor = os.path.join(BASE, "site", "vendor", "pkgcrypto.js")
    harness = r"""
    const fs=require('fs'), vm=require('vm'), path=require('path');
    function run(breakName){
      const ctx=vm.createContext({TextEncoder,TextDecoder,console,require});
      vm.runInContext(fs.readFileSync(VENDOR,'utf8'),ctx,{filename:'vendor'});
      // Break exactly one primitive, leaving the rest genuine.
      vm.runInContext(`
        var __real = PKGI_CRYPTO;
        PKGI_CRYPTO = {
          sha256: ${breakName==='sha256'
            ? '(b)=>new Uint8Array(32)' : '__real.sha256'},
          sha512: ${breakName==='sha512'
            ? '(b)=>new Uint8Array(64)' : '__real.sha512'},
          ed25519Verify: ${breakName==='ed25519'
            ? '()=>false' : (breakName==='ed25519-permissive'
                             ? '()=>true' : '__real.ed25519Verify')},
        };`, ctx);
      vm.runInContext(fs.readFileSync(VERIFY,'utf8'),ctx,{filename:'verify'});
      return vm.runInContext('PKGI_VERIFY.selfTest()',ctx);
    }
    const out={};
    for (const b of ['none','sha256','sha512','ed25519','ed25519-permissive']){
      out[b]=run(b);
    }
    console.log(JSON.stringify(out));
    """
    script = ("const VENDOR=%s, VERIFY=%s;\n%s"
              % (json.dumps(vendor), json.dumps(VERIFY_JS), harness))
    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)

    assert result["none"] == [], (
        "self-test fails on genuine primitives: %r" % result["none"])
    for broken in ("sha256", "sha512", "ed25519", "ed25519-permissive"):
        assert result[broken], (
            "selfTest did not notice a broken %s — it would render a green "
            "tick on top of it" % broken)


@requires_node
def test_malformed_records_raise_rather_than_hash_wrong(tmp_path):
    """Python raises on a malformed record; JS would happily interpolate
    `undefined` or treat a number as an empty string, producing a well-formed
    but wrong leaf. Downstream that reads as "this package was never
    published" — a false accusation, which is the worst output this project
    can produce. Every one of these must throw."""
    cases = [
        ("numeric version",
         "V.logLeafData({arch:'a',image_line:'i',name:'n',"
         "pkg_leaf_hash:'h',version:2026})"),
        ("null field",
         "V.logLeafData({arch:'a',image_line:'i',name:null,"
         "pkg_leaf_hash:'h',version:'1'})"),
        ("file entry missing its digest",
         "V.pkgLeafPreimage({name:'p',version:'1',arch:'x',"
         "files:[{path:'/a'}]})"),
        ("missing package name",
         "V.pkgLeafPreimage({version:'1',arch:'x',files:[]})"),
        ("files not an array",
         "V.pkgLeafPreimage({name:'p',version:'1',arch:'x',files:'nope'})"),
    ]
    script = "const V=require(%s);const out=[];" % json.dumps(VERIFY_JS)
    for label, expr in cases:
        script += ("try{%s;out.push([%s,false]);}"
                   "catch(e){out.push([%s,true]);}"
                   % (expr, json.dumps(label), json.dumps(label)))
    # And a valid record must still work.
    script += ("out.push(['valid', V.pkgLeafHash({name:'p',version:'1',"
               "arch:'x',files:[{path:'/a',sha256:'ab'}]}).length === 64]);")
    script += "console.log(JSON.stringify(out));"

    proc = subprocess.run([NODE, "-e", script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    for label, threw in json.loads(proc.stdout):
        assert threw, "%s did not raise — it would hash a wrong leaf" % label


@requires_node
def test_vendored_crypto_is_reproducible():
    """The committed vendor bundle must be exactly what the pinned upstream
    sources regenerate — offline, no network."""
    proc = subprocess.run(
        [sys.executable, os.path.join(BASE, "tools", "vendor_crypto.py"),
         "--check"], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check-vendor: OK" in proc.stdout


def test_vendor_converter_refuses_content_after_the_export():
    """EXPORT_RE uses re.M, so `$` matches at any line end. Without an
    explicit check, everything after the first export statement would be
    silently dropped — which on a future upstream build could mean discarding
    real code from a crypto bundle and pinning the mangled result forever."""
    sys.path.insert(0, os.path.join(BASE, "tools"))
    import vendor_crypto

    ok, stripped = vendor_crypto._convert(
        "var a=1;\nexport{a as sha256};\n", "test/ok")
    assert "a=1" in ok and stripped == []

    with pytest.raises(SystemExit, match="follow the export"):
        vendor_crypto._convert(
            "var a=1;\nexport{a as sha256};\nglobalThis.__patch=1;\n",
            "test/trailing")
