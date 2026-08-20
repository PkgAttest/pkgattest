/* verify.js -- the pkgattest verification core, run in the reader's browser.
 *
 * This is a byte-exact port of pkgintegrity/{merkle,canonical}.py. The three
 * existing implementations (Yocto class, on-device bash, host python) already
 * have to agree byte-for-byte; this is the fourth. pkg-integrity/SPEC.md is
 * the binding spec -- change it and all four together.
 *
 * Deliberate choices, each with a reason:
 *   - Classic script, no ES module, no fetch(): both are CORS-blocked on
 *     file://, and the offline bundle must be the same bytes as the hosted one.
 *   - This file is pure ASCII. It is loaded as a classic script, and over
 *     file:// there is no Content-Type header, so the browser guesses the
 *     encoding. A literal non-ASCII character in a string would be at the
 *     mercy of that guess; \uXXXX escapes are not.
 *   - Sorting compares UTF-8 bytes, never JS string order. Array.sort() ranks
 *     by UTF-16 code unit, which disagrees with Python's codepoint order (and
 *     with LC_ALL=C) for astral characters. Today's images contain no such
 *     path, so this is a latent trap rather than a live bug -- which is
 *     exactly the kind that ships.
 *   - Text becomes bytes through TextEncoder (UTF-8). Encoding, not sorting,
 *     is the live trap: the one non-ASCII path in the image hashes to
 *     ebca1496... as UTF-8 and to something else entirely via charCode
 *     truncation.
 *
 * Nothing here is secret, so nothing here needs to be constant-time.
 */
var PKGI_VERIFY = (function (crypto) {
  'use strict';

  var enc = new TextEncoder();

  function utf8(s) { return enc.encode(s); }

  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) {
      out.set(arguments[i], off);
      off += arguments[i].length;
    }
    return out;
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return s;
  }

  function unhex(s) {
    if (typeof s !== 'string' || s.length % 2 || /[^0-9a-fA-F]/.test(s)) {
      throw new Error('not hex: ' + String(s).slice(0, 32));
    }
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(s.substr(i * 2, 2), 16);
    }
    return out;
  }

  function equal(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  var sha256 = crypto.sha256;

  /* Lexicographic comparison of the UTF-8 encodings -- this is what
   * `LC_ALL=C sort` does, and what Python's codepoint ordering equals, for
   * every encodable codepoint (a 4-byte astral sequence F0.. sorts above a
   * 3-byte EF.., matching codepoint order).
   *
   * One known divergence, not reachable from real data: TextEncoder replaces
   * a LONE surrogate with U+FFFD, so two distinct lone surrogates compare
   * equal here while Python orders them, and Python's .encode("utf-8") would
   * raise where this silently substitutes. Only a literal \\udXXX escape in a
   * data file could produce one, and the build already rejects such paths. */
  function compareUtf8(a, b) {
    var x = utf8(a), y = utf8(b), n = Math.min(x.length, y.length);
    for (var i = 0; i < n; i++) {
      if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    }
    return x.length === y.length ? 0 : (x.length < y.length ? -1 : 1);
  }

  // ---------------------------------------------------------------- log tree
  // RFC 6962. Port of pkgintegrity/merkle.py.

  function leafHash(data) { return sha256(concat(new Uint8Array([0]), data)); }

  function nodeHash(l, r) {
    return sha256(concat(new Uint8Array([1]), l, r));
  }

  /* Ported verbatim from merkle._largest_power_of_two_lt. Written as a loop,
   * not `1 << (bitLength(n-1) - 1)`: the shift form is undefined at n === 1
   * (JS evaluates `1 << -1` to -2147483648) and overflows at 32 bits. */
  function largestPowerOfTwoLt(n) {
    var k = 1;
    while (k * 2 < n) k *= 2;
    return k;
  }

  var EMPTY_TREE_ROOT = sha256(new Uint8Array(0));

  /* Merkle Tree Hash over leafHashes[0:size]. The recursion splits at the
   * largest power of two below n, so its depth is logarithmic (about 12 at
   * n=2131, about 20 at a million) -- no stack risk at any realistic size. */
  function mth(leafHashes, size) {
    if (size === undefined) size = leafHashes.length;
    if (size === 0) return EMPTY_TREE_ROOT;
    if (size > leafHashes.length) throw new Error('size beyond tree');
    return subtree(leafHashes, 0, size);
  }

  /* Root of leafHashes[lo:hi], split at the largest power of two < n. */
  function subtree(leafHashes, lo, hi) {
    var n = hi - lo;
    if (n === 1) return leafHashes[lo];
    var k = largestPowerOfTwoLt(n);
    return nodeHash(subtree(leafHashes, lo, lo + k),
                    subtree(leafHashes, lo + k, hi));
  }

  /* Audit path for leaf `index` in the size-`size` tree. Derived locally from
   * the leaf set the reader holds -- never fetched from a server. */
  function inclusionProof(leafHashes, index, size) {
    if (size === undefined) size = leafHashes.length;
    if (!(index >= 0 && index < size && size <= leafHashes.length)) {
      throw new Error('bad index/size');
    }
    function path(m, lo, hi) {
      var n = hi - lo;
      if (n === 1) return [];
      var k = largestPowerOfTwoLt(n);
      if (m < k) {
        return path(m, lo, lo + k).concat([subtree(leafHashes, lo + k, hi)]);
      }
      return path(m - k, lo + k, hi).concat([subtree(leafHashes, lo, lo + k)]);
    }
    return path(index, 0, size);
  }

  /* Port of merkle.verify_inclusion. The direction alternates per level and
   * the `fn === sn` case fires on non-power-of-two trees (it does at 2131),
   * so the UI must render each step's direction rather than one formula. */
  function verifyInclusion(leaf, index, size, proof, root) {
    if (index >= size) return false;
    var h = leaf, fn = index, sn = size - 1;
    for (var i = 0; i < proof.length; i++) {
      var p = proof[i];
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        h = nodeHash(p, h);
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      } else {
        h = nodeHash(h, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && equal(h, root);
  }

  /* Which side each proof node joins on, for rendering the ladder. Mirrors
   * verifyInclusion step for step, so the drawing cannot disagree with the
   * proof it claims to show. */
  function inclusionSteps(index, size, proof) {
    var steps = [], fn = index, sn = size - 1;
    for (var i = 0; i < proof.length; i++) {
      if (sn === 0) break;
      if (fn % 2 === 1 || fn === sn) {
        steps.push({ sibling: proof[i], side: 'left' });
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      } else {
        steps.push({ sibling: proof[i], side: 'right' });
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return steps;
  }

  /* Port of merkle.verify_consistency. */
  function verifyConsistency(oldSize, newSize, oldRoot, newRoot, proof) {
    if (oldSize === newSize) {
      return proof.length === 0 && equal(oldRoot, newRoot);
    }
    if (!(oldSize > 0 && oldSize < newSize)) return false;
    proof = proof.slice();
    if ((oldSize & -oldSize) === oldSize) proof.unshift(oldRoot);
    if (!proof.length) return false;
    var fn = oldSize - 1, sn = newSize - 1;
    while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    var fr = proof[0], sr = proof[0];
    for (var i = 1; i < proof.length; i++) {
      var p = proof[i];
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        fr = nodeHash(p, fr);
        sr = nodeHash(p, sr);
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      } else {
        sr = nodeHash(sr, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && equal(fr, oldRoot) && equal(sr, newRoot);
  }

  function consistencyProof(leafHashes, oldSize, newSize) {
    if (newSize === undefined) newSize = leafHashes.length;
    if (!(oldSize > 0 && oldSize <= newSize && newSize <= leafHashes.length)) {
      throw new Error('bad sizes');
    }
    if (oldSize === newSize) return [];
    function subproof(m, lo, hi, complete) {
      var n = hi - lo;
      if (m === n) return complete ? [] : [subtree(leafHashes, lo, hi)];
      var k = largestPowerOfTwoLt(n);
      if (m <= k) {
        return subproof(m, lo, lo + k, complete)
          .concat([subtree(leafHashes, lo + k, hi)]);
      }
      return subproof(m - k, lo + k, hi, false)
        .concat([subtree(leafHashes, lo, lo + k)]);
    }
    return subproof(oldSize, 0, newSize, true);
  }

  // ------------------------------------------------------------- device tree
  // pkg-merkle-v1: deliberately NOT RFC 6962 -- it is recomputed in busybox
  // bash on the BMC, so it works on hex text. Never conflate the two.

  function deviceNodeHash(leftHex, rightHex) {
    return hex(sha256(utf8('pkg-node-v1\n' + leftHex + '\n' + rightHex + '\n')));
  }

  function deviceRoot(leavesHex) {
    if (!leavesHex.length) throw new Error('empty leaf set');
    var level = leavesHex.slice();
    while (level.length > 1) {
      var next = [];
      for (var i = 0; i + 1 < level.length; i += 2) {
        next.push(deviceNodeHash(level[i], level[i + 1]));
      }
      if (level.length % 2) next.push(level[level.length - 1]);
      level = next;
    }
    return level[0];
  }

  /* PCR 14 after one sha256-bank extend of the root from reset. Note this
   * hashes the root's 32 RAW BYTES, not its 64 hex characters. */
  function expectedPcr14(rootHex) {
    return hex(sha256(concat(new Uint8Array(32), unhex(rootHex))));
  }

  // -------------------------------------------------------- canonical formats

  /* pkg-leaf-v1 preimage. Port of canonical.PkgLeaf.preimage. Python sorts the
   * JOINED "<path> <sha256>" lines, so this must too. */
  function str(value, what) {
    if (typeof value !== 'string') {
      throw new Error(what + ' must be a string, got ' +
                      (value === null ? 'null' : typeof value));
    }
    return value;
  }

  function pkgLeafPreimage(pkg) {
    /* Every field is type-checked before it reaches the preimage. Python
     * raises on a malformed record (a file entry that will not unpack, a
     * missing name); JS would happily interpolate "undefined" and produce a
     * silently different leaf hash -- which reads downstream as "this package
     * was never published" rather than as the data error it is. */
    str(pkg.name, 'package name');
    str(pkg.version, 'package version');
    str(pkg.arch, 'package arch');
    if (!Array.isArray(pkg.files)) throw new Error('package files must be an array');
    var lines = pkg.files.map(function (f, i) {
      var path = f.path !== undefined ? f.path : f[0];
      var digest = f.sha256 !== undefined ? f.sha256 : f[1];
      return str(path, 'file path #' + i) + ' ' +
             str(digest, 'file sha256 #' + i);
    });
    lines.sort(compareUtf8);
    var head = 'pkg-leaf-v1\nname=' + pkg.name + '\nversion=' + pkg.version +
               '\narch=' + pkg.arch + '\nfiles=' + lines.length + '\n';
    return utf8(head + lines.map(function (l) { return l + '\n'; }).join(''));
  }

  function pkgLeafHash(pkg) { return hex(sha256(pkgLeafPreimage(pkg))); }

  /* Python's json.dumps(..., ensure_ascii=True) string escaping.
   *
   * Iterating by UTF-16 code unit is correct here, not a bug: for a character
   * outside the BMP Python emits the two \uXXXX escapes of its surrogate
   * pair, which is exactly what stepping over the two JS code units produces.
   */
  var ESCAPES = { '\\': '\\\\', '"': '\\"', '\b': '\\b', '\f': '\\f',
                  '\n': '\\n', '\r': '\\r', '\t': '\\t' };

  function pyJsonString(s) {
    /* Fail loudly on a non-string. Without this, `(2026).length` is undefined,
     * the loop never runs, and the function returns an empty JSON string --
     * so a version that arrived as a JSON number would hash to a well-formed
     * but wrong leaf, miss the log, and make the page accuse a package of
     * never having been published. A false accusation is the single worst
     * output this project can produce; an exception is far better. */
    if (typeof s !== 'string') {
      throw new Error('log-leaf-v1 fields must be strings, got ' +
                      (s === null ? 'null' : typeof s));
    }
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i), code = s.charCodeAt(i);
      if (ESCAPES[ch] !== undefined) out += ESCAPES[ch];
      else if (code < 0x20 || code > 0x7e) {
        out += '\\u' + ('0000' + code.toString(16)).slice(-4);
      } else out += ch;
    }
    return out + '"';
  }

  /* log-leaf-v1 canonical bytes. Port of canonical.log_leaf_data: keys sorted,
   * separators (",",":"), ensure_ascii, no trailing newline. */
  function logLeafData(rec) {
    var obj = {
      arch: rec.arch,
      image_line: rec.image_line,
      name: rec.name,
      pkg_leaf_hash: rec.pkg_leaf_hash,
      schema: 'log-leaf-v1',
      version: rec.version
    };
    var keys = Object.keys(obj).sort();
    var parts = keys.map(function (k) {
      return pyJsonString(k) + ':' + pyJsonString(obj[k]);
    });
    return utf8('{' + parts.join(',') + '}');
  }

  // ------------------------------------------------------- signed tree head

  function sthPayload(size, rootHex, timestamp) {
    return utf8('pkg-log-sth-v1 ' + size + ' ' + rootHex + ' ' +
                timestamp + '\n');
  }

  /* Verify an STH.
   *
   * Type discipline matters here because the two implementations must agree
   * on which heads are VALID, not merely on the bytes signed. Python's
   * sth_payload formats size and timestamp with %d (only root_hex is %s), so
   * a string-valued tree_size raises there and verify_sth returns False.
   * Accepting one here would make the browser call a head valid that the
   * exporter refuses to export. So: integers must be integers.
   *
   * This is deliberately stricter than Python in one direction \u2014 Python's %d
   * would silently truncate a float, and we reject it. Being stricter than
   * the reference can only reject things, never forge them.
   *
   * The key is validated separately and THROWS rather than returning false:
   * an unusable key is an operator error, and reporting it as "signature
   * invalid" would libel a perfectly good head. */
  function verifySth(pubKeyRaw, sth) {
    if (!(pubKeyRaw instanceof Uint8Array) || pubKeyRaw.length !== 32) {
      throw new Error('unusable log public key: expected 32 raw bytes, got ' +
                      (pubKeyRaw && pubKeyRaw.length !== undefined
                       ? pubKeyRaw.length + ' bytes' : typeof pubKeyRaw));
    }
    if (sth === null || typeof sth !== 'object') return false;
    if (typeof sth.root_hash !== 'string' ||
        !/^[0-9a-f]{64}$/.test(sth.root_hash)) return false;
    if (!Number.isInteger(sth.tree_size) || sth.tree_size < 0) return false;
    if (!Number.isInteger(sth.timestamp) || sth.timestamp < 0) return false;
    if (typeof sth.signature !== 'string' ||
        !/^[0-9a-f]{128}$/.test(sth.signature)) return false;
    var payload = sthPayload(sth.tree_size, sth.root_hash, sth.timestamp);
    return crypto.ed25519Verify(unhex(sth.signature), payload, pubKeyRaw);
  }

  /* Known-answer self-test. Call this before rendering any verdict: a broken
   * primitive must never be allowed to draw a green tick. */
  function selfTest() {
    var problems = [];
    if (hex(sha256(utf8('abc'))) !==
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
      problems.push('sha256 known-answer failed');
    }
    if (hex(EMPTY_TREE_ROOT) !==
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
      problems.push('empty-tree root wrong');
    }
    if (largestPowerOfTwoLt(1) !== 1 || largestPowerOfTwoLt(2) !== 1 ||
        largestPowerOfTwoLt(5) !== 4 || largestPowerOfTwoLt(2131) !== 2048) {
      problems.push('largestPowerOfTwoLt wrong');
    }
    /* The one non-ASCII path in the image, written as escapes rather than
     * literals so this check does not depend on how the browser guessed the
     * encoding of this very file: it is the canary for UTF-8 handling. */
    var p = '/usr/share/ca-certificates/mozilla/' +
            'NetLock_Arany_=Class_Gold=_F\u0151tan\u00fas\u00edtv\u00e1ny.crt';
    if (hex(sha256(utf8(p))).slice(0, 24) !== 'ebca1496dd1a66c2ddf84eee') {
      problems.push('UTF-8 encoding of the non-ASCII path is wrong');
    }
    if (pyJsonString('a"b\\c\nde\u00e9f') !==
        '"a\\"b\\\\c\\nde\\u00e9f"') {
      problems.push('canonical JSON string escaping wrong');
    }
    /* sha512 and Ed25519 are only reachable through the signature path, so
     * without these two checks a broken sha512Sync hook (a vendored-crypto
     * upgrade, say) would make every genuine tree head report "signature
     * INVALID" -- the most alarming thing this site can say -- while the
     * self-test stayed green. RFC 8032 section 7.1, TEST 1. */
    if (hex(crypto.sha512(utf8('abc'))) !==
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f') {
      problems.push('sha512 known-answer failed');
    }
    var rfcPub = unhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325' +
                       'af021a68f707511a');
    var rfcSig = unhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974' +
                       'd873e065224901555fb8821590a33bacc61e39701cf9b46b' +
                       'd25bf5f0595bbe24655141438e7a100b');
    if (crypto.ed25519Verify(rfcSig, new Uint8Array(0), rfcPub) !== true) {
      problems.push('ed25519 known-answer failed (valid signature rejected)');
    }
    var bad = rfcSig.slice();
    bad[0] ^= 1;
    if (crypto.ed25519Verify(bad, new Uint8Array(0), rfcPub) !== false) {
      problems.push('ed25519 accepted a tampered signature');
    }
    return problems;
  }

  return {
    utf8: utf8, hex: hex, unhex: unhex, concat: concat, equal: equal,
    sha256: sha256, compareUtf8: compareUtf8,
    leafHash: leafHash, nodeHash: nodeHash,
    largestPowerOfTwoLt: largestPowerOfTwoLt, EMPTY_TREE_ROOT: EMPTY_TREE_ROOT,
    mth: mth, inclusionProof: inclusionProof, verifyInclusion: verifyInclusion,
    inclusionSteps: inclusionSteps,
    consistencyProof: consistencyProof, verifyConsistency: verifyConsistency,
    deviceNodeHash: deviceNodeHash, deviceRoot: deviceRoot,
    expectedPcr14: expectedPcr14,
    pkgLeafPreimage: pkgLeafPreimage, pkgLeafHash: pkgLeafHash,
    logLeafData: logLeafData, pyJsonString: pyJsonString,
    sthPayload: sthPayload, verifySth: verifySth,
    selfTest: selfTest
  };
})(typeof PKGI_CRYPTO !== 'undefined' ? PKGI_CRYPTO
                                      : require('./vendor/pkgcrypto.js'));

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PKGI_VERIFY;
}
