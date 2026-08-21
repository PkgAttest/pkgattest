/* app.js -- renders the pkgattest snapshot, and refuses to render a verdict
 * it did not compute.
 *
 * Two rules this file exists to enforce:
 *
 *   1. PKGI_VERIFY.selfTest() runs before anything else. If a primitive is
 *      broken the page shows that and stops. A green tick drawn on top of
 *      arithmetic that failed is worse than no page at all.
 *
 *   2. Every value is written with textContent into an element built by
 *      createElement. No innerHTML, no inline styles, no inline handlers --
 *      package names and file paths are attacker-influenced data, and the CSP
 *      that would otherwise catch a slip is a <meta> tag on a host that
 *      cannot set headers.
 *
 * Classic script, no modules, no fetch: both are CORS-blocked on file://, and
 * the offline bundle has to be the same bytes as the hosted one.
 */
(function () {
  'use strict';

  var V = window.PKGI_VERIFY;
  var D = window.PKGI_DATA || {};
  var view = document.getElementById('view');

  // ---------------------------------------------------------------- helpers
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* A digest, whole, in 8 groups of 8. Abbreviating a hash that is being
     verified would leave the reader nothing to check. */
  function digest(hex, computed) {
    var wrap = el('div', 'digest' + (computed ? ' is-computed' : ''));
    for (var i = 0; i < hex.length; i += 8) {
      wrap.appendChild(el('span', null, hex.slice(i, i + 8)));
    }
    return wrap;
  }

  function group(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function loadScript(src, done) {
    var s = document.createElement('script');
    s.src = src;
    s.onload = function () { done(null); };
    s.onerror = function () { done(new Error('cannot load ' + src)); };
    document.head.appendChild(s);
  }

  function receiptRow(op, detail, value, state) {
    var row = el('div', 'receipt-row');
    row.appendChild(el('div', 'receipt-op', op));
    var mid = el('div', 'receipt-detail');
    if (typeof detail === 'string') mid.appendChild(document.createTextNode(detail));
    else if (detail) mid.appendChild(detail);
    row.appendChild(mid);
    row.appendChild(el('div', 'receipt-value' + (state ? ' ' + state : ''),
                       value));
    return row;
  }

  // ------------------------------------------------------------- the checks
  /* Everything the page later states as fact is produced here, once. */
  function verifyEverything() {
    var snap = D.snapshot;
    var out = { snapshot: snap, problems: [] };

    var t0 = (window.performance || Date).now();
    var leafHashes = D.leaves.map(function (s) {
      return V.leafHash(V.utf8(s));
    });
    var root = V.hex(V.mth(leafHashes, snap.tree_size));
    out.ms = Math.round(((window.performance || Date).now() - t0) * 10) / 10;

    out.leafHashes = leafHashes;
    out.root = root;
    out.rootMatches = (root === snap.root_hash);
    if (!out.rootMatches) {
      out.problems.push('the root rebuilt from these ' + snap.tree_size +
                        ' records is not the one the tree head is signed over');
    }

    // Leaves past tree_size are covered by no signature at all.
    if (D.leaves.length !== snap.tree_size) {
      out.problems.push('this bundle carries ' + D.leaves.length +
                        ' records but the signed head covers only ' +
                        snap.tree_size);
    }

    out.pub = V.unhex(snap.log_pubkey_hex);
    out.sigOk = V.verifySth(out.pub, snap);
    if (!out.sigOk) out.problems.push('the tree head signature does not verify');

    out.payload = 'pkg-log-sth-v1 ' + snap.tree_size + ' ' + snap.root_hash +
                  ' ' + snap.timestamp;

    // Each build: recompute its device root, then ask the log about every
    // package it contains.
    var byLeafHash = {};
    for (var i = 0; i < snap.tree_size; i++) {
      byLeafHash[V.hex(leafHashes[i])] = i;
    }
    out.byLeafHash = byLeafHash;

    /* The lookup index. Every entry is keyed by a hash this browser derived,
     * except the two -- device roots and tree-head roots -- that the bundle
     * states and the page recomputes elsewhere.
     *
     * Internal tree nodes are deliberately absent: a node hash is only
     * meaningful at one tree size, so an old one would resolve to nothing and
     * read as a bug rather than as the tree-size-scoped value it is. They
     * appear inside a proof ladder, where their size is on screen. */
    var index = { logLeaf: {}, pkgLeaf: {}, deviceRoot: {}, sthRoot: {},
                  file: {}, pcr14: {}, artifact: {} };

    function add(map, key, value) {
      if (!key) return;
      (map[key] = map[key] || []).push(value);
    }

    D.leaves.forEach(function (leafStr, i) {
      if (i >= snap.tree_size) return;   // beyond the signature
      var rec = JSON.parse(leafStr);
      add(index.logLeaf, V.hex(leafHashes[i]), { index: i, rec: rec });
      add(index.pkgLeaf, rec.pkg_leaf_hash, { index: i, rec: rec });
    });

    (D.sth_history || []).forEach(function (h) {
      add(index.sthRoot, h.root_hash, h);
    });
    add(index.sthRoot, V.hex(V.EMPTY_TREE_ROOT), { tree_size: 0, genesis: true });

    out.builds = (D.builds || []).map(function (b) {
      var short = b.device_root.slice(0, 16);
      var pkgs = D['pkgs_' + short];
      var files = D['files_' + short];
      var result = { meta: b, unaccounted: null, deviceRootOk: null,
                     pkgs: null, filesByName: null, leafHexes: null };

      add(index.deviceRoot, b.device_root, b);
      add(index.pcr14, b.pcr14, b);
      Object.keys(b.artifacts || {}).forEach(function (name) {
        var a = b.artifacts[name];
        if (a && a.sha256) {
          add(index.artifact, a.sha256, { build: b, name: name, meta: a });
        }
      });

      if (!pkgs || !files) return result;    // detail not loaded yet

      var filesByName = {};
      files.forEach(function (row) { filesByName[row[0]] = row[1]; });

      var leafHexes = pkgs.map(function (row) {
        return V.pkgLeafHash({
          name: row[0], version: row[1], arch: row[2],
          files: (filesByName[row[0]] || []).map(function (f) {
            return { path: f[0], sha256: f[1] };
          })
        });
      });
      result.deviceRootOk = (V.deviceRoot(leafHexes) === b.device_root);
      result.pkgs = pkgs;
      result.filesByName = filesByName;
      result.leafHexes = leafHexes;

      var missing = [];
      pkgs.forEach(function (row, idx) {
        var data = V.logLeafData({
          arch: row[2], image_line: b.image_line, name: row[0],
          version: row[1], pkg_leaf_hash: leafHexes[idx]
        });
        var inLog = V.hex(V.leafHash(data)) in byLeafHash;
        if (!inLog) missing.push({ name: row[0], version: row[1] });
        add(index.pkgLeaf, leafHexes[idx],
            { build: b, pkgIndex: idx, row: row, inLog: inLog });
        (filesByName[row[0]] || []).forEach(function (f) {
          add(index.file, f[1], { build: b, pkg: row[0], path: f[0] });
        });
      });
      result.unaccounted = missing;
      return result;
    });

    out.index = index;
    return out;
  }

  // ----------------------------------------------------------------- lookup
  /* Never reject input. The most natural thing a reader types is a package
   * name; the second is a log index. Demanding 64 hex would be a
   * discoverability bug on the one control the whole page exists for. */
  function normalise(raw) {
    return String(raw || '').trim().toLowerCase()
      .replace(/^0x/, '').replace(/[\s:]/g, '');
  }

  function lookup(r, raw) {
    var q = normalise(raw);
    var hits = [];
    if (!q) return { query: raw, kind: 'empty', hits: hits };

    var isHex = /^[0-9a-f]+$/.test(q);

    if (isHex && q.length === 64) {
      collectHashHits(r, q, q, hits);
      return { query: raw, norm: q, kind: 'hash', hits: hits };
    }

    if (isHex && q.length >= 12 && q.length < 64) {
      var full = prefixMatches(r, q);
      if (full.length === 1) {
        collectHashHits(r, full[0], q, hits);
        return { query: raw, norm: full[0], kind: 'hash', prefix: q,
                 hits: hits };
      }
      return { query: raw, norm: q, kind: 'ambiguous', candidates: full };
    }

    if (/^\d+$/.test(q)) {
      var i = parseInt(q, 10);
      if (i < r.snapshot.tree_size) {
        var rec = JSON.parse(D.leaves[i]);
        hits.push({ kind: 'log-index', index: i, rec: rec,
                    leafHash: V.hex(r.leafHashes[i]) });
        return { query: raw, kind: 'index', hits: hits };
      }
    }

    // A path, or a package name. Both are substring searches over data the
    // page already holds.
    var needle = String(raw).trim().toLowerCase();
    var names = {}, paths = [];
    r.builds.forEach(function (b) {
      if (!b.pkgs) return;
      b.pkgs.forEach(function (row, idx) {
        if (row[0].toLowerCase().indexOf(needle) >= 0) {
          names[row[0]] = true;
        }
        if (needle.indexOf('/') >= 0) {
          (b.filesByName[row[0]] || []).forEach(function (f) {
            if (paths.length < 60 && f[0].toLowerCase().indexOf(needle) >= 0) {
              paths.push({ build: b.meta, pkg: row[0], path: f[0],
                           sha256: f[1] });
            }
          });
        }
      });
    });
    return { query: raw, kind: 'search',
             names: Object.keys(names).sort(), paths: paths };
  }

  function prefixMatches(r, prefix) {
    var seen = {};
    ['logLeaf', 'pkgLeaf', 'deviceRoot', 'sthRoot', 'file', 'pcr14',
     'artifact'].forEach(function (ns) {
      Object.keys(r.index[ns]).forEach(function (h) {
        if (h.indexOf(prefix) === 0) seen[h] = true;
      });
    });
    return Object.keys(seen).sort();
  }

  /* Report EVERY namespace a hash matches, never the first. The empty file's
   * digest is also the RFC 6962 empty-tree root, and a reader who is shown
   * only one of those has been told something misleading. */
  function collectHashHits(r, hex, typed, hits) {
    (r.index.logLeaf[hex] || []).forEach(function (h) {
      hits.push({ kind: 'log-leaf', index: h.index, rec: h.rec,
                  leafHash: hex });
    });
    (r.index.pkgLeaf[hex] || []).forEach(function (h) {
      if (h.rec) hits.push({ kind: 'pkg-leaf-published', rec: h.rec });
      else hits.push({ kind: 'pkg-leaf', build: h.build, row: h.row,
                       inLog: h.inLog, pkgLeafHash: hex });
    });
    (r.index.deviceRoot[hex] || []).forEach(function (b) {
      hits.push({ kind: 'device-root', build: b });
    });
    (r.index.sthRoot[hex] || []).forEach(function (h) {
      hits.push({ kind: 'sth-root', head: h });
    });
    (r.index.file[hex] || []).forEach(function (f) {
      hits.push({ kind: 'file', file: f });
    });
    (r.index.pcr14[hex] || []).forEach(function (b) {
      hits.push({ kind: 'pcr14', build: b });
    });
    (r.index.artifact[hex] || []).forEach(function (a) {
      hits.push({ kind: 'artifact', artifact: a });
    });
    return hits;
  }

  // ---------------------------------------------------------------- renders
  function renderBlocked(title, problems, prose) {
    clear(view);
    var box = el('div', 'blocked');
    box.appendChild(el('h2', null, title));
    if (prose) box.appendChild(el('p', 'prose', prose));
    var list = el('ul');
    problems.forEach(function (p) { list.appendChild(el('li', null, p)); });
    box.appendChild(list);
    view.appendChild(box);
  }

  function renderHome(r) {
    var snap = r.snapshot;
    clear(view);

    view.appendChild(el('p', 'eyebrow',
      'snapshot ' + snap.snapshot_id + '  \u00b7  ' +
      group(snap.tree_size) + ' published package records'));

    // The thesis, in the asserting voice -- because the sentence itself is a
    // claim; the receipt below is what makes it checkable.
    var thesis = el('p', 'thesis');
    thesis.appendChild(document.createTextNode(
      'Both images carry a valid signature. '));
    thesis.appendChild(el('span', 'turn', 'One package was never published.'));
    view.appendChild(thesis);

    // ---- the receipt ----
    view.appendChild(el('h2', null, 'What this browser just did'));
    var receipt = el('div', 'receipt');

    receipt.appendChild(receiptRow('read',
      'published package records, as canonical log-leaf-v1 bytes',
      group(snap.tree_size)));

    receipt.appendChild(receiptRow('hash',
      'each record into an RFC 6962 leaf, then folded the tree',
      group(snap.tree_size * 2 - 1) + ' sha256'));

    receipt.appendChild(receiptRow('fold',
      'leaves into a single root',
      r.ms + ' ms'));

    receipt.appendChild(receiptRow('root', digest(r.root, true),
      r.rootMatches ? 'matches the signed head' : 'DOES NOT MATCH',
      r.rootMatches ? 'is-ok' : 'is-absent'));

    receipt.appendChild(receiptRow('verify',
      'Ed25519 over "' + r.payload + '"',
      r.sigOk ? 'signature valid' : 'SIGNATURE INVALID',
      r.sigOk ? 'is-ok' : 'is-absent'));

    receipt.appendChild(el('p', 'receipt-note',
      'Nothing above was asked of a server. The records came down with this ' +
      'page; the arithmetic happened here.'));
    view.appendChild(receipt);

    // ---- builds ----
    view.appendChild(el('h2', null,
      'Builds of ' + (r.builds[0] ? r.builds[0].meta.image_line : 'this line')));

    r.builds.forEach(function (b) {
      var m = b.meta;
      var missing = b.unaccounted;
      var absent = missing && missing.length > 0;

      var row = el('div', 'build' + (absent ? ' is-absent' : ''));
      row.appendChild(el('div', 'build-label', m.label));

      var mid = el('div');
      mid.appendChild(el('div', null,
        group(m.package_count) + ' packages, ' + group(m.file_count) +
        ' measured files'));
      mid.appendChild(el('div', 'build-id', m.build_id));
      row.appendChild(mid);

      var verdict;
      if (missing === null) {
        verdict = el('div', 'build-verdict', 'detail not in this snapshot');
      } else if (absent) {
        verdict = el('div', 'build-verdict is-absent',
          missing.length + ' of ' + group(m.package_count) +
          ' unaccounted for');
      } else {
        verdict = el('div', 'build-verdict is-ok',
          'every package published');
      }
      row.appendChild(verdict);

      if (absent) {
        var named = el('div', 'named');
        missing.slice(0, 5).forEach(function (p) {
          named.appendChild(el('div', null, p.name + ' ' + p.version));
        });
        if (missing.length > 5) {
          named.appendChild(el('div', null,
            'and ' + (missing.length - 5) + ' more'));
        }
        named.appendChild(el('span', 'named-scope',
          'No log entry for this version under image line ' + m.image_line +
          ', at tree size ' + group(snap.tree_size) + '.'));
        row.appendChild(named);
      }
      view.appendChild(row);
    });

    // ---- the key ----
    view.appendChild(el('h2', null, 'The key this rests on'));
    var box = el('div', 'keybox');
    box.appendChild(el('p', 'prose',
      'Every signature above was checked against this key \u2014 which ' +
      'arrived in the same download as the signatures. That proves the ' +
      'bundle is internally consistent, not that the key is the log\'s. ' +
      'Compare it against a value you got somewhere else: the talk, the ' +
      'signed release tag, the README.'));
    box.appendChild(digest(snap.key_id.replace(/^sha256:/, ''), false));
    box.appendChild(el('p', 'prose dim', 'sha256 of the key\'s SPKI DER'));
    var cmd = el('pre', 'cmd',
      'pkgattest verify-sth --sth-file sth.json \\\n' +
      '                     --log-pub log_ed25519.pub');
    box.appendChild(cmd);
    view.appendChild(box);

    // ---- look anything up ----
    view.appendChild(el('h2', null, 'Check something yourself'));
    view.appendChild(el('p', 'prose dim',
      'Every record, measurement, device root and file digest in this ' +
      'snapshot is searchable. A hash may mean more than one thing; all of ' +
      'them are shown.'));
    view.appendChild(searchBox(''));

    var more = el('p', 'prose');
    var link = el('a', null, 'What this does not prove');
    link.href = '#/limits';
    more.appendChild(link);
    more.appendChild(document.createTextNode(
      ' \u2014 the four things this page cannot tell you. '));
    var slink = el('a', null, 'Statistics');
    slink.href = '#/stats';
    more.appendChild(slink);
    more.appendChild(document.createTextNode(
      ' \u2014 coverage, and where the weight actually is.'));
    view.appendChild(more);
  }

  function renderLimits(r) {
    clear(view);
    view.appendChild(el('p', 'eyebrow', 'what this does not prove'));
    view.appendChild(el('p', 'thesis', 'Four things this page cannot tell you.'));

    var limits = [
      ['The key is the log\'s key.',
       'The public key ships in the same bundle as the signatures it ' +
       'checks. A bundle re-signed under somebody else\'s key verifies ' +
       'against itself perfectly. Only a value you obtained elsewhere ' +
       'settles this, which is why the fingerprint is printed rather than ' +
       'quietly used.'],
      ['This tree head is current.',
       'The bundle is an archive of one signed head, not a live mirror, and ' +
       'an HTTPS page cannot reach a log server on someone\'s laptop. ' +
       'Everything here is true as of the head named at the top and says ' +
       'nothing about what the log looks like now. "Never published" always ' +
       'means "not present at this tree size".'],
      ['This image was published.',
       'A log entry commits to a package \u2014 its name, version, ' +
       'architecture, image line and the digest of its file list \u2014 and ' +
       'never to an image. So "every package is published" is exactly that. ' +
       'An image assembled entirely from packages that were published ' +
       'before, including a downgrade to an older signed version, would ' +
       'satisfy it.'],
      ['The images are correctly signed.',
       'The RSA-4096 signature over the 71 MB update payload is not checked ' +
       'here; hashing that in a browser tab is not a reasonable thing to do ' +
       'to a reader. Run pkgattest verify-image against the payload ' +
       'instead.']
    ];

    limits.forEach(function (pair) {
      var box = el('div', 'limit');
      box.appendChild(el('h3', null, pair[0]));
      box.appendChild(el('p', 'prose', pair[1]));
      view.appendChild(box);
    });

    view.appendChild(el('h2', null, 'What it does prove'));
    view.appendChild(el('p', 'prose',
      'That the records in this bundle fold into exactly the root the tree ' +
      'head is signed over, that the signature over that head is valid ' +
      'under the key shown, and that each build\'s device root follows ' +
      'from its own package measurements. Your browser did all of it; the ' +
      'receipt on the front page reports the real timings.'));

    var back = el('p', 'prose');
    var link = el('a', null, 'Back to the verification');
    link.href = '#/';
    back.appendChild(link);
    view.appendChild(back);
  }

  // --------------------------------------------------------- proof rendering
  /* The fold-up ladder. Each row is one level: the value carried up, the
   * sibling it joins, and which side it joins on -- printed per row rather
   * than as one formula, because RFC 6962 alternates and the fn === sn case
   * fires on a tree this size.
   *
   * Intermediates are shown abbreviated; they are working values. The final
   * root is shown whole, because that is the value being checked. */
  function ladder(leafHash, index, size, proof, rootHex) {
    var box = el('div', 'ladder');
    var steps = V.inclusionSteps(index, size, proof);
    var cur = leafHash;

    var head = el('div', 'ladder-row is-head');
    head.appendChild(el('div', 'ladder-level', 'leaf'));
    head.appendChild(el('div', 'ladder-value', abbrev(V.hex(cur))));
    head.appendChild(el('div', 'ladder-op', 'index ' + group(index)));
    box.appendChild(head);

    steps.forEach(function (s, i) {
      cur = (s.side === 'left') ? V.nodeHash(s.sibling, cur)
                                : V.nodeHash(cur, s.sibling);
      var row = el('div', 'ladder-row');
      row.appendChild(el('div', 'ladder-level', 'L' + (i + 1)));
      row.appendChild(el('div', 'ladder-value', abbrev(V.hex(cur))));
      row.appendChild(el('div', 'ladder-op',
        (s.side === 'left' ? 'sibling on the left  ' : 'sibling on the right ')
        + abbrev(V.hex(s.sibling))));
      box.appendChild(row);
    });

    var ok = V.hex(cur) === rootHex;
    var foot = el('div', 'ladder-foot' + (ok ? ' is-ok' : ' is-absent'));
    foot.appendChild(el('div', 'ladder-level', 'root'));
    var val = el('div');
    val.appendChild(digest(V.hex(cur), true));
    val.appendChild(el('div', 'ladder-verdict',
      ok ? 'this is the root the tree head is signed over'
         : 'this is NOT the signed root'));
    foot.appendChild(val);
    box.appendChild(foot);
    return { node: box, ok: ok, steps: steps.length };
  }

  function abbrev(hex) {
    return hex.slice(0, 8) + ' ' + hex.slice(8, 16) + '...';
  }

  // ------------------------------------------------------------ package view
  function findPackage(r, name, wantBuild) {
    var found = null;
    r.builds.forEach(function (b) {
      if (!b.pkgs || found) return;
      if (wantBuild && b.meta.label !== wantBuild) return;
      b.pkgs.forEach(function (row, idx) {
        if (!found && row[0] === name) {
          found = { build: b, row: row, idx: idx,
                    pkgLeafHash: b.leafHexes[idx] };
        }
      });
    });
    return found;
  }

  function renderPkg(r, name, wantBuild) {
    var snap = r.snapshot;
    var p = findPackage(r, name, wantBuild);
    clear(view);
    if (!p) {
      view.appendChild(el('p', 'eyebrow', 'package'));
      view.appendChild(el('p', 'thesis', 'No package by that name.'));
      view.appendChild(el('p', 'prose', 'Nothing called "' + name +
        '" appears in any build in this snapshot.'));
      view.appendChild(backLink());
      return;
    }

    var b = p.build, row = p.row;
    var files = (b.filesByName[name] || []).map(function (f) {
      return { path: f[0], sha256: f[1] };
    });
    var pkg = { name: row[0], version: row[1], arch: row[2], files: files };

    var preimage = V.pkgLeafPreimage(pkg);
    var leafHex = V.hex(V.sha256(preimage));
    var record = V.logLeafData({
      arch: row[2], image_line: b.meta.image_line, name: row[0],
      version: row[1], pkg_leaf_hash: leafHex
    });
    var recordHex = V.hex(V.leafHash(record));
    var logIndex = r.byLeafHash[recordHex];
    var inLog = logIndex !== undefined;

    view.appendChild(el('p', 'eyebrow',
      'package \u00b7 build ' + b.meta.label + ' \u00b7 ' + b.meta.image_line));
    var title = el('p', 'thesis');
    title.appendChild(document.createTextNode(row[0] + ' ' + row[1]));
    view.appendChild(title);

    var verdict = el('p', inLog ? 'verdict is-ok' : 'verdict is-absent');
    verdict.textContent = inLog
      ? 'Published \u2014 leaf ' + group(logIndex) + ' of ' +
        group(snap.tree_size)
      : 'Not present at tree size ' + group(snap.tree_size);
    view.appendChild(verdict);

    // --- 1. the preimage ---
    view.appendChild(el('h2', null, 'One \u2014 what was measured'));
    view.appendChild(el('p', 'prose dim',
      'The pkg-leaf-v1 preimage: this package\'s identity and the digest of ' +
      'every file it installs. ' + group(preimage.length) + ' bytes.'));
    var pre = el('pre', 'bytes');
    var text = new TextDecoder().decode(preimage);
    var lines = text.split('\n');
    pre.textContent = lines.length > 14
      ? lines.slice(0, 8).join('\n') + '\n  ... ' +
        group(lines.length - 12) + ' more file lines ...\n' +
        lines.slice(-4).join('\n')
      : text;
    view.appendChild(pre);
    var d1 = el('div', 'proofline');
    d1.appendChild(el('span', 'proofline-op', 'sha256(preimage)'));
    d1.appendChild(digest(leafHex, true));
    view.appendChild(d1);

    // --- 2. the log record ---
    view.appendChild(el('h2', null, 'Two \u2014 the record the log commits to'));
    view.appendChild(el('p', 'prose dim',
      'log-leaf-v1: canonical JSON, exactly these bytes. It carries the ' +
      'digest above, not the file list itself.'));
    var rec = el('pre', 'bytes');
    rec.textContent = new TextDecoder().decode(record);
    view.appendChild(rec);
    var d2 = el('div', 'proofline');
    d2.appendChild(el('span', 'proofline-op', 'sha256(0x00 || record)'));
    d2.appendChild(digest(recordHex, true));
    view.appendChild(d2);

    // --- 3. inclusion, or its absence ---
    if (inLog) {
      var proof = V.inclusionProof(r.leafHashes, logIndex, snap.tree_size);
      var lad = ladder(r.leafHashes[logIndex], logIndex, snap.tree_size,
                       proof, snap.root_hash);
      view.appendChild(el('h2', null,
        'Three \u2014 folding that record up to the root'));
      view.appendChild(el('p', 'prose dim',
        lad.steps + ' sibling hashes, derived here from the records this ' +
        'page holds. The server was not asked for a proof.'));
      view.appendChild(lad.node);

      view.appendChild(el('h2', null, 'Four \u2014 the signature'));
      var d4 = el('div', 'proofline');
      d4.appendChild(el('span', 'proofline-op', 'Ed25519'));
      d4.appendChild(el('span', r.sigOk ? 'is-ok' : 'is-absent',
        r.sigOk ? 'valid over the tree head above' : 'INVALID'));
      view.appendChild(d4);
    } else {
      view.appendChild(el('h2', null, 'Three \u2014 no such record'));
      var absent = el('div', 'named');
      absent.appendChild(el('div', null,
        'No leaf in this log matches that record.'));
      absent.appendChild(el('span', 'named-scope',
        'Checked against all ' + group(snap.tree_size) + ' records the ' +
        'signed head covers, for image line ' + b.meta.image_line + '. ' +
        'That is a statement about this tree size, not about all time.'));
      view.appendChild(absent);

      var others = (r.index.pkgLeaf[leafHex] || []).length;
      var published = [];
      r.builds.forEach(function (ob) {
        if (!ob.pkgs) return;
        ob.pkgs.forEach(function (orow, oi) {
          if (orow[0] === name && ob.meta.label !== b.meta.label) {
            var od = V.logLeafData({
              arch: orow[2], image_line: ob.meta.image_line, name: orow[0],
              version: orow[1], pkg_leaf_hash: ob.leafHexes[oi]
            });
            if (V.hex(V.leafHash(od)) in r.byLeafHash) {
              published.push(ob.meta.label + ': ' + orow[1]);
            }
          }
        });
      });
      if (published.length) {
        view.appendChild(el('p', 'prose',
          'What is published for ' + name + ' on this image line: ' +
          published.join(', ') + '.'));
      }
      void others;
    }

    view.appendChild(el('h2', null, 'Files measured'));
    view.appendChild(el('p', 'prose dim', group(files.length) +
      ' regular files. Every digest below is inside the preimage above.'));
    var table = el('div', 'filelist');
    files.slice(0, 40).forEach(function (f) {
      var frow = el('div', 'filerow');
      frow.appendChild(el('div', 'filepath', f.path));
      frow.appendChild(el('div', 'filehash', f.sha256.slice(0, 16) + '...'));
      table.appendChild(frow);
    });
    if (files.length > 40) {
      table.appendChild(el('div', 'filerow',
        'and ' + group(files.length - 40) + ' more'));
    }
    view.appendChild(table);
    view.appendChild(backLink());
  }

  // --------------------------------------------------------------- hash view
  function renderHash(r, raw) {
    var res = lookup(r, raw);
    clear(view);
    view.appendChild(el('p', 'eyebrow', 'lookup'));

    if (res.kind === 'empty') {
      view.appendChild(el('p', 'thesis', 'Nothing to look up.'));
      view.appendChild(searchBox(raw));
      return;
    }

    if (res.kind === 'ambiguous') {
      view.appendChild(el('p', 'thesis', 'That prefix matches ' +
        res.candidates.length + ' hashes.'));
      var list = el('div', 'filelist');
      res.candidates.slice(0, 30).forEach(function (h) {
        var a = el('a', 'filerow', h);
        a.href = '#/hash/' + h;
        list.appendChild(a);
      });
      view.appendChild(list);
      view.appendChild(searchBox(raw));
      return;
    }

    if (res.kind === 'search') {
      view.appendChild(el('p', 'thesis',
        res.names.length || res.paths.length
          ? 'Found ' + (res.names.length + res.paths.length) + '.'
          : 'No package or path matches that.'));
      if (res.names.length) {
        view.appendChild(el('h2', null, 'Packages'));
        var pl = el('div', 'filelist');
        res.names.slice(0, 60).forEach(function (n) {
          var a = el('a', 'filerow', n);
          a.href = '#/pkg/' + encodeURIComponent(n);
          pl.appendChild(a);
        });
        view.appendChild(pl);
      }
      if (res.paths.length) {
        view.appendChild(el('h2', null, 'Files'));
        var fl = el('div', 'filelist');
        res.paths.forEach(function (f) {
          var frow = el('div', 'filerow');
          var a = el('a', 'filepath', f.path);
          a.href = '#/hash/' + f.sha256;
          frow.appendChild(a);
          frow.appendChild(el('div', 'filehash', f.pkg));
          fl.appendChild(frow);
        });
        view.appendChild(fl);
      }
      view.appendChild(searchBox(raw));
      return;
    }

    // A hash, or a log index.
    if (!res.hits.length) {
      view.appendChild(el('p', 'thesis unknown', 'Unknown value.'));
      view.appendChild(el('div', 'digest', ''));
      view.appendChild(digest(res.norm.length === 64 ? res.norm : res.norm,
                              false));
      view.appendChild(el('p', 'prose',
        'This is not a log record, a package measurement, a device root, a ' +
        'tree head, a measured file, a PCR value or an artifact digest in ' +
        'this snapshot. That is different from a package whose version was ' +
        'never published \u2014 this value is simply not here at all.'));
      view.appendChild(el('p', 'prose dim',
        'Internal tree nodes are not indexed: a node hash only means ' +
        'anything at one tree size, so it is shown inside a proof ladder ' +
        'rather than looked up on its own.'));
      view.appendChild(searchBox(raw));
      return;
    }

    view.appendChild(el('p', 'thesis',
      res.hits.length === 1 ? 'One match.'
                            : res.hits.length + ' matches, all shown.'));
    if (res.hits.length > 1) {
      view.appendChild(el('p', 'prose dim',
        'A digest can mean more than one thing. Every namespace it appears ' +
        'in is listed, never just the first.'));
    }
    res.hits.forEach(function (h) { view.appendChild(hitCard(r, h)); });
    view.appendChild(searchBox(raw));
  }

  function hitCard(r, h) {
    var card = el('div', 'hit');
    var kind = el('div', 'hit-kind');
    var body = el('div', 'hit-body');

    if (h.kind === 'log-leaf' || h.kind === 'log-index') {
      kind.textContent = 'log record';
      body.appendChild(el('div', null,
        h.rec.name + ' ' + h.rec.version + '  (' + h.rec.arch + ')'));
      body.appendChild(el('div', 'hit-note',
        'leaf ' + group(h.index) + ' of ' + group(r.snapshot.tree_size) +
        ', image line ' + h.rec.image_line));
      var a = el('a', 'hit-link', 'open the package and fold the proof');
      a.href = '#/pkg/' + encodeURIComponent(h.rec.name);
      body.appendChild(a);
    } else if (h.kind === 'pkg-leaf-published') {
      kind.textContent = 'package measurement';
      body.appendChild(el('div', null,
        h.rec.name + ' ' + h.rec.version + ' \u2014 committed to by a log ' +
        'record'));
    } else if (h.kind === 'pkg-leaf') {
      kind.textContent = 'package measurement';
      body.appendChild(el('div', null,
        h.row[0] + ' ' + h.row[1] + '  in build ' + h.build.label));
      body.appendChild(el('div', 'hit-note', h.inLog
        ? 'this measurement has a log record'
        : 'no log record for this measurement at this tree size'));
      var pa = el('a', 'hit-link', 'open the package');
      pa.href = '#/pkg/' + encodeURIComponent(h.row[0]);
      body.appendChild(pa);
    } else if (h.kind === 'device-root') {
      kind.textContent = 'device root';
      body.appendChild(el('div', null, 'build ' + h.build.label + ' \u2014 ' +
        h.build.build_id));
      body.appendChild(el('div', 'hit-note',
        'the pkg-merkle-v1 root over all ' + group(h.build.package_count) +
        ' package measurements; this is what a BMC extends into PCR 14'));
    } else if (h.kind === 'sth-root') {
      kind.textContent = 'signed tree head';
      body.appendChild(el('div', null, h.head.genesis
        ? 'the empty tree (size 0)'
        : 'tree size ' + group(h.head.tree_size)));
      if (h.head.genesis) {
        body.appendChild(el('div', 'hit-note',
          'sha256 of nothing at all \u2014 RFC 6962 defines the empty tree ' +
          'this way, which is why an empty file has the same digest'));
      }
    } else if (h.kind === 'file') {
      kind.textContent = 'measured file';
      body.appendChild(el('div', 'filepath', h.file.path));
      body.appendChild(el('div', 'hit-note',
        'installed by ' + h.file.pkg + ' in build ' + h.file.build.label));
      var fa = el('a', 'hit-link', 'open ' + h.file.pkg);
      fa.href = '#/pkg/' + encodeURIComponent(h.file.pkg);
      body.appendChild(fa);
    } else if (h.kind === 'pcr14') {
      kind.textContent = 'expected PCR 14';
      body.appendChild(el('div', null, 'build ' + h.build.label));
      body.appendChild(el('div', 'hit-note',
        'sha256(0^32 || device root) \u2014 what a TPM would hold after one ' +
        'extend. No quote is in this bundle, so this is the value to expect, ' +
        'not one that was measured.'));
    } else if (h.kind === 'artifact') {
      kind.textContent = 'artifact';
      body.appendChild(el('div', null, h.artifact.name));
      body.appendChild(el('div', 'hit-note',
        'build ' + h.artifact.build.label + ', ' +
        group(h.artifact.meta.size) + ' bytes'));
    }

    card.appendChild(kind);
    card.appendChild(body);
    return card;
  }

  // -------------------------------------------------------------- stats view
  function renderStats(r) {
    var snap = r.snapshot;
    clear(view);
    view.appendChild(el('p', 'eyebrow', 'statistics'));
    view.appendChild(el('p', 'thesis', 'What is in the log, and what is not.'));

    var b0 = r.builds[0];
    var pkgs = b0 && b0.pkgs ? b0.pkgs : [];
    var arch = {}, zero = 0, kernel = 0, kernelFiles = 0, totalFiles = 0;
    pkgs.forEach(function (row) {
      arch[row[2]] = (arch[row[2]] || 0) + 1;
      var n = row[4];
      totalFiles += n;
      if (n === 0) zero++;
      if (row[0].indexOf('kernel-') === 0) { kernel++; kernelFiles += n; }
    });

    function stat(label, value, note) {
      var s = el('div', 'stat');
      s.appendChild(el('div', 'stat-value', value));
      s.appendChild(el('div', 'stat-label', label));
      if (note) s.appendChild(el('p', 'prose dim', note));
      return s;
    }

    view.appendChild(el('h2', null, 'Publication coverage'));
    var cov = el('div', 'stats');
    r.builds.forEach(function (b) {
      var missing = b.unaccounted ? b.unaccounted.length : 0;
      cov.appendChild(stat('build ' + b.meta.label,
        group(b.meta.package_count - missing) + ' / ' +
        group(b.meta.package_count),
        missing ? 'packages with a log record; ' + missing + ' without'
                : 'every package has a log record'));
    });
    view.appendChild(cov);

    view.appendChild(el('h2', null, 'Where the weight actually is'));
    view.appendChild(el('p', 'prose',
      'Kernel modules are ' + pct(kernel, pkgs.length) + ' of the packages ' +
      'but only ' + pct(kernelFiles, totalFiles) + ' of the measured files. ' +
      'Counting packages is not the same as measuring attack surface.'));
    var w = el('div', 'stats');
    w.appendChild(stat('kernel-* packages',
      group(kernel) + ' / ' + group(pkgs.length)));
    w.appendChild(stat('their share of files',
      group(kernelFiles) + ' / ' + group(totalFiles)));
    view.appendChild(w);

    view.appendChild(el('h2', null, 'Packages that constrain nothing'));
    view.appendChild(el('p', 'prose',
      group(zero) + ' packages measure zero files. They are metapackages \u2014 ' +
      'packagegroups and kernel-module aggregates \u2014 so each contributes a ' +
      'leaf to the tree while committing to no bytes at all. Worth saying ' +
      'plainly rather than letting the package count imply more coverage ' +
      'than it has.'));

    view.appendChild(el('h2', null, 'The log itself'));
    var l = el('div', 'stats');
    l.appendChild(stat('records', group(snap.tree_size)));
    l.appendChild(stat('signed tree heads',
      group((D.sth_history || []).length)));
    l.appendChild(stat('architectures', String(Object.keys(arch).length),
      Object.keys(arch).sort().map(function (a) {
        return a + ' ' + group(arch[a]);
      }).join(', ')));
    view.appendChild(l);

    view.appendChild(el('p', 'prose dim',
      'Not shown: what fraction of the root filesystem is measured. The ' +
      'denominator is not in this data, and inventing it would be the one ' +
      'number on this page nobody could check.'));
    view.appendChild(backLink());
  }

  function pct(a, b) {
    return b ? (Math.round(a / b * 1000) / 10) + '%' : '0%';
  }

  // -------------------------------------------------------------- search box
  function searchBox(value) {
    var form = el('div', 'search');
    var label = el('label', 'search-label',
      'Paste a hash, a log index, a package name or a file path');
    label.setAttribute('for', 'q');
    var input = el('input', 'search-input');
    input.id = 'q';
    input.setAttribute('type', 'text');
    input.setAttribute('spellcheck', 'false');
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('placeholder', 'dropbear');
    if (value) input.value = value;
    var go = el('button', 'search-go', 'Look it up');

    function submit() {
      var v = input.value;
      if (v && v.trim()) location.hash = '#/hash/' + encodeURIComponent(v.trim());
    }
    go.addEventListener('click', submit);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') submit();
    });

    form.appendChild(label);
    var line = el('div', 'search-line');
    line.appendChild(input);
    line.appendChild(go);
    form.appendChild(line);
    return form;
  }

  function backLink() {
    var p = el('p', 'prose');
    var a = el('a', null, 'Back to the verification');
    a.href = '#/';
    p.appendChild(a);
    return p;
  }

  // ----------------------------------------------------------------- router
  var verified = null;

  function route() {
    if (!verified) return;
    var hash = String(location.hash || '');
    var m;
    try {
      if (hash === '#/limits') renderLimits(verified);
      else if (hash === '#/stats') renderStats(verified);
      else if ((m = hash.match(/^#\/hash\/(.*)$/))) {
        renderHash(verified, decodeURIComponent(m[1]));
      } else if ((m = hash.match(/^#\/pkg\/([^?]*)(?:\?build=([A-Za-z0-9._-]+))?$/))) {
        renderPkg(verified, decodeURIComponent(m[1]), m[2] || null);
      } else {
        renderHome(verified);
      }
    } catch (e) {
      // location.hash is attacker-controlled and survives being shared, so a
      // malformed one must land on a page, not on a broken render.
      renderBlocked('That link could not be read',
                    [e && e.message ? e.message : String(e)]);
    }
    window.scrollTo(0, 0);
  }

  function boot() {
    // Rule 1. Before anything is rendered as fact.
    var broken = V ? V.selfTest() : ['the verifier did not load'];
    if (broken.length) {
      renderBlocked('Verification is not possible in this browser', broken,
        'These are known-answer checks of the arithmetic this page relies ' +
        'on. One of them failed, so nothing here can be trusted and nothing ' +
        'will be shown. This is a bug in the page, not a finding about the ' +
        'log.');
      return;
    }

    if (!D.snapshot) {
      renderBlocked('No snapshot in this bundle',
        ['data/snapshot.js is missing or empty'],
        'This page is generated by `make site`, which writes the log data ' +
        'alongside it. Opening site/index.html straight from the source ' +
        'tree will land here, because the data only exists in site-dist/.');
      return;
    }

    // Leaves are the bulk of the download, so they load only when something
    // is actually going to be verified -- which is immediately, here.
    var needed = ['data/leaves.js'];
    (D.builds || []).forEach(function (b) {
      var short = b.device_root.slice(0, 16);
      needed.push('data/pkgs-' + short + '.js');
      needed.push('data/files-' + short + '.js');
    });

    var pending = needed.length;
    var failures = [];
    needed.forEach(function (src) {
      loadScript(src, function (err) {
        if (err) failures.push(err.message);
        if (--pending > 0) return;
        if (!D.leaves) {
          renderBlocked('The log records did not load', failures.length
            ? failures : ['data/leaves.js did not define any records']);
          return;
        }
        try {
          verified = verifyEverything();
        } catch (e) {
          renderBlocked('Verification stopped on an error',
            [e && e.message ? e.message : String(e)],
            'The page reached data it could not verify and stopped rather ' +
            'than showing a partial result.');
          return;
        }
        if (verified.problems.length) {
          renderBlocked('This bundle does not verify', verified.problems,
            'The records shipped with this page do not agree with the ' +
            'signed tree head. Do not trust anything it says.');
          return;
        }
        route();
      });
    });
  }

  window.addEventListener('hashchange', route);
  boot();
})();
