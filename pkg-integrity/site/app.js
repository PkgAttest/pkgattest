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
    out.assessments = (D.assessments || []).map(function (a) {
      return analyseAssessment(a, out.builds);
    });
    return out;
  }

  /* Compare an assessment's stated scope against what each build actually
   * contains.
   *
   * Three buckets, not two, and the middle one is the whole point:
   *
   *   examined    this exact measurement was in the assessed image -- the
   *               artefact reviewed and the artefact running are the same
   *               bytes.
   *   rebuilt     the package NAME was in the review, but this build of it
   *               is not the one that was reviewed. The review looked at
   *               this area and its conclusions do not carry over to these
   *               bytes.
   *   outside     the package was never in the review's scope at all.
   *
   * Joining on the leaf hash rather than on name+version is what makes the
   * middle bucket possible. Two builds of "dropbear 2026.92" with different
   * patches produce different leaves; only the leaf says whether the thing
   * reviewed is the thing present. */
  function analyseAssessment(a, builds) {
    var byLeaf = {}, byName = {};
    (a.examined || []).forEach(function (e) {
      byLeaf[e.pkg_leaf_hash] = e;
      byName[e.name] = e;
    });

    var perBuild = builds.map(function (b) {
      var r = { build: b.meta, examined: [], rebuilt: [], outsideCount: 0,
                isSubject: b.meta.device_root === a.subject.device_root };
      if (!b.pkgs) return r;
      b.pkgs.forEach(function (row, i) {
        var leaf = b.leafHexes[i];
        if (byLeaf[leaf]) r.examined.push({ name: row[0], version: row[1] });
        else if (byName[row[0]]) {
          r.rebuilt.push({ name: row[0], version: row[1],
                           reviewedVersion: byName[row[0]].version });
        } else r.outsideCount++;
      });
      return r;
    });

    return { doc: a, byLeaf: byLeaf, byName: byName, builds: perBuild };
  }

  /* Where one package sits relative to every assessment in the bundle. */
  function assessmentStanding(r, name, leafHex) {
    return r.assessments.map(function (an) {
      if (an.byLeaf[leafHex]) return { a: an.doc, state: 'examined' };
      if (an.byName[name]) {
        return { a: an.doc, state: 'rebuilt',
                 reviewedVersion: an.byName[name].version };
      }
      return { a: an.doc, state: 'outside' };
    });
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
      ' \u2014 coverage, and where the weight actually is. '));
    var alink = el('a', null, 'Security assessment');
    alink.href = '#/assessment';
    more.appendChild(alink);
    more.appendChild(document.createTextNode(
      ' \u2014 what an audit can and cannot say about what you are running.'));
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

  // ------------------------------------------------------------------- tabs
  /* Two views of one proof. The ladder is the arithmetic, step by step; the
   * tree is the shape that makes twelve hashes enough for 2,132 records.
   * Same data, same order, same source -- neither is a summary of the other. */
  var tabSeq = 0;

  function tabbed(panels) {
    var wrap = el('div', 'tabs');
    var bar = el('div', 'tablist');
    bar.setAttribute('role', 'tablist');
    var id = 'tabs' + (++tabSeq);
    var buttons = [], bodies = [];

    panels.forEach(function (p, i) {
      var btn = el('button', 'tab', p.label);
      btn.setAttribute('role', 'tab');
      btn.setAttribute('id', id + '-t' + i);
      btn.setAttribute('aria-controls', id + '-p' + i);
      var body = el('div', 'tabpanel');
      body.setAttribute('role', 'tabpanel');
      body.setAttribute('id', id + '-p' + i);
      body.setAttribute('aria-labelledby', id + '-t' + i);
      body.appendChild(p.build());
      buttons.push(btn);
      bodies.push(body);
      bar.appendChild(btn);
    });

    function select(n) {
      buttons.forEach(function (b, i) {
        b.setAttribute('aria-selected', i === n ? 'true' : 'false');
        b.setAttribute('tabindex', i === n ? '0' : '-1');
        b.className = 'tab' + (i === n ? ' is-current' : '');
        if (i === n) bodies[i].removeAttribute('hidden');
        else bodies[i].setAttribute('hidden', '');
      });
    }

    buttons.forEach(function (b, i) {
      b.addEventListener('click', function () { select(i); });
      b.addEventListener('keydown', function (e) {
        var d = e.key === 'ArrowRight' ? 1 : (e.key === 'ArrowLeft' ? -1 : 0);
        if (!d) return;
        var n = (i + d + buttons.length) % buttons.length;
        select(n);
        buttons[n].focus && buttons[n].focus();
      });
    });

    wrap.appendChild(bar);
    bodies.forEach(function (b) { wrap.appendChild(b); });
    select(0);
    return wrap;
  }

  // ----------------------------------------------------------- tree drawing
  var SVGNS = 'http://www.w3.org/2000/svg';

  function svg(tag, attrs, cls) {
    var node = document.createElementNS(SVGNS, tag);
    if (cls) node.setAttribute('class', cls);
    for (var k in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, k)) {
        node.setAttribute(k, String(attrs[k]));
      }
    }
    return node;
  }

  function svgText(x, y, text, cls, anchor) {
    var t = svg('text', { x: x, y: y, 'text-anchor': anchor || 'middle' }, cls);
    t.textContent = text;
    return t;
  }

  /* The audit path drawn as the tree it actually is.
   *
   * Only the spine and its siblings are drawn -- 13 nodes, never 2,132. Each
   * sibling is one hash standing in for a whole subtree, so it is drawn as a
   * triangle whose width grows with the number of leaves underneath it and
   * labelled with that count. Those counts are the point: they sum to every
   * record in the log except this one, which is why twelve hashes suffice.
   *
   * The widths come from V.inclusionSpans, computed by the same recursion
   * that produced the proof, so the picture cannot drift from the arithmetic
   * on the other tab. */
  function treeDiagram(index, size, proof, rootHex, ok) {
    var spans = V.inclusionSpans(index, size);
    var L = proof.length;
    var rowH = 44, top = 54, cx = 380, W = 760;
    var H = top + L * rowH + 76;

    var root = svg('svg', {
      viewBox: '0 0 ' + W + ' ' + H,
      width: '100%', role: 'img',
      'aria-label': 'The audit path from leaf ' + index + ' to the root: ' +
                    L + ' sibling subtrees.'
    }, 'tree');

    function y(r) { return top + r * rowH; }

    // The spine: leaf at the bottom, root at the top.
    root.appendChild(svg('line',
      { x1: cx, y1: y(0), x2: cx, y2: y(L) }, 'tree-spine'));

    for (var r = 0; r < L; r++) {
      var j = L - 1 - r;                 // proof[j] joins to make row r
      var sp = spans[j];
      var leaves = sp.hi - sp.lo;
      var w = 26 + 7 * (Math.log(leaves) / Math.LN2);
      var dx = 78 + w / 2;
      var tx = sp.side === 'left' ? cx - dx : cx + dx;
      var ty = y(r + 1);
      var th = 24;

      // parent -> sibling subtree
      root.appendChild(svg('line',
        { x1: cx, y1: y(r), x2: tx, y2: ty }, 'tree-edge'));
      root.appendChild(svg('polygon', {
        points: [tx, ty, tx - w / 2, ty + th, tx + w / 2, ty + th].join(' ')
      }, 'tree-subtree'));
      root.appendChild(svgText(tx, ty + th + 15, group(leaves) +
        (leaves === 1 ? ' record' : ' records'), 'tree-count'));
      root.appendChild(svgText(
        sp.side === 'left' ? cx - 30 : cx + 30, y(r) + 17,
        'L' + (j + 1), 'tree-level',
        sp.side === 'left' ? 'end' : 'start'));
    }

    // Nodes on the spine, drawn last so they sit above the edges.
    for (var k = 0; k <= L; k++) {
      var isRoot = (k === 0), isLeaf = (k === L);
      root.appendChild(svg('circle', {
        cx: cx, cy: y(k), r: isRoot ? 9 : (isLeaf ? 8 : 5)
      }, 'tree-node' + (isRoot ? ' is-root' + (ok ? ' is-ok' : ' is-absent')
                               : (isLeaf ? ' is-leaf' : ''))));
    }

    root.appendChild(svgText(cx, y(0) - 20,
      'root  ' + rootHex.slice(0, 8) + ' ' + rootHex.slice(8, 16) + '...',
      'tree-label'));
    root.appendChild(svgText(cx, y(L) + 30,
      'this record  \u00b7  leaf ' + group(index), 'tree-label'));

    var box = el('div', 'treebox');
    box.appendChild(root);
    var total = spans.reduce(function (a, s) { return a + (s.hi - s.lo); }, 0);
    var sizes = spans.map(function (s) { return s.hi - s.lo; });
    var odd = sizes.filter(function (n) { return (n & (n - 1)) !== 0; });
    var caption = L + ' triangles, ' + group(total) + ' records between them' +
      ' \u2014 every record in the log except this one. Each is a single ' +
      'hash standing for a whole subtree, which is why a proof this short ' +
      'covers a log this size.';
    if (odd.length) {
      caption += ' The sizes double all the way up except one: ' +
        group(odd[0]) + ' records, because ' + group(size) + ' is not a ' +
        'power of two and the last subtree is short.';
    }
    box.appendChild(el('p', 'prose dim', caption));
    return box;
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

    var isUnowned = row[0] === UNOWNED_NAME;
    view.appendChild(el('p', 'eyebrow',
      (isUnowned ? 'files no package owns' : 'package') +
      ' \u00b7 build ' + b.meta.label + ' \u00b7 ' + b.meta.image_line));
    var title = el('p', 'thesis');
    title.appendChild(document.createTextNode(row[0] + ' ' + row[1]));
    view.appendChild(title);

    var verdict = el('p', inLog ? 'verdict is-ok' : 'verdict is-absent');
    verdict.textContent = inLog
      ? 'Published \u2014 leaf ' + group(logIndex) + ' of ' +
        group(snap.tree_size)
      : 'Not present at tree size ' + group(snap.tree_size);
    view.appendChild(verdict);

    if (isUnowned) {
      view.appendChild(el('p', 'prose',
        'Not a package. This leaf covers every regular file in the image ' +
        'that no package claims \u2014 /etc/passwd, /etc/shadow, ' +
        '/etc/ld.so.cache, the indexes depmod writes \u2014 so that nothing ' +
        'in the rootfs sits outside the device root, and therefore outside ' +
        'PCR 14. It is an ordinary pkg-leaf-v1 with a name no opkg package ' +
        'can have, which is why it needed no new format anywhere.'));
    }

    // --- 1. the preimage ---
    view.appendChild(el('h2', null, 'One \u2014 what was measured'));
    view.appendChild(el('p', 'prose dim',
      'The pkg-leaf-v1 preimage: ' + (isUnowned
        ? 'the identity of this leaf and the digest of every file it covers. '
        : 'this package\'s identity and the digest of every file it ' +
          'installs. ') + group(preimage.length) + ' bytes.'));
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
      view.appendChild(tabbed([
        { label: 'Each step', build: function () { return lad.node; } },
        { label: 'The shape', build: function () {
            return treeDiagram(logIndex, snap.tree_size, proof,
                               snap.root_hash, lad.ok);
          } }
      ]));

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

    // Where this exact measurement sits relative to any assessment.
    var standing = assessmentStanding(r, row[0], leafHex);
    if (standing.length) {
      view.appendChild(el('h2', null, 'Security assessment'));
      standing.forEach(function (st) {
        var box = el('div', st.state === 'rebuilt' ? 'named' : 'keybox');
        if (st.state === 'examined') {
          box.appendChild(el('p', 'prose',
            'This exact measurement is named as examined by ' +
            st.a.issuer.name + '. The artefact reviewed and the artefact ' +
            'here are the same bytes.'));
        } else if (st.state === 'rebuilt') {
          box.appendChild(el('div', null,
            'Inside the reviewed area, but not the reviewed build.'));
          box.appendChild(el('span', 'named-scope',
            st.a.issuer.name + ' examined ' + row[0] + ' ' +
            st.reviewedVersion + '. This is ' + row[1] + ', a different ' +
            'measurement, so the review\'s conclusions do not carry over ' +
            'to these bytes.'));
        } else {
          box.appendChild(el('p', 'prose dim',
            'Not in the scope named by ' + st.a.issuer.name + '.'));
        }
        if (st.a.illustrative) {
          box.appendChild(el('p', 'prose dim', st.a.disclaimer));
        }
        view.appendChild(box);
      });
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

  // --------------------------------------------------------- assessment view
  function renderAssessment(r) {
    clear(view);
    view.appendChild(el('p', 'eyebrow', 'security assessment'));
    view.appendChild(el('p', 'thesis',
      'An assessment names one hash. A device runs 2,131 packages.'));

    view.appendChild(el('p', 'prose',
      'An OCP S.A.F.E. Short-Form Report identifies what a Security Review ' +
      'Provider looked at by a single firmware hash \u2014 ' +
      'device.fw_hash_sha2_384. For a monolithic root-of-trust image that ' +
      'describes one artefact fairly. For a Linux BMC image it answers only ' +
      '"are these bytes identical", and the answer is no as soon as anything ' +
      'is rebuilt, including things that changed nothing anyone reviewed.'));

    var shape = el('pre', 'bytes');
    shape.textContent =
      '"device": {\n' +
      '  "vendor":            "...",\n' +
      '  "product":           "...",\n' +
      '  "fw_version":        "...",\n' +
      '  "fw_hash_sha2_384":  "..."      <- one hash, and it does not\n' +
      '}                                    decompose\n' +
      '"audit": {\n' +
      '  "srp": "...", "scope_number": 1, "issues": [ ... ]\n' +
      '}';
    view.appendChild(shape);
    view.appendChild(el('p', 'prose dim',
      'The real schema, with placeholder values. Published reports live in ' +
      'the OCP-Security-SAFE repository; nothing here is one of them.'));

    if (!r.assessments.length) {
      view.appendChild(el('p', 'prose',
        'No assessment scope is carried in this snapshot.'));
      view.appendChild(backLink());
      return;
    }

    r.assessments.forEach(function (an) {
      var a = an.doc;

      if (a.illustrative) {
        var warn = el('div', 'caution');
        warn.appendChild(el('div', 'caution-head', 'Worked example'));
        warn.appendChild(el('p', 'prose', a.disclaimer));
        view.appendChild(warn);
      }

      view.appendChild(el('h2', null, 'What it says'));
      var meta = el('div', 'keybox');
      meta.appendChild(el('p', 'prose',
        'Issued by ' + a.issuer.name + ' on ' + a.issued_at + '. ' +
        a.review.basis));
      meta.appendChild(el('p', 'prose dim',
        'It names its subject by the device merkle root rather than an image ' +
        'hash. That root commits to all ' + group(a.subject.package_count) +
        ' package measurements underneath it, so unlike a firmware hash it ' +
        'can be taken apart \u2014 and it is also the value a BMC extends into ' +
        'PCR 14, which is what lets the artefact an assessment names and the ' +
        'artefact a device attests be compared at all.'));
      meta.appendChild(digest(a.subject.device_root, false));
      meta.appendChild(el('p', 'prose dim',
        group((a.examined || []).length) + ' of ' +
        group(a.subject.package_count) + ' packages named as examined.'));
      view.appendChild(meta);

      view.appendChild(el('h2', null, 'What that means for each build'));
      view.appendChild(el('p', 'prose dim',
        'Joined on the package measurement, not on name and version: two ' +
        'builds of the same version produce different measurements, and only ' +
        'the measurement says whether the thing reviewed is the thing here.'));

      an.builds.forEach(function (pb) {
        var row = el('div', 'build' + (pb.rebuilt.length ? ' is-absent' : ''));
        row.appendChild(el('div', 'build-label', pb.build.label));

        var mid = el('div');
        mid.appendChild(el('div', null, pb.isSubject
          ? 'This is the image the assessment names.'
          : 'A different image from the one assessed.'));
        mid.appendChild(el('div', 'build-id', pb.build.build_id));
        row.appendChild(mid);

        row.appendChild(el('div',
          'build-verdict ' + (pb.rebuilt.length ? 'is-absent' : 'is-ok'),
          group(pb.examined.length) + ' examined'));

        if (pb.rebuilt.length) {
          var named = el('div', 'named');
          pb.rebuilt.forEach(function (p) {
            named.appendChild(el('div', null,
              p.name + ' ' + p.version + '  \u2014  reviewed build was ' +
              p.reviewedVersion));
          });
          named.appendChild(el('span', 'named-scope',
            pb.rebuilt.length + ' package' +
            (pb.rebuilt.length === 1 ? ' is' : 's are') +
            ' inside the reviewed area but not the reviewed build. The ' +
            'assessment looked here; its conclusions do not carry over to ' +
            'these bytes.'));
          row.appendChild(named);
        }
        view.appendChild(row);
      });

      view.appendChild(el('p', 'prose',
        'That distinction is the argument. A firmware hash can only say ' +
        'identical or not: every one of these builds would fail it equally, ' +
        'including the one whose only change was a build identifier. Naming ' +
        'packages separates a change the review cares about from one it ' +
        'does not.'));
    });

    // ---- the vocabulary ----
    view.appendChild(el('h2', null, 'The same things, in three vocabularies'));
    view.appendChild(el('p', 'prose dim',
      'Two rows have no OCP S.A.F.E. term. That gap is what this page is ' +
      'about.'));
    var tbl = el('div', 'vocab');
    [['', 'here', 'OCP S.A.F.E.', 'RATS (RFC 9334)'],
     ['the BMC', 'device', 'device.product', 'Attester'],
     ['an image', 'build', 'the artefact behind fw_hash_sha2_384', '--'],
     ['a package measurement', 'pkg-leaf-v1', '(no term)', 'Reference Value'],
     ['the log', 'transparency log', '(no term)', 'Reference Value Provider'],
     ['the checker', 'pkgattest', '--', 'Verifier'],
     ['the operator', '--', 'Cloud Service Provider', 'Relying Party'],
     ['who builds it', '--', 'Device Vendor', '--'],
     ['who reviews it', '--', 'Security Review Provider', '--']
    ].forEach(function (cols, i) {
      var vr = el('div', 'vocab-row' + (i === 0 ? ' is-head' : ''));
      cols.forEach(function (c, j) {
        vr.appendChild(el('div', j === 0 ? 'vocab-what' : 'vocab-cell', c));
      });
      tbl.appendChild(vr);
    });
    view.appendChild(tbl);

    view.appendChild(el('h2', null, 'What would close the gap'));
    view.appendChild(el('p', 'prose',
      'One field. An SFR already carries a hash of the reviewed artefact; ' +
      'alongside it, a hash that decomposes:'));
    var prop = el('pre', 'bytes');
    prop.textContent =
      '"device": {\n' +
      '  "fw_hash_sha2_384": "...",\n' +
      '  "components": {\n' +
      '    "manifest_type":         "pkg-measurements-v1",\n' +
      '    "manifest_hash_sha2_256": "' +
      r.assessments[0].doc.subject.device_root.slice(0, 24) + '...",\n' +
      '    "count":                  ' +
      r.assessments[0].doc.subject.package_count + '\n' +
      '  }\n' +
      '}';
    view.appendChild(prop);
    var ilink = el('p', 'prose');
    var ia = el('a', null, 'What a package update does to an assessment');
    ia.href = '#/impact';
    ilink.appendChild(ia);
    ilink.appendChild(document.createTextNode(
      ' \u2014 what carries across an image, and what does not.'));
    view.appendChild(ilink);

    view.appendChild(el('p', 'prose dim',
      'This is an observation, not a submission. It has not been through an ' +
      'OCP Security Project call, no Security Review Provider has seen it, ' +
      'and nothing here is endorsed by OCP. It also asks nothing of review ' +
      'providers: it changes how the reviewed artefact is identified, not ' +
      'how a review is scoped or carried out \u2014 S.A.F.E. leaves review areas ' +
      'deliberately open, and this does not touch that.'));
    view.appendChild(backLink());
  }

  // --------------------------------------------------------- objections view
  /* Arguments against this approach, including the ones with no answer.
   *
   * This whole page is assertion -- it argues, it does not compute -- so it
   * is set in the asserting typeface throughout. That is the point of having
   * the rule.
   *
   * The three marked "stands" are not softened. A project that lists only
   * the objections it can rebut has published an advertisement. */
  var UNOWNED_NAME = '(unowned)';

  /* Which builds carry the leaf that covers files no package owns. */
  function unownedCoverage(r) {
    return r.builds.map(function (b) {
      var found = null;
      if (b.pkgs) {
        b.pkgs.forEach(function (row, i) {
          if (row[0] === UNOWNED_NAME) {
            found = { count: row[4], leaf: b.leafHexes[i] };
          }
        });
      }
      return { label: b.meta.label, covered: !!found,
               count: found ? found.count : 0 };
    });
  }

  function objections(r) {
   var cov = unownedCoverage(r);
   var have = cov.filter(function (c) { return c.covered; });
   var lack = cov.filter(function (c) { return !c.covered; });

   var unownedVerdict = have.length
     ? { verdict: 'answered',
         label: lack.length ? 'closed, from image ' + have[0].label
                            : 'closed',
         body: [
           'It was true, and it was a way through rather than a rough edge: ' +
           'files no package claims sat in no leaf, so no device root, so no ' +
           'PCR, and adding a root user to /etc/passwd changed nothing the ' +
           'mechanism committed to.',
           'It is now covered by one further leaf, named "(unowned)", which ' +
           'measures every regular file no package claims. It is an ordinary ' +
           'pkg-leaf-v1 with a name no opkg package can have, so it needed no ' +
           'new format and no change to the on-device agent, the host ' +
           'verifier or the log \u2014 it arrives like any other leaf and is ' +
           'published like any other leaf.',
           'In this snapshot: ' + (have.map(function (c) {
             return 'image ' + c.label + ' covers ' + group(c.count) +
                    ' such files';
           }).join(', ')) + (lack.length
             ? '; ' + lack.map(function (c) { return 'image ' + c.label; })
                 .join(', ') + ' predate' + (lack.length === 1 ? 's' : '') +
               ' the change and remain uncovered.'
             : '.'),
           'Three files stay outside every leaf on purpose: /etc/machine-id, ' +
           '/etc/version and /etc/timestamp change on every boot or every ' +
           'build, so measuring them would make the root unstable rather ' +
           'than meaningful. That is a named gap, not an oversight.'
         ] }
     : { verdict: 'stands', label: 'no answer',
         body: [
           'Regular files in the built image owned by no package \u2014 ' +
           '/etc/passwd, /etc/shadow, /etc/ld.so.cache, the kernel module ' +
           'indexes depmod writes \u2014 are in no package leaf, so in no device ' +
           'root, so in no PCR.',
           'Adding a root user to /etc/passwd changes nothing this mechanism ' +
           'commits to. That is not a rough edge, it is a way through.'
         ] };

   return OBJECTIONS.map(function (o) {
     if (o.id !== 'unowned') return o;
     return { id: o.id, claim: o.claim, verdict: unownedVerdict.verdict,
              label: unownedVerdict.label, body: unownedVerdict.body };
   });
  }

  var OBJECTIONS = [
    {
      verdict: 'stands', label: 'no answer',
      claim: 'Measuring files at rest says nothing about what is running.',
      body: [
        'A file is measured when the image is built and again when the BMC ' +
        'boots. Neither says anything about a process compromised after it ' +
        'loaded. The literature calls this the TOCTOU problem in remote ' +
        'attestation and describes it as unsolved: transient malware can ' +
        'infect a device, do its work, and erase itself before the next ' +
        'attestation, leaving nothing to measure.',
        'This approach is about substitution in the supply chain \u2014 a ' +
        'different package arriving in a build. It is not about compromise ' +
        'of a running system, and nothing here should be read as covering ' +
        'the second.'
      ]
    },
    {
      id: 'unowned',
      verdict: 'stands', label: 'no answer',
      claim: 'Files that belong to no package are invisible to it.',
      body: ['(computed per build)']
    },
    {
      verdict: 'stands', label: 'no answer',
      claim: 'One log with one key is not a transparency ecosystem.',
      body: [
        'Certificate Transparency works because there are many independent ' +
        'logs, clients enforce inclusion, and they gossip about what they ' +
        'have seen. Here there is one log, run by whoever builds the images, ' +
        'with no monitors and no gossip.',
        'What publication buys is narrower than it sounds: divergence ' +
        'becomes detectable. You cannot publish one thing and ship another ' +
        'without it being visible to anyone who looks. It does not make the ' +
        'build correct, and nothing here should be read as saying so.'
      ]
    },
    {
      verdict: 'answered', label: 'answered, partly',
      claim: 'This is Linux IMA with extra steps.',
      body: [
        'IMA measures files as they are accessed and extends PCR 10 as it ' +
        'goes. Because post-OS execution is multi-process, the order of ' +
        'those extends \u2014 and therefore the PCR value \u2014 differs on every ' +
        'boot; the IMA PCR is documented as unsuitable even for a TPM ' +
        'unseal. One image has no single IMA value to compare.',
        'pkg-merkle-v1 hashes a name-sorted set, so an image has exactly one ' +
        'root: the same on every boot, the same on every device, and ' +
        'diffable against another image. IMA also measures what ran; this ' +
        'measures what is installed, including what has not run yet.',
        'The limit of the rebuttal, stated plainly: a verifier that parses ' +
        'the IMA log can reconstruct state too, and this approach equally ' +
        'needs its measurement list. The claim is that the root is ' +
        'comparable, not that IMA cannot get there.'
      ]
    },
    {
      verdict: 'answered', label: 'answered',
      claim: 'An SBOM already lists packages with their hashes.',
      body: [
        'It does, and the measurement document here is close to being one. ' +
        'The difference is what is done with it. An SBOM is a claim by ' +
        'whoever built the image, with nothing binding it to a device and ' +
        'nothing making it append-only. The addition is the log and the PCR ' +
        'binding, not the inventory.'
      ]
    },
    {
      verdict: 'answered', label: 'answered, for the log',
      claim: 'This will not scale.',
      body: [
        'Publishing a third image added exactly one leaf and reused 2,130. ' +
        'The log grows by the delta between builds, not by the size of each ' +
        'image.',
        'What does not scale is the absence argument. This page proves ' +
        'absence by holding every leaf, which is fine at 2,132 records and ' +
        'not at a million.'
      ]
    },
    {
      verdict: 'conceded', label: 'conceded',
      claim: 'Why not build this on Rekor?',
      body: [
        'Reasonable. Sigstore\'s Rekor is a mature transparency log built ' +
        'for this shape of problem, with Mozilla\'s Binary Transparency work ' +
        'behind it. The log here is a demonstration, not a proposal.',
        'What is being proposed is the leaf semantics \u2014 a package ' +
        'measurement as a reference value, scoped to an image line \u2014 and ' +
        'those could sit on Rekor perfectly well.'
      ]
    },
    {
      verdict: 'conceded', label: 'conceded, and it points somewhere better',
      claim: 'CoRIM already carries per-component reference values.',
      body: [
        'It does, and it is deployed: CoRIM and CoMID reference measurements ' +
        'ship per firmware component today. But a component there is one of ' +
        'a handful of blobs \u2014 root-of-trust firmware, accelerator firmware. ' +
        'Nobody is doing this at 2,131 packages inside a single Linux image.',
        'So this is not a refutation so much as the right implementation ' +
        'target. The argument is about granularity, not about needing a new ' +
        'format.'
      ]
    }
  ];

  var SOURCES = [
    ['IMA concepts, on order-dependent PCR extends',
     'https://ima-doc.readthedocs.io/en/latest/ima-concepts.html'],
    ['On the TOCTOU Problem in Remote Attestation (ACM CCS 2021)',
     'https://dl.acm.org/doi/abs/10.1145/3460120.3484532'],
    ['Remote Attestation: A Literature Review',
     'https://arxiv.org/pdf/2105.02466'],
    ['TCG Guidance on Integrity Measurements and Event Log Processing',
     'https://trustedcomputinggroup.org/wp-content/uploads/TCG-Guidance-Integrity-Measurements-Event-Log-Processing_v1_r0p118_24feb2022-1.pdf'],
    ['Sigstore Rekor', 'https://github.com/sigstore/rekor'],
    ['NVIDIA CoRIM-based reference measurement sharing',
     'https://networking-docs.nvidia.com/dpunicattestation/']
  ];

  function renderObjections(r) {
    clear(view);
    var live = objections(r);
    var standing = live.filter(function (o) { return o.verdict === 'stands'; });

    view.appendChild(el('p', 'eyebrow', 'arguments against this approach'));
    view.appendChild(el('p', 'thesis',
      standing.length === 1 ? 'One of these has no answer.'
                            : standing.length + ' of these have no answer.'));

    view.appendChild(el('p', 'prose',
      'Everything on this page is argument rather than arithmetic, so it is ' +
      'set in the asserting typeface throughout \u2014 nothing below was computed ' +
      'by your browser. The objections are stated in the strongest form ' +
      'found for them, and the ones with no rebuttal are marked as having ' +
      'none.'));

    ['stands', 'answered', 'conceded'].forEach(function (group) {
      var heading = { stands: 'Objections that stand',
                      answered: 'Objections with an answer',
                      conceded: 'Objections that are simply right' }[group];
      view.appendChild(el('h2', null, heading));

      live.filter(function (o) { return o.verdict === group; })
        .forEach(function (o) {
          var box = el('div', 'objection is-' + o.verdict);
          var head = el('div', 'objection-head');
          head.appendChild(el('div', 'objection-claim', o.claim));
          head.appendChild(el('div', 'verdict-tag is-' + o.verdict, o.label));
          box.appendChild(head);
          o.body.forEach(function (para) {
            box.appendChild(el('p', 'prose', para));
          });
          view.appendChild(box);
        });
    });

    view.appendChild(el('h2', null, 'The line through all of it'));
    view.appendChild(el('p', 'prose',
      'Every objection that lands is a version of "what is happening on ' +
      'that machine right now". Every one that misses is a version of "what ' +
      'changed between two builds". This is built for the second question, ' +
      'and is worth exactly nothing against the first.'));

    view.appendChild(el('h2', null, 'Sources'));
    var list = el('div', 'filelist');
    SOURCES.forEach(function (s) {
      var a = el('a', 'filerow', s[0]);
      a.href = s[1];
      a.setAttribute('rel', 'noopener noreferrer');
      list.appendChild(a);
    });
    view.appendChild(list);
    view.appendChild(el('p', 'prose dim',
      'These links leave the page and will not resolve from the offline ' +
      'copy.'));

    var back = el('p', 'prose');
    var l1 = el('a', null, 'What this page does not prove');
    l1.href = '#/limits';
    back.appendChild(l1);
    back.appendChild(document.createTextNode(' \u00b7 '));
    var l2 = el('a', null, 'Back to the verification');
    l2.href = '#/';
    back.appendChild(l2);
    view.appendChild(back);
  }

  // ------------------------------------------------------------- impact view
  /* Compare the image an assessment names against another image, and report
   * what moved.
   *
   * The one rule this must obey: it may only ever ESCALATE. It computes
   * reasons to re-review; the absence of a reason is not clearance. Printing
   * "minor change, assurance maintained" would be the tool doing the
   * reviewer's job, and it is not equipped to. Common Criteria puts that
   * classification in a human's hands for good reason -- see the note the
   * page prints.
   *
   * What transfers and what does not:
   *   - a finding about an artefact ("this build has CVE-X") is a property
   *     of bytes, and follows an identical leaf hash exactly;
   *   - an absence of findings is a property of the review effort, and
   *     follows nothing at all. */
  function impactAnalysis(an, subject, candidate) {
    function index(b) {
      var m = {};
      if (b.pkgs) {
        b.pkgs.forEach(function (row, i) {
          m[row[0]] = { version: row[1], leaf: b.leafHexes[i] };
        });
      }
      return m;
    }
    var S = index(subject), C = index(candidate);
    var out = { subject: subject.meta, candidate: candidate.meta,
                identical: 0, changed: [], added: [], removed: [],
                reasons: [] };

    Object.keys(C).forEach(function (name) {
      var c = C[name], s = S[name];
      if (!s) {
        out.added.push({ name: name, version: c.version,
                         reviewedArea: !!an.byName[name] });
        return;
      }
      if (s.leaf === c.leaf) out.identical++;
      else {
        out.changed.push({ name: name, from: s.version, to: c.version,
                           reviewedArea: !!an.byName[name] });
      }
    });
    Object.keys(S).forEach(function (name) {
      if (!C[name]) {
        out.removed.push({ name: name, version: S[name].version,
                           reviewedArea: !!an.byName[name] });
      }
    });

    out.changed.sort(function (a, b) { return a.name < b.name ? -1 : 1; });

    var reviewedChanged = out.changed.filter(function (p) {
      return p.reviewedArea;
    });
    if (reviewedChanged.length) {
      out.reasons.push({
        kind: 'changed',
        text: reviewedChanged.length + ' package' +
              (reviewedChanged.length === 1 ? '' : 's') +
              ' inside the reviewed area changed',
        items: reviewedChanged.map(changeLabel)
      });
    }
    if (out.added.length) {
      out.reasons.push({
        kind: 'added',
        text: out.added.length + ' package' +
              (out.added.length === 1 ? ' is' : 's are') +
              ' present here and absent from the assessed image, so no ' +
              'part of the review saw them',
        items: out.added.slice(0, 10).map(function (p) {
          return p.name + ' ' + p.version;
        })
      });
    }
    var reviewedGone = out.removed.filter(function (p) {
      return p.reviewedArea;
    });
    if (reviewedGone.length) {
      out.reasons.push({
        kind: 'removed',
        text: reviewedGone.length + ' package' +
              (reviewedGone.length === 1 ? '' : 's') +
              ' the review examined ' +
              (reviewedGone.length === 1 ? 'is' : 'are') +
              ' no longer present, so the composition it judged is gone',
        items: reviewedGone.map(function (p) { return p.name; })
      });
    }
    return out;
  }

  /* A version string is not an identity. When a package's measurement moved
   * but its version did not, say so plainly -- that case is the whole reason
   * this joins on the leaf hash instead of on name and version. */
  function changeLabel(p) {
    return p.from === p.to
      ? p.name + '  ' + p.from + '  (same version, different measurement)'
      : p.name + '  ' + p.from + ' -> ' + p.to;
  }

  function renderImpact(r) {
    clear(view);
    view.appendChild(el('p', 'eyebrow', 'impact analysis'));
    view.appendChild(el('p', 'thesis',
      'What a package update does to an assessment.'));

    if (!r.assessments.length) {
      view.appendChild(el('p', 'prose',
        'No assessment scope is carried in this snapshot, so there is ' +
        'nothing to compare against.'));
      view.appendChild(backLink());
      return;
    }

    view.appendChild(el('p', 'prose',
      'An assessment is pinned to one image. Update a single package and, as ' +
      'far as a firmware hash is concerned, the whole thing is a stranger. ' +
      'Measuring packages separately lets you compute what actually moved \u2014 ' +
      'and, just as importantly, be precise about what that does and does ' +
      'not license you to conclude.'));

    var split = el('div', 'keybox');
    split.appendChild(el('p', 'prose',
      'Two kinds of claim, and they behave differently. A finding about an ' +
      'artefact \u2014 "this build contains CVE-2026-X" \u2014 is a property of bytes, ' +
      'so it follows an identical measurement exactly. An absence of ' +
      'findings \u2014 "the review found no issues" \u2014 is a property of the review ' +
      'effort, and follows nothing. Identical measurements carry forward ' +
      'what was found. They do not carry forward the fact that nothing else ' +
      'was.'));
    view.appendChild(split);

    r.assessments.forEach(function (an) {
      var subject = null;
      r.builds.forEach(function (b) {
        if (b.meta.device_root === an.doc.subject.device_root) subject = b;
      });
      if (!subject) return;

      r.builds.forEach(function (cand) {
        if (cand === subject || !cand.pkgs) return;
        var im = impactAnalysis(an, subject, cand);

        view.appendChild(el('h2', null,
          'Assessed image ' + subject.meta.label + '  ->  image ' +
          cand.meta.label));

        var tally = el('div', 'stats');
        function stat(v, l, note) {
          var s = el('div', 'stat');
          s.appendChild(el('div', 'stat-value', v));
          s.appendChild(el('div', 'stat-label', l));
          if (note) s.appendChild(el('p', 'prose dim', note));
          return s;
        }
        tally.appendChild(stat(group(im.identical), 'identical measurements',
          'Findings recorded against these exact bytes still apply.'));
        tally.appendChild(stat(group(im.changed.length), 'changed',
          'Nothing recorded about the old bytes says anything about these.'));
        tally.appendChild(stat(group(im.added.length + im.removed.length),
          'added or removed'));
        view.appendChild(tally);

        if (im.reasons.length) {
          var box = el('div', 'caution');
          box.appendChild(el('div', 'caution-head', 'Reasons to re-review'));
          im.reasons.forEach(function (rs) {
            box.appendChild(el('p', 'prose', rs.text + ':'));
            var list = el('div', 'filelist');
            rs.items.forEach(function (it) {
              list.appendChild(el('div', 'filerow', it));
            });
            box.appendChild(list);
          });
          view.appendChild(box);
        } else {
          var none = el('div', 'keybox');
          none.appendChild(el('div', 'build-verdict is-ok',
            'No reason to re-review found in the reviewed area.'));
          none.appendChild(el('p', 'prose',
            'That is not clearance, and this page will not offer any. It ' +
            'means this analysis found nothing, across the things it can ' +
            'see. Whether the change is minor is a judgement, and it belongs ' +
            'to a reviewer.'));
          if (im.changed.length) {
            none.appendChild(el('p', 'prose dim',
              'What did change, outside the reviewed area: ' +
              im.changed.map(changeLabel).join('; ') + '.'));
          }
          view.appendChild(none);
        }
      });
    });

    // ---- the limits of this analysis ----
    view.appendChild(el('h2', null, 'What this analysis cannot see'));

    var lim1 = el('div', 'limit');
    lim1.appendChild(el('h3', null, 'Files that belong to no package'));
    lim1.appendChild(el('p', 'prose',
      '25 regular files in the built image are owned by no package at all, ' +
      'so no measurement covers them and this comparison cannot include ' +
      'them: 12 kernel module indexes written by depmod, 10 files assembled ' +
      'during image composition \u2014 among them /etc/passwd, /etc/shadow and ' +
      '/etc/ld.so.cache \u2014 and 3 written by the measurement pass itself. Two ' +
      'images with identical package measurements can still differ in those. ' +
      'The count comes from measuring the built root filesystem directly; it ' +
      'is not derivable from this bundle.'));
    view.appendChild(lim1);

    var lim2 = el('div', 'limit');
    lim2.appendChild(el('h3', null, 'Packages whose behaviour changed anyway'));
    lim2.appendChild(el('p', 'prose',
      'Update a shared library and every package linking it behaves ' +
      'differently while its own bytes stay identical \u2014 so it counts as ' +
      '"identical" above. Catching that needs the dependency graph, and the ' +
      'measurement documents do not carry one yet. This is the largest hole ' +
      'in the analysis and it is stated here rather than papered over.'));
    view.appendChild(lim2);

    var lim3 = el('div', 'limit');
    lim3.appendChild(el('h3', null, 'The judgement itself'));
    lim3.appendChild(el('p', 'prose',
      'Common Criteria has had a process for this for years: under Assurance ' +
      'Continuity a developer files an Impact Analysis Report and the change ' +
      'is classified minor, keeping the certificate under maintenance, or ' +
      'major, requiring re-evaluation. The classification is a human ' +
      'decision. OCP S.A.F.E. defines no equivalent \u2014 no expiry, no cadence, ' +
      'and nothing about how a report applies to a later version \u2014 so today ' +
      'an update simply drops you to zero. What a page like this can ' +
      'contribute is the input to that decision, stated exactly, instead of ' +
      '"we rebuilt the image".'));
    view.appendChild(lim3);

    view.appendChild(backLink());
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

    view.appendChild(el('h2', null, 'Files no package owns'));
    var cov = unownedCoverage(r);
    var haveCov = cov.filter(function (c) { return c.covered; });
    if (haveCov.length) {
      view.appendChild(el('p', 'prose',
        'Some regular files in an image are claimed by no package at all: ' +
        '/etc/passwd, /etc/shadow, /etc/ld.so.cache, the indexes depmod ' +
        'writes. They are covered by one further leaf so that nothing in the ' +
        'rootfs sits outside the device root.'));
      var cs = el('div', 'stats');
      cov.forEach(function (c) {
        cs.appendChild(stat('build ' + c.label,
          c.covered ? group(c.count) : 'not covered',
          c.covered ? 'files no package claims, inside the device root'
                    : 'built before the (unowned) leaf existed'));
      });
      view.appendChild(cs);
      view.appendChild(el('p', 'prose dim',
        '/etc/machine-id, /etc/version and /etc/timestamp stay outside every ' +
        'leaf deliberately: they change on every boot or every build, so ' +
        'measuring them would make the root unstable rather than meaningful.'));
    } else {
      view.appendChild(el('p', 'prose',
        'No build in this snapshot carries the (unowned) leaf, so files ' +
        'claimed by no package are outside every measurement here.'));
    }

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
      else if (hash === '#/assessment') renderAssessment(verified);
      else if (hash === '#/impact') renderImpact(verified);
      else if (hash === '#/objections') renderObjections(verified);
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
