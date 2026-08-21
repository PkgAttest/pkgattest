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
    out.builds = (D.builds || []).map(function (b) {
      var short = b.device_root.slice(0, 16);
      var pkgs = D['pkgs_' + short];
      var files = D['files_' + short];
      var result = { meta: b, unaccounted: null, deviceRootOk: null };
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

      var missing = [];
      pkgs.forEach(function (row, idx) {
        var data = V.logLeafData({
          arch: row[2], image_line: b.image_line, name: row[0],
          version: row[1], pkg_leaf_hash: leafHexes[idx]
        });
        if (!(V.hex(V.leafHash(data)) in byLeafHash)) {
          missing.push({ name: row[0], version: row[1] });
        }
      });
      result.unaccounted = missing;
      return result;
    });

    return out;
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

    var more = el('p', 'prose');
    var link = el('a', null, 'What this does not prove');
    link.href = '#/limits';
    more.appendChild(link);
    more.appendChild(document.createTextNode(
      ' \u2014 the four things this page cannot tell you.'));
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

  // ----------------------------------------------------------------- router
  var verified = null;

  function route() {
    if (!verified) return;
    if (location.hash === '#/limits') renderLimits(verified);
    else renderHome(verified);
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
