/* verify-bundle.js -- check an exported site bundle the way a browser will.
 *
 *   node tools/verify-bundle.js site-dist [--expect-key <64-hex>]
 *
 * Loads the bundle's classic scripts into one shared scope, exactly as a page
 * does with <script> tags, then re-derives everything from the leaf set it
 * holds. Nothing here asks a server anything.
 *
 * What it proves, and what it cannot
 * ----------------------------------
 * Every leaf, root, proof and signature below is recomputed locally. Two
 * things are NOT proved, and are printed as such rather than quietly folded
 * into a green tick:
 *
 *   - **Key authenticity.** The bundle ships the log's public key alongside
 *     the signatures it checks, so a bundle re-signed under an attacker's key
 *     verifies against itself perfectly. Pass --expect-key with a value
 *     obtained out of band (the slide, the signed release tag) to close this.
 *
 *   - **Image attestation.** A log leaf attests a *package*, never a build:
 *     log-leaf-v1 carries no merkle_root. So "every package is published"
 *     is exactly that, and does not mean anyone published this image. A
 *     fabricated image assembled from already-published packages -- including
 *     a downgrade -- satisfies it.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const argv = process.argv.slice(2);
const dist = argv.find(a => !a.startsWith('--')) || 'site-dist';
const keyFlag = argv.indexOf('--expect-key');
const expectKey = keyFlag >= 0 ? (argv[keyFlag + 1] || '').toLowerCase() : null;

const abs = p => path.resolve(dist, p);

function loadScripts(files) {
  const ctx = vm.createContext({ TextEncoder, TextDecoder, console });
  for (const f of files) {
    vm.runInContext(fs.readFileSync(abs(f), 'utf8'), ctx, { filename: f });
  }
  return ctx;
}

const dataDir = abs('data');
const buildFiles = fs.readdirSync(path.join(dataDir, 'builds')).sort()
  .map(n => 'data/builds/' + n);
const pkgFiles = fs.readdirSync(dataDir).filter(n => n.startsWith('pkgs-'))
  .sort().map(n => 'data/' + n);
const fileFiles = fs.readdirSync(dataDir).filter(n => n.startsWith('files-'))
  .sort().map(n => 'data/' + n);

const ctx = loadScripts([
  'vendor/pkgcrypto.js', 'verify.js',
  'data/snapshot.js', 'data/leaves.js', 'data/sth-history.js',
  'data/builds-index.js', ...buildFiles, ...pkgFiles, ...fileFiles,
]);

const V = ctx.PKGI_VERIFY;
const D = ctx.PKGI_DATA;
const problems = [];
const caveats = [];
const note = s => console.log('  ' + s);

for (const p of V.selfTest()) problems.push('selfTest: ' + p);

const snap = D.snapshot || {};
console.log(`snapshot ${snap.snapshot_id}`);

/* Validate the snapshot's SHAPE before any of it is used as a number or a
 * hex string. Everything below consumes these values, and a bundle under
 * suspicion is exactly the kind that carries a negative tree_size or a
 * truncated key -- which must come out as BUNDLE INVALID, never as a stack
 * trace on top of a half-printed, green-looking transcript. */
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
let shapeOk = true;
function shape(cond, msg) {
  if (!cond) { problems.push('snapshot: ' + msg); shapeOk = false; }
}
shape(Number.isSafeInteger(snap.tree_size) && snap.tree_size >= 0,
      `tree_size must be a non-negative integer, got ${JSON.stringify(snap.tree_size)}`);
shape(typeof snap.root_hash === 'string' && HEX64.test(snap.root_hash),
      'root_hash must be 64 lowercase hex characters');
shape(typeof snap.signature === 'string' && HEX128.test(snap.signature),
      'signature must be 128 lowercase hex characters');
shape(Number.isSafeInteger(snap.timestamp) && snap.timestamp >= 0,
      'timestamp must be a non-negative integer');
shape(typeof snap.log_pubkey_hex === 'string' && HEX64.test(snap.log_pubkey_hex),
      'log_pubkey_hex must be 64 lowercase hex characters');
shape(Array.isArray(D.leaves), 'leaves must be an array');
shape(Array.isArray(D.sth_history), 'sth_history must be an array');
shape(Array.isArray(D.builds), 'builds must be an array');

let leafHashes = null;
let pubRaw = null;

if (!shapeOk) {
  console.log('');
  console.log(`BUNDLE INVALID -- ${problems.length} problem(s):`);
  for (const p of problems) console.log('  ! ' + p);
  process.exit(1);
}

try {
  // --- 0. The leaf set must be exactly the signed head, no more ------------
  // Leaves beyond tree_size are covered by no signature. Without this check,
  // appending one unsigned line to leaves.js is enough to make an unpublished
  // package look published -- no key required.
  if (D.leaves.length !== snap.tree_size) {
    problems.push(`leaves.js holds ${D.leaves.length} records but the signed ` +
                  `head covers ${snap.tree_size} -- the extra records are ` +
                  `signed by nothing`);
  } else if (snap.package_records !== snap.tree_size) {
    problems.push(`snapshot.package_records (${snap.package_records}) != ` +
                  `tree_size (${snap.tree_size})`);
  } else {
    note(`${D.leaves.length} records, exactly matching the signed head`);
  }

  // --- 1-2. The signed head, re-derived from the leaves the bundle ships ----
  const t0 = Date.now();
  leafHashes = D.leaves.map(s => V.leafHash(V.utf8(s)));
  const root = V.hex(V.mth(leafHashes, snap.tree_size));
  const ms = Date.now() - t0;

  note(`rebuilt root from ${snap.tree_size} leaves in ${ms} ms`);
  if (root !== snap.root_hash) {
    problems.push(`recomputed root ${root} != signed head ${snap.root_hash}`);
  } else {
    note(`root matches the signed head: ${root.slice(0, 16)}...`);
  }

  pubRaw = V.unhex(snap.log_pubkey_hex);
  if (!V.verifySth(pubRaw, snap)) {
    problems.push('Ed25519 signature over the current head is invalid');
  } else {
    note('Ed25519 signature over the head verifies');
  }

  // The bundle also states a key_id; it must be derivable from the key shipped,
  // or the bundle is internally inconsistent.
  const SPKI_PREFIX = '302a300506032b6570032100';
  const derivedKeyId = 'sha256:' + V.hex(
    V.sha256(V.unhex(SPKI_PREFIX + snap.log_pubkey_hex)));
  if (snap.key_id !== derivedKeyId) {
    problems.push(`snapshot.key_id ${snap.key_id} is not the SPKI digest of ` +
                  `the key shipped (${derivedKeyId})`);
  }

  // Key authenticity: only an out-of-band value can settle it.
  if (expectKey) {
    if (snap.log_pubkey_hex.toLowerCase() !== expectKey) {
      problems.push(`log key ${snap.log_pubkey_hex} != expected ${expectKey}`);
    } else {
      note(`log key matches the one supplied out of band`);
    }
  } else {
    caveats.push('the log key was read from this bundle, not pinned -- a ' +
                 'bundle re-signed under another key would verify against ' +
                 'itself. Re-run with --expect-key <64-hex> to close this.');
    note(`log key (UNPINNED): ${snap.log_pubkey_hex.slice(0, 16)}...`);
    note(`  key_id ${snap.key_id.slice(0, 23)}... -- compare out of band`);
  }

  // --- 3. Every historical head must be a prefix of the tree, and signed ----
  for (const h of D.sth_history) {
    if (h.tree_size > snap.tree_size) {
      problems.push(`history contains a head at size ${h.tree_size}, beyond ` +
                    `the snapshot's ${snap.tree_size}`);
      continue;
    }
    const r = V.hex(V.mth(leafHashes, h.tree_size));
    if (r !== h.root_hash) {
      problems.push(`head at size ${h.tree_size}: prefix root ${r} != ${h.root_hash}`);
    } else if (!V.verifySth(pubRaw, h)) {
      problems.push(`head at size ${h.tree_size}: bad signature`);
    } else {
      note(`head size ${h.tree_size} reproduced by prefix and signed`);
    }
  }
  if (D.sth_history.length &&
      D.sth_history[D.sth_history.length - 1].tree_size !== snap.tree_size) {
    problems.push('the snapshot head is not the newest head in its own history');
  }

  // Consistency between consecutive heads. Both roots were already matched
  // against this same leaf set above, so this is a demonstration of the
  // append-only property rather than an independent check -- say so.
  for (let i = 1; i < D.sth_history.length; i++) {
    const a = D.sth_history[i - 1], b = D.sth_history[i];
    if (a.tree_size === 0) {
      note(`consistency 0 -> ${b.tree_size} not applicable (empty tree)`);
      continue;
    }
    try {
      const proof = V.consistencyProof(leafHashes, a.tree_size, b.tree_size);
      const ok = V.verifyConsistency(a.tree_size, b.tree_size,
        V.unhex(a.root_hash), V.unhex(b.root_hash), proof);
      if (!ok) problems.push(`consistency ${a.tree_size}->${b.tree_size} failed`);
      else note(`consistency ${a.tree_size} -> ${b.tree_size} demonstrated ` +
                `(${proof.length} nodes, derived from these same leaves)`);
    } catch (e) {
      problems.push(`consistency ${a.tree_size}->${b.tree_size}: ${e.message}`);
    }
  }
} catch (e) {
  // Same rule as the build loop: a verifier that dies mid-render
  // tells the reader nothing. Report and keep going.
  problems.push('while checking the log: ' +
                (e && e.message ? e.message : e));
}

// --- 4-5. Each build ------------------------------------------------------
// Membership is decided ONLY against leaves covered by the signed head.
if (leafHashes === null) {
  console.log('');
  console.log(`BUNDLE INVALID -- ${problems.length} problem(s):`);
  for (const p of problems) console.log('  ! ' + p);
  process.exit(1);
}
const signedLeaves = leafHashes.slice(0, snap.tree_size);
const byLeafHash = new Map(signedLeaves.map((h, i) => [V.hex(h), i]));

for (const b of D.builds) {
 try {
  const short = b.device_root.slice(0, 16);
  const pkgs = D['pkgs_' + short];
  const files = D['files_' + short];
  if (!pkgs || !files) { problems.push(`${b.label}: missing package data`); continue; }

  // The per-build file must agree with the index that drives this loop.
  const detail = D['build_' + b.label];
  if (!detail) {
    problems.push(`${b.label}: no per-build record`);
  } else {
    for (const k of ['build_id', 'image_line', 'device_root', 'pcr14',
                     'package_count', 'status', 'unpublished_count']) {
      if (JSON.stringify(detail[k]) !== JSON.stringify(b[k])) {
        problems.push(`${b.label}: ${k} differs between builds-index.js ` +
                      `(${JSON.stringify(b[k])}) and the per-build record ` +
                      `(${JSON.stringify(detail[k])})`);
      }
    }
  }

  const filesByName = new Map(files);
  const leafHexes = pkgs.map(([name, version, arch]) =>
    V.pkgLeafHash({
      name, version, arch,
      files: (filesByName.get(name) || []).map(([p, s]) => ({ path: p, sha256: s })),
    }));

  if (pkgs.length !== b.package_count) {
    problems.push(`${b.label}: package_count ${b.package_count} != ` +
                  `${pkgs.length} packages shipped`);
  }

  const derived = V.deviceRoot(leafHexes);
  if (derived !== b.device_root) {
    problems.push(`${b.label}: device root ${derived} != ${b.device_root}`);
    continue;
  }

  const unaccounted = [];
  pkgs.forEach(([name, version, arch], i) => {
    const data = V.logLeafData({
      arch, image_line: b.image_line, name, version,
      pkg_leaf_hash: leafHexes[i],
    });
    if (!byLeafHash.has(V.hex(V.leafHash(data)))) {
      unaccounted.push(`${name} ${version}`);
    }
  });

  // member_indices is shipped as this build's claimed footprint in the log,
  // and a detail page will render it. Every index must land inside the signed
  // prefix and name a leaf this build actually contains -- otherwise a build
  // could claim membership it does not have.
  if (detail && Array.isArray(detail.member_indices)) {
    const mine = new Set(pkgs.map((row, i) => V.hex(V.leafHash(V.logLeafData({
      arch: row[2], image_line: b.image_line, name: row[0], version: row[1],
      pkg_leaf_hash: leafHexes[i],
    })))));
    const bad = detail.member_indices.filter(function (idx) {
      if (!Number.isSafeInteger(idx) || idx < 0 || idx >= snap.tree_size) {
        return true;
      }
      return !mine.has(V.hex(signedLeaves[idx]));
    });
    if (bad.length) {
      problems.push(`${b.label}: ${bad.length} of ` +
                    `${detail.member_indices.length} member_indices do not ` +
                    `name a leaf of this build inside the signed head ` +
                    `(first: ${bad[0]})`);
    } else {
      note(`all ${detail.member_indices.length} claimed log indices resolve ` +
           `to this build's own leaves`);
    }
  }

  const pcr = V.expectedPcr14(b.device_root);
  if (pcr !== b.pcr14) problems.push(`${b.label}: PCR14 mismatch`);
  if (unaccounted.length !== b.unpublished_count) {
    problems.push(`${b.label}: index says ${b.unpublished_count} unpublished, ` +
                  `recomputed ${unaccounted.length}`);
  }

  console.log(`\nbuild ${b.label}  ${b.build_id}`);
  note(`device root recomputed from ${pkgs.length} pkg-leaf-v1 preimages: ` +
       `${derived.slice(0, 16)}...`);
  note(`expected PCR14 = sha256(0^32 || root) = ${pcr.slice(0, 16)}... ` +
       `(no TPM quote in this bundle)`);
  if (unaccounted.length === 0) {
    note(`all ${pkgs.length} packages have a log entry under image line ` +
         `${b.image_line} at tree size ${snap.tree_size}`);
    note(`  note: no log entry attests this IMAGE -- a log leaf commits to a ` +
         `package, never to a build`);
  } else {
    note(`${unaccounted.length} of ${pkgs.length} packages unaccounted for ` +
         `under image line ${b.image_line} at tree size ${snap.tree_size}:`);
    for (const u of unaccounted.slice(0, 5)) note(`    ${u}`);
    if (unaccounted.length > 5) {
      note(`    ... and ${unaccounted.length - 5} more`);
    }
  }
 } catch (e) {
   // A verifier that crashes tells the reader nothing. Every failure has to
   // come out as a reported problem.
   problems.push(`${b.label}: ${e && e.message ? e.message : e}`);
 }
}

console.log('');
if (problems.length) {
  console.log(`BUNDLE INVALID -- ${problems.length} problem(s):`);
  for (const p of problems) console.log('  ! ' + p);
  process.exit(1);
}
console.log('bundle OK -- every value above was recomputed from the leaf set ' +
            'this bundle ships; no server was asked anything.');
for (const c of caveats) console.log('  caveat: ' + c);
