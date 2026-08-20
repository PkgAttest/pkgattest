/* verify-bundle.js — check an exported site bundle the way a browser will.
 *
 *   node tools/verify-bundle.js site-dist
 *
 * Loads the bundle's classic scripts into one shared scope, exactly as a
 * page does with <script> tags, then re-derives everything from the leaf set
 * it holds:
 *
 *   1. the RFC 6962 root over all leaves            -> matches the signed head
 *   2. the Ed25519 signature over that head          -> valid under the pinned key
 *   3. every historical head                         -> reproduced by prefix
 *   4. each build's device root from pkg-leaf-v1     -> matches the build record
 *   5. each build's packages against the log         -> named if unpublished
 *
 * Nothing here asks a server anything. If this passes, the bundle is
 * internally self-verifying, which is the site's entire claim.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const dist = process.argv[2] || 'site-dist';
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
const note = s => console.log('  ' + s);

for (const p of V.selfTest()) problems.push('selfTest: ' + p);

// 1-2. The signed head, re-derived from the leaves the bundle ships.
const t0 = Date.now();
const leafHashes = D.leaves.map(s => V.leafHash(V.utf8(s)));
const root = V.hex(V.mth(leafHashes, D.snapshot.tree_size));
const ms = Date.now() - t0;

console.log(`snapshot ${D.snapshot.snapshot_id}  (${D.leaves.length} records)`);
note(`rebuilt root from ${D.snapshot.tree_size} leaves in ${ms} ms`);
if (root !== D.snapshot.root_hash) {
  problems.push(`recomputed root ${root} != signed head ${D.snapshot.root_hash}`);
} else {
  note(`root matches the signed head: ${root.slice(0, 16)}…`);
}

const pubRaw = V.unhex(D.snapshot.log_pubkey_hex);
if (!V.verifySth(pubRaw, D.snapshot)) {
  problems.push('Ed25519 signature over the current head is invalid');
} else {
  note('Ed25519 signature over the head verifies');
}

// 3. Every historical head must be a prefix of the tree we hold, and signed.
for (const h of D.sth_history) {
  const r = V.hex(V.mth(leafHashes, h.tree_size));
  if (r !== h.root_hash) {
    problems.push(`head at size ${h.tree_size}: prefix root ${r} != ${h.root_hash}`);
  } else if (!V.verifySth(pubRaw, h)) {
    problems.push(`head at size ${h.tree_size}: bad signature`);
  } else {
    note(`head size ${h.tree_size} reproduced by prefix and signed`);
  }
}

// Consistency between consecutive heads. RFC 6962 defines no consistency
// proof out of an empty tree, so a genesis head is skipped rather than
// treated as a failure.
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
    else note(`consistency ${a.tree_size} -> ${b.tree_size} verified ` +
              `(${proof.length} nodes)`);
  } catch (e) {
    problems.push(`consistency ${a.tree_size}->${b.tree_size}: ${e.message}`);
  }
}

// 4-5. Each build: device root from preimages, and log membership.
const byLeafHash = new Map(leafHashes.map((h, i) => [V.hex(h), i]));

for (const b of D.builds) {
 try {
  const short = b.device_root.slice(0, 16);
  const pkgs = D['pkgs_' + short];
  const files = D['files_' + short];
  if (!pkgs || !files) { problems.push(`${b.label}: missing package data`); continue; }

  const filesByName = new Map(files);
  const leafHexes = pkgs.map(([name, version, arch]) =>
    V.pkgLeafHash({
      name, version, arch,
      files: (filesByName.get(name) || []).map(([p, s]) => ({ path: p, sha256: s })),
    }));

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
      unaccounted.push(`${name} ${version.replace(/-r\d+$/, '')}`);
    }
  });

  const pcr = V.expectedPcr14(b.device_root);
  if (pcr !== b.pcr14) problems.push(`${b.label}: PCR14 mismatch`);

  console.log(`\nbuild ${b.label}  ${b.build_id}`);
  note(`device root recomputed from ${pkgs.length} pkg-leaf-v1 preimages: ` +
       `${derived.slice(0, 16)}…`);
  note(`PCR14 = sha256(0^32 || root) = ${pcr.slice(0, 16)}…`);
  if (unaccounted.length === 0) {
    note(`all ${pkgs.length} packages have a log entry`);
  } else {
    note(`${unaccounted.length} of ${pkgs.length} packages unaccounted for ` +
         `at tree size ${D.snapshot.tree_size}:`);
    for (const u of unaccounted.slice(0, 5)) note(`    ${u}`);
  }
  if (b.status === 'published' && unaccounted.length) {
    problems.push(`${b.label}: marked published but ${unaccounted.length} missing`);
  }
  if (b.status === 'unpublished' && !unaccounted.length) {
    problems.push(`${b.label}: marked unpublished but everything is in the log`);
  }
 } catch (e) {
   // A verifier that crashes tells the reader nothing. Every failure has to
   // come out as a reported problem.
   problems.push(`${b.label}: ${e && e.message ? e.message : e}`);
 }
}

console.log('');
if (problems.length) {
  console.log(`BUNDLE INVALID — ${problems.length} problem(s):`);
  for (const p of problems) console.log('  ! ' + p);
  process.exit(1);
}
console.log('bundle OK — every claim above was recomputed locally, ' +
            'nothing was asked of a server');
