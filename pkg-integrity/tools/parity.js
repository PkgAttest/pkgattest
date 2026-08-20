/* parity.js — prove the browser verifier agrees with the Python one.
 *
 * Reads a vector file produced by tests/test_js_parity.py (or by
 * `make parity`) and re-derives every value with site/verify.js. Any
 * disagreement between the two implementations is a spec violation, not a
 * test-tuning problem: pkg-integrity/SPEC.md is binding on both.
 *
 *   node tools/parity.js <vectors.json>
 *
 * Exits 0 when every check matches, 1 otherwise, printing each failure.
 */
'use strict';

const path = require('path');
const fs = require('fs');

const V = require(path.join(__dirname, '..', 'site', 'verify.js'));

const vectors = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const failures = [];
let checks = 0;

function check(name, got, want) {
  checks++;
  if (got !== want) {
    failures.push(`${name}\n    got  ${got}\n    want ${want}`);
  }
}

// --- primitives ------------------------------------------------------------
for (const p of V.selfTest()) failures.push(`selfTest: ${p}`);
checks++;

// --- pkg-leaf-v1 preimages (UTF-8; the ca-certificates path lives here) ----
for (const pkg of vectors.packages || []) {
  const pre = V.pkgLeafPreimage(pkg);
  check(`preimage bytes ${pkg.name}`, V.hex(pre), pkg.preimage_hex);
  check(`pkg leaf hash ${pkg.name}`, V.pkgLeafHash(pkg), pkg.leaf_hash);
}

// --- device tree -----------------------------------------------------------
for (const d of vectors.device_trees || []) {
  check(`device root ${d.label}`, V.deviceRoot(d.leaf_hashes), d.root);
  check(`pcr14 ${d.label}`, V.expectedPcr14(d.root), d.pcr14);
}

// --- log-leaf-v1 canonical JSON -------------------------------------------
const leafHashes = [];
for (const rec of vectors.log_records || []) {
  const data = V.logLeafData(rec);
  check(`log leaf bytes #${rec.index}`, V.hex(data), rec.data_hex);
  const lh = V.leafHash(data);
  check(`log leaf hash #${rec.index}`, V.hex(lh), rec.leaf_hash);
  leafHashes.push(lh);
}

// --- RFC 6962 tree, proofs, consistency ------------------------------------
for (const h of vectors.heads || []) {
  check(`mth(${h.tree_size})`, V.hex(V.mth(leafHashes, h.tree_size)),
        h.root_hash);
  checks++;
  if (!V.verifySth(V.unhex(vectors.log_pubkey_hex), h)) {
    failures.push(`STH signature at size ${h.tree_size} failed to verify`);
  }
  // A tampered head must be rejected.
  checks++;
  const bad = Object.assign({}, h, { timestamp: String(Number(h.timestamp) + 1) });
  if (V.verifySth(V.unhex(vectors.log_pubkey_hex), bad)) {
    failures.push(`tampered STH at size ${h.tree_size} was accepted`);
  }
}

for (const pr of vectors.inclusion || []) {
  const proof = V.inclusionProof(leafHashes, pr.index, pr.tree_size);
  check(`inclusion proof path ${pr.index}@${pr.tree_size}`,
        proof.map(V.hex).join(','), pr.path.join(','));
  checks++;
  if (!V.verifyInclusion(leafHashes[pr.index], pr.index, pr.tree_size, proof,
                         V.unhex(pr.root))) {
    failures.push(`inclusion verify failed ${pr.index}@${pr.tree_size}`);
  }
  // Wrong index must not verify.
  checks++;
  const other = pr.index === 0 ? 1 : pr.index - 1;
  if (V.verifyInclusion(leafHashes[pr.index], other, pr.tree_size, proof,
                        V.unhex(pr.root))) {
    failures.push(`inclusion verified under the wrong index ${pr.index}`);
  }
}

for (const c of vectors.consistency || []) {
  const proof = V.consistencyProof(leafHashes, c.old_size, c.new_size);
  check(`consistency proof ${c.old_size}->${c.new_size}`,
        proof.map(V.hex).join(','), c.proof.join(','));
  checks++;
  if (!V.verifyConsistency(c.old_size, c.new_size, V.unhex(c.old_root),
                           V.unhex(c.new_root), proof)) {
    failures.push(`consistency verify failed ${c.old_size}->${c.new_size}`);
  }
}

// --- edge cases the RFC gets subtly wrong if ported carelessly -------------
for (const e of vectors.mth_sizes || []) {
  const synth = e.leaves.map(V.unhex);
  check(`mth n=${e.n}`, V.hex(V.mth(synth, e.n)), e.root);
}

if (failures.length) {
  console.log(`PARITY FAILED — ${failures.length} of ${checks} checks:`);
  for (const f of failures.slice(0, 25)) console.log('  ' + f);
  if (failures.length > 25) console.log(`  ... and ${failures.length - 25} more`);
  process.exit(1);
}
console.log(`parity OK — ${checks} checks agree with the Python implementation`);
