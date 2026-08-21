/* render-check.js -- run the page's own app.js against a minimal DOM and
 * report what it rendered.
 *
 *   node tools/render-check.js site-dist [--hash '#/limits']
 *                                       [--break sha256|sha512|ed25519]
 *
 * The point is not to check pixels. It is to check the two rules the page is
 * supposed to enforce -- that a verdict is never drawn on top of a failed
 * self-test, and that every value shown was recomputed here -- without
 * needing a browser in the loop. `--break` swaps in a deliberately broken
 * primitive so the refusal path is exercised too.
 *
 * The shim is only as complete as app.js needs. If app.js starts using a DOM
 * feature this does not implement, this fails loudly rather than silently
 * skipping the check.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const args = process.argv.slice(2);
const dist = args.find(a => !a.startsWith('--')) || 'site-dist';
const breakIdx = args.indexOf('--break');
const breakName = breakIdx >= 0 ? args[breakIdx + 1] : null;
const hashIdx = args.indexOf('--hash');
const startHash = hashIdx >= 0 ? args[hashIdx + 1] : '';

function makeNode(tag) {
  return {
    tagName: String(tag).toUpperCase(),
    className: '',
    children: [],
    _text: null,
    style: new Proxy({}, {
      set() { throw new Error('app.js set an inline style; the CSP forbids it'); }
    }),
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() {
      if (this._text !== null) return this._text;
      return this.children.map(c => c.textContent).join('');
    },
    set innerHTML(v) { throw new Error('app.js used innerHTML'); },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) {
      const i = this.children.indexOf(c);
      if (i >= 0) this.children.splice(i, 1);
      return c;
    },
    get firstChild() { return this.children[0] || null; },
  };
}

/* Render the tree as text, one line per block-ish element, so assertions can
 * be made about what a reader actually sees. */
function toLines(node, out = [], depth = 0) {
  if (node._text !== null) {
    const t = node._text.trim();
    if (t) out.push(t);
    return out;
  }
  for (const c of node.children) toLines(c, out, depth + 1);
  return out;
}

const view = makeNode('main');
const head = makeNode('head');
const pending = [];

const document = {
  createElement: makeNode,
  createTextNode(t) { const n = makeNode('#text'); n.textContent = t; return n; },
  getElementById: id => (id === 'view' ? view : null),
  head,
};

// Scripts injected by app.js are loaded straight off disk, in order.
head.appendChild = function (node) {
  this.children.push(node);
  if (node.tagName === 'SCRIPT' && node.src) pending.push(node);
  return node;
};

const listeners = {};
const win = {
  document,
  location: { hash: startHash },
  performance: { now: () => Number(process.hrtime.bigint()) / 1e6 },
  scrollTo() {},
  addEventListener(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
};
win.window = win;

const ctx = vm.createContext(Object.assign(win, { TextEncoder, TextDecoder, console }));

function load(rel) {
  vm.runInContext(fs.readFileSync(path.resolve(dist, rel), 'utf8'), ctx,
                  { filename: rel });
}

load('vendor/pkgcrypto.js');

if (breakName) {
  const broken = {
    sha256: '(b) => new Uint8Array(32)',
    sha512: '(b) => new Uint8Array(64)',
    ed25519: '() => false',
  }[breakName];
  if (!broken) throw new Error('unknown --break target: ' + breakName);
  vm.runInContext(`
    var __real = PKGI_CRYPTO;
    PKGI_CRYPTO = {
      sha256: ${breakName === 'sha256' ? broken : '__real.sha256'},
      sha512: ${breakName === 'sha512' ? broken : '__real.sha512'},
      ed25519Verify: ${breakName === 'ed25519' ? broken : '__real.ed25519Verify'},
    };`, ctx);
}

load('verify.js');
for (const f of ['data/snapshot.js', 'data/sth-history.js',
                 'data/builds-index.js']) load(f);
load('app.js');

// Drain the scripts app.js asked for, firing onload as a browser would.
let guard = 0;
while (pending.length) {
  if (++guard > 200) throw new Error('script loading did not settle');
  const node = pending.shift();
  try {
    load(node.src);
    node.onload();
  } catch (e) {
    node.onerror ? node.onerror() : (() => { throw e; })();
  }
}

const lines = toLines(view);
console.log(lines.join('\n'));
console.log('\n--- render-check ---');
console.log('lines rendered:', lines.length);
