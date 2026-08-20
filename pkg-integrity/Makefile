PY      := .venv/bin/python3
PIP     := .venv/bin/pip
PYTEST  := .venv/bin/pytest
HOST    ?= raspberrypi3-64.local
A_MEAS  := artifacts/A/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json
SSH     := ssh -i keys/id_ed25519 -o UserKnownHostsFile=keys/known_hosts \
           -o StrictHostKeyChecking=no -o LogLevel=ERROR root@$(HOST)

.PHONY: venv keys test log publish trust-device wait-device xcheck \
        beat1 beat2 beat3 beat4 closer qr freeze e2e-sim build-a build-b \
        build-c publish-c log-writable site site-verify site-check \
        site-serve vendor-crypto check-vendor parity

venv:
	python3 -m venv .venv
	$(PIP) install -q -r requirements.txt
	$(PIP) install -q -e .

keys:
	@test -f keys/konasense-demo.priv || (umask 077 && \
	  openssl genrsa -out keys/konasense-demo.priv 4096)
	@openssl pkey -in keys/konasense-demo.priv -pubout \
	  -out keys/build-rsa4096.pub.pem
	@test -f keys/log_ed25519.key || (umask 077 && \
	  openssl genpkey -algorithm ed25519 -out keys/log_ed25519.key)
	@openssl pkey -in keys/log_ed25519.key -pubout -out keys/log_ed25519.pub
	@test -f keys/id_ed25519 || ssh-keygen -t ed25519 -N '' -q \
	  -f keys/id_ed25519 -C pkg-integrity-demo
	@cp keys/id_ed25519.pub \
	  ../meta-pkg-integrity/recipes-security/pkg-witness/files/authorized_keys
	@echo "keys ready (authorized_keys synced into the layer)"

test:
	$(PYTEST) -q tests

# Read-only: this is what runs during the demo. Publishing needs log-writable.
log:
	$(PY) log_server.py

log-writable:
	$(PY) log_server.py --writable

publish:
	$(PY) publish.py --measurements $(A_MEAS)

build-a:
	./build-image.sh A

build-b:
	./build-image.sh B

# Image C: a later build of the same line. Publishing it gives the log a
# second signed tree head, which consistency proofs require.
build-c:
	./build-image.sh C

publish-c:
	$(PY) publish.py --measurements artifacts/C/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json

# Optional if the baked key ever fails: push the ssh key by password.
trust-device:
	ssh-copy-id -i keys/id_ed25519.pub root@$(HOST)

wait-device:
	@echo "waiting for measurement agent on $(HOST)..."
	@until $(SSH) test -e /run/pkg-integrity/done 2>/dev/null; do \
	  sleep 3; printf .; done; echo
	@$(SSH) cat /run/pkg-integrity/status /run/pkg-integrity/root.hex

xcheck:
	@echo "three-way root agreement (build / device / fetched):"
	@$(PY) -c "import json;print('build  ', json.load(open('$(A_MEAS)'))['merkle_root'])"
	@$(SSH) cat /run/pkg-integrity/root.hex | sed 's/^/device /'
	@$(SSH) cat /run/pkg-integrity/measurement-list > /tmp/pkgi-ml
	@$(PY) -c "import sys; sys.path.insert(0,'.'); \
	  from pkgintegrity import canonical; \
	  pkgs=canonical.parse_measurement_list(open('/tmp/pkgi-ml','rb').read()); \
	  print('fetched', canonical.device_tree_root(pkgs), '(%d pkgs)'%len(pkgs))"

beat1 beat2 beat3 beat4 closer qr:
	@bash demo/$@.sh

freeze:
	@bash demo/beat3.sh | tee demo/frames/beat3.txt

e2e-sim:
	@bash sim/e2e-sim.sh

# ---- static site ---------------------------------------------------------
# The bundle is deterministic on purpose: site-verify builds it twice into
# temp dirs and diffs, so the published bytes are reproducible by anyone.

site:
	@$(PY) -c "import os,sys,json; sys.path.insert(0,'.'); \
	  from pkgintegrity import site_export; \
	  print(json.dumps(site_export.export(os.path.abspath('.'), \
	    os.path.abspath('site-dist')), indent=1))"
	@echo "site-dist/ ready — open site-dist/index.html or 'make site-serve'"

site-verify:
	@rm -rf .site-a .site-b
	@$(PY) -c "import os,sys; sys.path.insert(0,'.'); \
	  from pkgintegrity import site_export; \
	  site_export.export(os.path.abspath('.'), os.path.abspath('.site-a')); \
	  site_export.export(os.path.abspath('.'), os.path.abspath('.site-b'))"
	@diff -r .site-a .site-b && echo "deterministic: two exports are identical"
	@rm -rf .site-a .site-b

# Check the bundle the way a browser will: rebuild every tree, verify every
# signature, name any unpublished package. Needs node (test-only dependency).
site-check: site
	@command -v node >/dev/null && node tools/verify-bundle.js site-dist \
	  || echo "node not found — skipping the browser-path check"

site-serve: site
	$(PY) log_server.py --site site-dist

# ---- vendored browser crypto --------------------------------------------
vendor-crypto:
	$(PY) tools/vendor_crypto.py --fetch

check-vendor:
	@$(PY) tools/vendor_crypto.py --check

parity:
	@$(PYTEST) -q tests/test_js_parity.py
