PY      := .venv/bin/python3
PIP     := .venv/bin/pip
PYTEST  := .venv/bin/pytest
HOST    ?= raspberrypi3-64.local
A_MEAS  := artifacts/A/obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json
SSH     := ssh -i keys/id_ed25519 -o UserKnownHostsFile=keys/known_hosts \
           -o StrictHostKeyChecking=no -o LogLevel=ERROR root@$(HOST)

.PHONY: venv keys test log publish trust-device wait-device xcheck \
        beat1 beat2 beat3 beat4 closer qr freeze e2e-sim build-a build-b

venv:
	python3 -m venv .venv
	$(PIP) install -q -r requirements.txt

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

log:
	$(PY) log_server.py

publish:
	$(PY) publish.py --measurements $(A_MEAS)

build-a:
	./build-image.sh A

build-b:
	./build-image.sh B

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
