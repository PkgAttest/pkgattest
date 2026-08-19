# Trim swtpm for the BMC image: openssl only. Drops the gnutls PACKAGECONFIG
# whose RDEPENDS (gnutls-bin, expect, tpm2-pkcs11-tools) bloat the image; the
# demo does not use swtpm_cert/local CA provisioning.
PACKAGECONFIG = "openssl"

# swtpm_localca.c includes gmp.h unconditionally; with gnutls enabled gmp
# arrives transitively (gnutls -> nettle -> gmp), so declare it directly.
DEPENDS += "gmp"

# The shipped installed-tests use bash; with gnutls the bash RDEPENDS came
# along via that PACKAGECONFIG. bash is in the BMC image regardless.
RDEPENDS:${PN} += "bash"
