SUMMARY = "Boot-time per-package integrity measurement agent"
DESCRIPTION = "Re-hashes every installed package's files against the baked \
build manifest, composes the pkg-merkle-v1 root and extends it into TPM \
PCR 14 (swtpm via kernel vtpm-proxy). Ships the evidence-collection helper \
invoked by the host verifier over ssh, plus demo ssh/dropbear plumbing for \
the read-only rootfs."
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = " \
    file://pkg-measure.sh \
    file://collect \
    file://pkg-witness.service \
    file://etc-dropbear-tmpfs.service \
    file://authorized_keys \
    "

S = "${UNPACKDIR}"

inherit systemd

RDEPENDS:${PN} = "bash swtpm tpm2-tools"
RRECOMMENDS:${PN} = "kernel-module-tpm-vtpm-proxy"

SYSTEMD_SERVICE:${PN} = "pkg-witness.service etc-dropbear-tmpfs.service"

do_install() {
    install -d ${D}${libexecdir}/pkg-integrity
    install -m 0755 ${S}/pkg-measure.sh ${D}${libexecdir}/pkg-integrity/
    install -m 0755 ${S}/collect ${D}${libexecdir}/pkg-integrity/

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/pkg-witness.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/etc-dropbear-tmpfs.service ${D}${systemd_system_unitdir}/

    # Demo ssh access: nothing persists on the read-only wic rootfs, so the
    # verifier's public key must be baked in at build time.
    install -d -m 0700 ${D}/home/root/.ssh
    install -m 0600 ${S}/authorized_keys ${D}/home/root/.ssh/authorized_keys
    chown -R root:root ${D}/home/root
}

FILES:${PN} += "/home/root/.ssh"
