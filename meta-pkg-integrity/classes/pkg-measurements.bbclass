# pkg-measurements.bbclass — per-package integrity measurement of an image.
#
# For every package installed in the image rootfs, computes a canonical leaf
# preimage (pkg-leaf-v1) over the package identity and the sha256 of each of
# its installed regular files, then composes all leaves into a merkle root
# (pkg-merkle-v1).  Three byte-identical implementations of these formats
# exist: this class, the on-target boot agent (pkg-witness, bash), and the
# host tooling (pkg-integrity/pkgintegrity/canonical.py).  The binding spec
# is pkg-integrity/SPEC.md — change nothing here without changing all three.
#
# Outputs:
#   ${IMAGE_ROOTFS}/usr/share/pkg-integrity/pkgs.tsv    name\tver\tarch
#   ${IMAGE_ROOTFS}/usr/share/pkg-integrity/files.tsv   name\tpath\tsha256
#   ${IMAGE_ROOTFS}/usr/share/pkg-integrity/root.sha256 expected merkle root
#   ${IMGDEPLOYDIR}/${IMAGE_NAME}.pkg-measurements.json full measurement set
#
# The rootfs files are deliberately unowned by any package, so they are
# structurally outside every leaf.  Leaves measure INSTALLED state (postinst-
# modified files hash as-installed); A/B image parity holds because unchanged
# packages install bit-identical ipks from the shared deploy/sstate cache.
#
# One further leaf, named "(unowned)", covers every regular file in the image
# that no package claims — /etc/passwd, /etc/shadow, /etc/ld.so.cache, the
# indexes depmod writes.  Without it those files sit in no leaf, therefore no
# device root, therefore no PCR, and adding a root user to /etc/passwd would
# change nothing the mechanism commits to.  It is an ordinary pkg-leaf-v1
# with a name no opkg package can have (opkg names cannot contain
# parentheses), so it needs no new format and sorts into place normally:
# "(" is 0x28, below every letter and digit, so it is always the first leaf.

PKG_MEASUREMENTS_DIR = "${WORKDIR}/pkg-measurements"
PKG_MEASUREMENTS_PKGLIST = "${PKG_MEASUREMENTS_DIR}/rootfs-packages.json"
# Excluded from every leaf, package or unowned: these change on every boot
# or every build, so measuring them would make the root unstable rather than
# meaningful.  This is a deliberate, named gap, not an oversight.
PKG_MEASUREMENTS_EXCLUDE ?= "/etc/machine-id /etc/version /etc/timestamp"
PKG_MEASUREMENTS_IMAGE_LINE ?= "rpi3-openbmc"
PKG_MEASUREMENTS_ROOTFS_DIR ?= "${datadir}/pkg-integrity"

# The unowned-files leaf. Constant metadata so the leaf is a pure function of
# the file set: two builds whose unowned files match produce the same leaf and
# deduplicate in the log, exactly as an unchanged package does.
PKG_MEASUREMENTS_UNOWNED_NAME ?= "(unowned)"
PKG_MEASUREMENTS_UNOWNED_VERSION ?= "1.0"
PKG_MEASUREMENTS_UNOWNED_ARCH ?= "all"

# Collect the installed-package list while the opkg DB still exists
# (do_rootfs removes it right after ROOTFS_POSTUNINSTALL_COMMAND runs;
# same pattern as spdx_collect_rootfs_packages).
python pkg_measurements_collect_packages() {
    import json
    import os
    from oe.rootfs import image_list_installed_packages

    out = d.getVar("PKG_MEASUREMENTS_PKGLIST")
    packages = image_list_installed_packages(d) or {}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(packages, f)
}
ROOTFS_POSTUNINSTALL_COMMAND =+ "pkg_measurements_collect_packages "

def pkg_measurements_merkle_root(leaves):
    # pkg-merkle-v1: pair nodes sha256("pkg-node-v1\n<Lhex>\n<Rhex>\n"),
    # odd node promoted; leaves already sorted by package name.
    import hashlib
    if not leaves:
        bb.fatal("pkg-measurements: no leaves to hash")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            data = "pkg-node-v1\n%s\n%s\n" % (level[i], level[i + 1])
            nxt.append(hashlib.sha256(data.encode("ascii")).hexdigest())
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]

fakeroot python do_pkg_measurements() {
    import hashlib
    import json
    import os
    import stat
    import oe.packagedata

    rootfs = d.getVar("IMAGE_ROOTFS")
    pkgdata_dir = d.getVar("PKGDATA_DIR")
    exclude = set((d.getVar("PKG_MEASUREMENTS_EXCLUDE") or "").split())

    with open(d.getVar("PKG_MEASUREMENTS_PKGLIST")) as f:
        installed = json.load(f)
    if not installed:
        bb.fatal("pkg-measurements: empty installed-package list")

    def files_info(pkg):
        fn = os.path.join(pkgdata_dir, "runtime-reverse", pkg)
        if not os.path.exists(fn):
            return None
        data = oe.packagedata.read_pkgdatafile(fn)
        for key, value in data.items():
            if key.split(":")[0] == "FILES_INFO":
                return json.loads(value)
        return {}

    def sha256_file(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    packages = []
    missing_pkgdata = []
    for name in sorted(installed.keys()):
        info = installed[name]
        ver = info.get("ver") or ""
        arch = info.get("arch") or ""
        fi = files_info(name)
        if fi is None:
            missing_pkgdata.append(name)
            fi = {}
        files = []
        for path in fi.keys():
            # Paths are UTF-8; python sorted() (codepoint order) matches
            # LC_ALL=C byte sort because UTF-8 is order-preserving. Newline
            # breaks the preimage framing, tab breaks files.tsv.
            if "\n" in path or "\t" in path:
                bb.fatal("pkg-measurements: newline/tab in path %r (pkg %s)" % (path, name))
            if path in exclude:
                continue
            fs_path = rootfs + path
            try:
                st = os.lstat(fs_path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            files.append((path, sha256_file(fs_path)))
        lines = sorted("%s %s" % (p, h) for p, h in files)
        preimage = "pkg-leaf-v1\nname=%s\nversion=%s\narch=%s\nfiles=%d\n" % (
            name, ver, arch, len(lines)) + "".join(l + "\n" for l in lines)
        leaf = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        packages.append({
            "name": name,
            "version": ver,
            "arch": arch,
            "leaf_hash": leaf,
            "files": [{"path": p, "sha256": h} for p, h in
                      sorted(files, key=lambda x: x[0])],
        })

    if missing_pkgdata:
        bb.warn("pkg-measurements: no pkgdata for %d packages (measured with "
                "empty file list): %s" % (len(missing_pkgdata),
                                          " ".join(missing_pkgdata[:10])))

    # ---- the files no package owns --------------------------------------
    # Walked before the agent inputs below are written, so those three files
    # do not exist yet; the on-device agent must skip that directory
    # explicitly, since by then they do.
    owned = set()
    for p in packages:
        for e in p["files"]:
            owned.add(e["path"])
    share_rel = d.getVar("PKG_MEASUREMENTS_ROOTFS_DIR")

    unowned = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            path = "/" + os.path.relpath(full, rootfs)
            if path in owned or path in exclude:
                continue
            if path == share_rel or path.startswith(share_rel + "/"):
                continue
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                continue
            if "\n" in path or "\t" in path:
                bb.fatal("pkg-measurements: newline/tab in unowned path %r"
                         % path)
            unowned.append((path, sha256_file(full)))

    u_name = d.getVar("PKG_MEASUREMENTS_UNOWNED_NAME")
    u_ver = d.getVar("PKG_MEASUREMENTS_UNOWNED_VERSION")
    u_arch = d.getVar("PKG_MEASUREMENTS_UNOWNED_ARCH")
    u_lines = sorted("%s %s" % (p, h) for p, h in unowned)
    u_preimage = "pkg-leaf-v1\nname=%s\nversion=%s\narch=%s\nfiles=%d\n" % (
        u_name, u_ver, u_arch, len(u_lines)) + "".join(
        l + "\n" for l in u_lines)
    packages.append({
        "name": u_name,
        "version": u_ver,
        "arch": u_arch,
        "leaf_hash": hashlib.sha256(u_preimage.encode("utf-8")).hexdigest(),
        "files": [{"path": p, "sha256": h} for p, h in
                  sorted(unowned, key=lambda x: x[0])],
    })
    bb.plain("pkg-measurements: %d files owned by no package" % len(unowned))

    # pkg-merkle-v1 wants leaves in bytewise name order, and "(unowned)"
    # sorts ahead of every package name.
    packages.sort(key=lambda p: p["name"])

    root = pkg_measurements_merkle_root([p["leaf_hash"] for p in packages])
    bb.plain("pkg-measurements: %d packages, merkle root %s" %
             (len(packages), root))

    # Bake the agent inputs into the rootfs (unowned by any package).
    share = rootfs + d.getVar("PKG_MEASUREMENTS_ROOTFS_DIR")
    os.makedirs(share, exist_ok=True)
    with open(os.path.join(share, "pkgs.tsv"), "w") as f:
        for p in packages:
            f.write("%s\t%s\t%s\n" % (p["name"], p["version"], p["arch"]))
    with open(os.path.join(share, "files.tsv"), "w") as f:
        for p in packages:
            for e in p["files"]:
                f.write("%s\t%s\t%s\n" % (p["name"], e["path"], e["sha256"]))
    with open(os.path.join(share, "root.sha256"), "w") as f:
        f.write(root + "\n")

    # Deploy the full measurement set for the host publisher/verifier.
    doc = {
        "schema": "pkg-measurements-v1",
        "image_line": d.getVar("PKG_MEASUREMENTS_IMAGE_LINE"),
        "machine": d.getVar("MACHINE"),
        "image_name": d.getVar("IMAGE_NAME"),
        "version": d.getVar("DISTRO_VERSION"),
        "timestamp": d.getVar("DATETIME"),
        "merkle_root": root,
        "packages": packages,
    }
    deploydir = d.getVar("IMGDEPLOYDIR")
    name = d.getVar("IMAGE_NAME") + ".pkg-measurements.json"
    link = d.getVar("IMAGE_LINK_NAME")
    os.makedirs(deploydir, exist_ok=True)
    with open(os.path.join(deploydir, name), "w") as f:
        json.dump(doc, f, indent=1)
    if link:
        lnk = os.path.join(deploydir, link + ".pkg-measurements.json")
        if os.path.lexists(lnk):
            os.unlink(lnk)
        os.symlink(name, lnk)
}
addtask do_pkg_measurements after do_rootfs before do_image
do_pkg_measurements[depends] += "virtual/fakeroot-native:do_populate_sysroot"
do_pkg_measurements[dirs] = "${PKG_MEASUREMENTS_DIR}"
do_pkg_measurements[vardepsexclude] += "DATETIME"
