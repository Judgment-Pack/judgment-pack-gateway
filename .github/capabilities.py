"""Hold the gateway binary inside a saved image to exactly the file
capabilities the design states: CAP_SETUID, CAP_SETGID and CAP_KILL,
permitted and effective, nothing inheritable -- and, since it carries
them, to the signer's ownership and a mode nobody else may execute. The
attribute travels in the layer's pax headers; extracting the file to a
host would drop it, so the headers are read as they are."""
import sys, tarfile, os, glob

image_dir = sys.argv[1]
# VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, permitted = 1<<7 | 1<<6 | 1<<5, inheritable 0
want = bytes.fromhex("01000002e0000000000000000000000000000000")
found = None
mode, uid = None, None
for layer in glob.glob(os.path.join(image_dir, "blobs", "sha256", "*")) + glob.glob(os.path.join(image_dir, "*", "layer.tar")):
    try:
        t = tarfile.open(layer)
    except tarfile.ReadError:
        continue
    for m in t.getmembers():
        if m.name.rstrip("/") == "usr/local/bin/gateway":
            raw = m.pax_headers.get("SCHILY.xattr.security.capability")
            found = raw.encode("utf-8", "surrogateescape") if raw is not None else b""
            mode, uid = m.mode & 0o7777, m.uid
if found is None:
    sys.exit("the gateway binary is not in the image")
if found != want:
    sys.exit("the gateway binary's file capabilities are %s, not %s" % (found.hex(), want.hex()))
if mode != 0o700 or uid != 65532:
    sys.exit("the gateway binary is mode %04o owned by uid %s; it must be 0700 and the signer's (65532), since it carries file capabilities" % (mode, uid))
print("gateway holds cap_setuid, cap_setgid, cap_kill as permitted and effective, nothing inheritable; mode 0700, owned by engine")
