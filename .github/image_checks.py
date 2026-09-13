"""Hold a saved engine image to what the design states, from the image's
own layers applied in the order its manifest gives them (whiteouts
honoured), never from a glob or a copy to the host: the gateway binary
carries exactly CAP_SETUID, CAP_SETGID and CAP_KILL (permitted and
effective, nothing inheritable, in the v2 or the v3 attribute) and is the
signer's alone (uid 65532, mode 0700); nothing else in the image carries a
capability or a set-user-id or set-group-id bit; every home is its user's
alone at 0700; the adapters are there, executable, unprivileged; the
catalog and the corpus are byte for byte the checkout's; the users are in
/etc/passwd with their uids; and the image starts the gateway as engine
with serve --config /etc/engine/engine.json.

Usage: image_checks.py <dir of docker save, extracted> <repository checkout>
"""
import json, os, struct, sys, tarfile

image_dir, checkout = sys.argv[1], sys.argv[2]


def fail(message):
    sys.exit("image check: " + message)


manifest = json.load(open(os.path.join(image_dir, "manifest.json")))
if len(manifest) != 1:
    fail("the save holds %d images, not one" % len(manifest))
layers, config_path = manifest[0]["Layers"], manifest[0]["Config"]

# The final filesystem: path -> (layer path, tar member), applied in order.
# A whiteout removes what an earlier layer put there; an opaque whiteout
# empties a directory of everything earlier layers put in it.
fs = {}
for layer in layers:
    path = os.path.join(image_dir, layer)
    try:
        t = tarfile.open(path, "r:*")
    except tarfile.ReadError:
        fail("layer %s is not a tar archive" % layer)
    for m in t.getmembers():
        name = m.name.lstrip("./").rstrip("/")
        base, parent = os.path.basename(name), os.path.dirname(name)
        if base == ".wh..wh..opq":
            for existing in [p for p in fs if p.startswith(parent + "/")]:
                del fs[existing]
            continue
        if base.startswith(".wh."):
            target = os.path.join(parent, base[len(".wh."):]).lstrip("/")
            for existing in [p for p in fs if p == target or p.startswith(target + "/")]:
                del fs[existing]
            continue
        fs[name] = (path, m)


def entry(name):
    if name not in fs:
        fail("%s is not in the image" % name)
    return fs[name]


def content(name):
    path, m = entry(name)
    if not m.isfile():
        fail("%s is not a regular file" % name)
    with tarfile.open(path, "r:*") as t:
        return t.extractfile(m.name).read()


def capability(m):
    raw = m.pax_headers.get("SCHILY.xattr.security.capability")
    return raw.encode("utf-8", "surrogateescape") if raw is not None else None


def decode_capability(data):
    """The kernel's vfs_cap_data: magic (revision | effective flag), then
    (permitted, inheritable) as two 32-bit halves each, then for v3 the
    user-namespace root id."""
    if len(data) < 4:
        fail("a capability attribute of %d bytes" % len(data))
    magic = struct.unpack_from("<I", data, 0)[0]
    revision, effective = magic & 0xFF000000, magic & 1
    if revision == 0x02000000 and len(data) == 20:
        p0, i0, p1, i1 = struct.unpack_from("<IIII", data, 4)
        rootid = 0
    elif revision == 0x03000000 and len(data) == 24:
        p0, i0, p1, i1, rootid = struct.unpack_from("<IIIII", data, 4)
    else:
        fail("a capability attribute of revision %#x and %d bytes, which this check does not read" % (revision, len(data)))
    return {"permitted": p0 | (p1 << 32), "inheritable": i0 | (i1 << 32), "effective": bool(effective), "rootid": rootid}


# 1. The gateway binary: the three capabilities and nothing more, the
# signer's alone.
gateway = "usr/local/bin/gateway"
_, gm = entry(gateway)
if not gm.isfile():
    fail("the gateway binary is not a regular file")
caps = capability(gm)
if caps is None:
    fail("the gateway binary carries no capability attribute")
decoded = decode_capability(caps)
want_permitted = 1 << 5 | 1 << 6 | 1 << 7
if decoded["permitted"] != want_permitted or decoded["inheritable"] != 0 or not decoded["effective"] or decoded["rootid"] != 0:
    fail("the gateway binary's capabilities are %r, not permitted and effective CAP_KILL, CAP_SETGID, CAP_SETUID with nothing inheritable and a root id of 0" % decoded)
if gm.mode & 0o7777 != 0o700 or gm.uid != 65532:
    fail("the gateway binary is mode %04o owned by uid %d; it must be 0700 and the signer's (65532), since it carries file capabilities" % (gm.mode & 0o7777, gm.uid))

# 2. Nothing else privileged: no other capability attribute, no set-user-id
# or set-group-id bit anywhere.
for name, (_, m) in fs.items():
    if name != gateway and capability(m) is not None:
        fail("%s carries a capability attribute; only the gateway binary may" % name)
    if m.isfile() and m.mode & 0o6000:
        fail("%s is set-user-id or set-group-id (mode %04o); nothing in the image may be" % (name, m.mode & 0o7777))

# 3. The homes: each user's alone.
homes = {"home/engine": 65532}
homes.update({"home/engine-%d" % n: 65600 + n for n in range(1, 9)})
for name, uid in homes.items():
    _, m = entry(name)
    if not m.isdir() or m.mode & 0o7777 != 0o700 or m.uid != uid or m.gid != uid:
        fail("%s is %s mode %04o uid %d gid %d; it must be a directory, 0700, owned by %d:%d" % (name, m.type, m.mode & 0o7777, m.uid, m.gid, uid, uid))

# 4. The adapters: there, executable by the platform users, unprivileged.
for name in ("usr/local/bin/adapter-airbyte", "usr/local/bin/adapter-mcp"):
    _, m = entry(name)
    if not m.isfile() or m.mode & 0o111 != 0o111 or m.uid != 0:
        fail("%s is mode %04o uid %d; it must be a regular file executable by every user and root's" % (name, m.mode & 0o7777, m.uid))

# 5. The catalog and the corpus, byte for byte the checkout's.
for top in ("catalog", "corpus"):
    root = os.path.join(checkout, top)
    for dirpath, _, files in os.walk(root):
        for f in files:
            here = os.path.join(dirpath, f)
            rel = os.path.relpath(here, root)
            there = "usr/share/engine/%s/%s" % (top, rel)
            if content(there) != open(here, "rb").read():
                fail("%s differs from %s" % (there, here))

# 6. The users, by uid.
passwd = {line.split(":")[0]: int(line.split(":")[2]) for line in content("etc/passwd").decode().splitlines() if line.count(":") >= 6}
for user, uid in {"engine": 65532, **{"engine-%d" % n: 65600 + n for n in range(1, 9)}}.items():
    if passwd.get(user) != uid:
        fail("/etc/passwd names %s as uid %s, not %d" % (user, passwd.get(user), uid))

# 7. What the image starts: the gateway, as engine, serving the configuration.
config = json.load(open(os.path.join(image_dir, config_path)))["config"]
if config.get("Entrypoint") != ["/usr/local/bin/gateway"] or config.get("Cmd") != ["serve", "--config", "/etc/engine/engine.json"] or config.get("User") not in ("engine", "65532"):
    fail("the image starts %r %r as %r" % (config.get("Entrypoint"), config.get("Cmd"), config.get("User")))

print("the image holds: gateway with exactly CAP_SETUID, CAP_SETGID, CAP_KILL, 0700, engine's; nothing else privileged; %d homes at 0700; adapters; catalog and corpus as in the checkout; users; entrypoint and command" % len(homes))
