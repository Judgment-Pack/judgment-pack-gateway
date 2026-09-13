"""Hold a saved engine image to what the design states, from the image's
own layers applied in the order its manifest gives them -- as an unpacker
would: names normalised, a whiteout removing what earlier layers put there
and never what its own layer adds, a path replaced by a file or a link
losing its descendants, a hard link sharing its target's bits -- and never
from a glob or a copy to the host.

What is held: the gateway binary carries exactly CAP_SETUID, CAP_SETGID
and CAP_KILL (permitted and effective, nothing inheritable, in the v2 or
the v3 attribute) and is the signer's alone (uid 65532, mode 0700); nothing
else in the image carries a capability or a set-user-id or set-group-id
bit, hard links included; every path the engine or a platform user
executes or reads -- the gateway, the adapters, the catalog, the corpus --
is reached through directories owned by root that nobody else may write,
with no link on the way, and is itself root's and unwritable by others;
every home is its user's alone at 0700; the users are in /etc/passwd with
their uids; the helper that made the homes is gone; and the image starts
the gateway as engine with serve --config /etc/engine/engine.json.

Usage: image_checks.py <dir of docker save, extracted> <repository checkout>
The layer semantics are exercised by test_image_checks.py.
"""
import json, os, posixpath, struct, sys, tarfile


class Failure(Exception):
    pass


def fail(message):
    raise Failure("image check: " + message)


def normalise(name):
    """A tar name as an unpacker reads it: no leading "./" or "/", no
    trailing "/", no "." or ".." components, or else refused -- never by
    stripping characters, which would eat the dot a whiteout starts with."""
    name = name.strip("/")
    if name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return ""
    normalised = posixpath.normpath(name)
    parts = normalised.split("/")
    if normalised != name or ".." in parts or "." in parts:
        fail("a layer names %r, which is not a normalised path" % name)
    return normalised


class Entry:
    """One path of the final filesystem: its tar member's bits, and for a
    hard link its target's, since they are one inode."""

    def __init__(self, member, layer):
        self.type, self.mode, self.uid, self.gid = member.type, member.mode & 0o7777, member.uid, member.gid
        self.layer, self.member = layer, member
        raw = member.pax_headers.get("SCHILY.xattr.security.capability")
        self.capability = raw.encode("utf-8", "surrogateescape") if raw is not None else None

    @property
    def isdir(self):
        return self.type == tarfile.DIRTYPE

    @property
    def isfile(self):
        return self.type in (tarfile.REGTYPE, tarfile.AREGTYPE)

    @property
    def islink(self):
        return self.type == tarfile.SYMTYPE


def apply_layers(image_dir, layers):
    """The final filesystem, path -> Entry, from the layers in manifest
    order. Within a layer, whiteouts are applied to what earlier layers
    left before the layer's own additions land, whatever order the archive
    lists them in (OCI layer spec, "Whiteouts")."""
    fs = {}
    for layer in layers:
        path = os.path.join(image_dir, layer)
        try:
            t = tarfile.open(path, "r:*")
        except tarfile.ReadError:
            fail("layer %s is not a tar archive" % layer)
        members = [(normalise(m.name), m) for m in t.getmembers()]
        members = [(n, m) for n, m in members if n != ""]
        # 1. The layer's whiteouts, against the filesystem so far.
        for name, m in members:
            base, parent = posixpath.basename(name), posixpath.dirname(name)
            if base == ".wh..wh..opq":
                for existing in [p for p in fs if parent == "" or p.startswith(parent + "/")]:
                    if existing != parent:
                        del fs[existing]
            elif base.startswith(".wh."):
                target = posixpath.join(parent, base[len(".wh."):])
                for existing in [p for p in fs if p == target or p.startswith(target + "/")]:
                    del fs[existing]
        # 2. The layer's additions. A path that replaces a directory with
        # anything else, or a directory with a directory, keeps or loses its
        # descendants as an unpacker would: only a directory keeps them.
        for name, m in members:
            base = posixpath.basename(name)
            if base.startswith(".wh."):
                continue
            if m.type == tarfile.LNKTYPE:
                target = normalise(m.linkname)
                if target not in fs:
                    fail("layer %s hard-links %s to %s, which is not in the image" % (layer, name, target))
                entry = Entry(fs[target].member, fs[target].layer)
                entry.type = fs[target].type
            else:
                entry = Entry(m, path)
            if name in fs and fs[name].isdir and not entry.isdir:
                for existing in [p for p in fs if p.startswith(name + "/")]:
                    del fs[existing]
            fs[name] = entry
    return fs


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


def entry(fs, name):
    if name not in fs:
        fail("%s is not in the image" % name)
    return fs[name]


def content(fs, name):
    e = entry(fs, name)
    if not e.isfile:
        fail("%s is not a regular file" % name)
    with tarfile.open(e.layer, "r:*") as t:
        return t.extractfile(e.member.name).read()


def trusted_path(fs, name):
    """Every directory on the way to name, and name itself, is root's and
    writable by root alone, and none of them is a link: what a platform
    user reaches under this name is what root put there."""
    parts = name.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        e = entry(fs, prefix)
        if e.islink:
            fail("%s is a symbolic link; the image must not reach %s through one" % (prefix, name))
        if i < len(parts) and not e.isdir:
            fail("%s is not a directory on the way to %s" % (prefix, name))
        if e.uid != 0 or e.gid != 0 or e.mode & 0o022:
            fail("%s is uid %d gid %d mode %04o; every path to %s must be root's and unwritable by others" % (prefix, e.uid, e.gid, e.mode, name))


def check(fs, config, checkout):
    gateway = "usr/local/bin/gateway"
    # The way to the gateway is root's and unlinked before the gateway is
    # looked for: a path replaced by a link has no gateway under it, and
    # the link is the finding.
    trusted_path(fs, posixpath.dirname(gateway))
    g = entry(fs, gateway)
    if not g.isfile:
        fail("the gateway binary is not a regular file")
    if g.capability is None:
        fail("the gateway binary carries no capability attribute")
    decoded = decode_capability(g.capability)
    want_permitted = 1 << 5 | 1 << 6 | 1 << 7
    if decoded["permitted"] != want_permitted or decoded["inheritable"] != 0 or not decoded["effective"] or decoded["rootid"] != 0:
        fail("the gateway binary's capabilities are %r, not permitted and effective CAP_KILL, CAP_SETGID, CAP_SETUID with nothing inheritable and a root id of 0" % decoded)
    if g.mode != 0o700 or g.uid != 65532:
        fail("the gateway binary is mode %04o owned by uid %d; it must be 0700 and the signer's (65532), since it carries file capabilities" % (g.mode, g.uid))
    for name, e in fs.items():
        if name != gateway and e.capability is not None:
            fail("%s carries a capability attribute; only the gateway binary may" % name)
        if not e.isdir and not e.islink and e.mode & 0o6000:
            fail("%s is set-user-id or set-group-id (mode %04o); nothing in the image may be" % (name, e.mode))
    homes = {"home/engine": 65532}
    homes.update({"home/engine-%d" % n: 65600 + n for n in range(1, 9)})
    for name, uid in homes.items():
        e = entry(fs, name)
        if not e.isdir or e.mode != 0o700 or e.uid != uid or e.gid != uid:
            fail("%s is type %r mode %04o uid %d gid %d; it must be a directory, 0700, owned by %d:%d" % (name, e.type, e.mode, e.uid, e.gid, uid, uid))
    if any(name == "mkhomes" or name.endswith("/mkhomes") for name in fs):
        fail("the mkhomes helper is still in the image")
    for name in ("usr/local/bin/adapter-airbyte", "usr/local/bin/adapter-mcp"):
        trusted_path(fs, name)
        e = entry(fs, name)
        if not e.isfile or e.mode & 0o111 != 0o111:
            fail("%s is type %r mode %04o; it must be a regular file executable by every user" % (name, e.type, e.mode))
    for top in ("catalog", "corpus"):
        root = os.path.join(checkout, top)
        trusted_path(fs, "usr/share/engine/" + top)
        for dirpath, _, files in os.walk(root):
            for f in files:
                here = os.path.join(dirpath, f)
                rel = os.path.relpath(here, root).replace(os.sep, "/")
                there = "usr/share/engine/%s/%s" % (top, rel)
                trusted_path(fs, there)
                if content(fs, there) != open(here, "rb").read():
                    fail("%s differs from %s" % (there, here))
    trusted_path(fs, "etc/passwd")
    passwd = {line.split(":")[0]: int(line.split(":")[2]) for line in content(fs, "etc/passwd").decode().splitlines() if line.count(":") >= 6}
    for user, uid in {"engine": 65532, **{"engine-%d" % n: 65600 + n for n in range(1, 9)}}.items():
        if passwd.get(user) != uid:
            fail("/etc/passwd names %s as uid %s, not %d" % (user, passwd.get(user), uid))
    if config.get("Entrypoint") != ["/usr/local/bin/gateway"] or config.get("Cmd") != ["serve", "--config", "/etc/engine/engine.json"] or config.get("User") not in ("engine", "65532"):
        fail("the image starts %r %r as %r" % (config.get("Entrypoint"), config.get("Cmd"), config.get("User")))
    return "the image holds: gateway with exactly CAP_SETUID, CAP_SETGID, CAP_KILL, 0700, engine's, on a root-owned path; nothing else privileged; %d homes at 0700; adapters, catalog and corpus root's, unwritable by others, as in the checkout; users; entrypoint and command" % len(homes)


def main(image_dir, checkout):
    manifest = json.load(open(os.path.join(image_dir, "manifest.json")))
    if len(manifest) != 1:
        fail("the save holds %d images, not one" % len(manifest))
    fs = apply_layers(image_dir, manifest[0]["Layers"])
    config = json.load(open(os.path.join(image_dir, manifest[0]["Config"])))["config"]
    return check(fs, config, checkout)


if __name__ == "__main__":
    try:
        print(main(sys.argv[1], sys.argv[2]))
    except Failure as failure:
        sys.exit(str(failure))
