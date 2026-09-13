"""Hold the engine image to what the design states, from the filesystem
the container runtime itself unpacked -- `docker export` of a container
created from the image, one flat archive with every layer applied by the
unpacker that will run it -- rather than from a model of the layers, so
that what is judged is what runs and a bypass would have to be the
unpacker's own.

What is held: the gateway binary carries exactly CAP_SETUID, CAP_SETGID
and CAP_KILL (permitted and effective, nothing inheritable, in the v2 or
the v3 attribute) and is the signer's alone (uid 65532, mode 0700);
nothing else in the image carries a capability or a set-user-id or
set-group-id bit, hard links included; every path the engine or a
platform user executes or reads -- the gateway, the adapters, the
catalog, the corpus, the passwd file -- and every home is reached through
directories owned by root that nobody else may write, with no link on the
way; the adapters, the catalog and the corpus are root's and unwritable
by others, the last two byte for byte the checkout's; every home is its
user's alone at 0700; the users are in /etc/passwd with their uids; the
helper that made the homes is gone; and the image's configuration starts
the gateway as engine with serve --config /etc/engine/engine.json.

Usage: image_checks.py <export.tar> <image config json> <repository checkout>
The invariants are each held by a negative case in test_image_checks.py.
"""
import json, os, posixpath, struct, sys, tarfile


class Failure(Exception):
    pass


def fail(message):
    raise Failure("image check: " + message)


class Entry:
    def __init__(self, member):
        self.member = member
        self.type, self.mode, self.uid, self.gid = member.type, member.mode & 0o7777, member.uid, member.gid
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

    @property
    def ishardlink(self):
        return self.type == tarfile.LNKTYPE


def normalise(name):
    name = name.strip("/")
    if name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return ""
    if posixpath.normpath(name) != name or ".." in name.split("/"):
        fail("the export names %r, which is not a normalised path" % name)
    return name


def read_export(path):
    """path -> Entry for the exported filesystem, plus the archive."""
    t = tarfile.open(path, "r:*")
    fs = {}
    for m in t.getmembers():
        name = normalise(m.name)
        if name == "":
            continue
        if name in fs:
            fail("the export names %s twice" % name)
        fs[name] = Entry(m)
    # A hard link is the same inode as its target: it carries the target's
    # bits, and any privilege the link's own header claims is refused as a
    # header the unpacker would have applied to the shared inode.
    for name, e in list(fs.items()):
        if e.ishardlink:
            target = normalise(e.member.linkname)
            if target not in fs:
                fail("%s hard-links %s, which is not in the export" % (name, target))
            fs[name] = fs[target]
    return fs, t


def decode_capability(data):
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


def content(fs, archive, name):
    e = entry(fs, name)
    if not e.isfile:
        fail("%s is not a regular file" % name)
    return archive.extractfile(e.member.name).read()


def trusted_path(fs, name):
    """Every directory on the way to name, and name itself, is root's and
    writable by root alone, none of them a link: what a platform user
    reaches under this name is what root put there, and nobody can rename
    it away."""
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


HOMES = {"home/engine": 65532}
HOMES.update({"home/engine-%d" % n: 65600 + n for n in range(1, 9)})
USERS = {"engine": 65532, **{"engine-%d" % n: 65600 + n for n in range(1, 9)}}
GATEWAY = "usr/local/bin/gateway"
ADAPTERS = ("usr/local/bin/adapter-airbyte", "usr/local/bin/adapter-mcp")


def check(fs, archive, config, checkout):
    trusted_path(fs, posixpath.dirname(GATEWAY))
    g = entry(fs, GATEWAY)
    if not g.isfile:
        fail("the gateway binary is not a regular file")
    if g.capability is None:
        fail("the gateway binary carries no capability attribute")
    decoded = decode_capability(g.capability)
    if decoded["permitted"] != 1 << 5 | 1 << 6 | 1 << 7 or decoded["inheritable"] != 0 or not decoded["effective"] or decoded["rootid"] != 0:
        fail("the gateway binary's capabilities are %r, not permitted and effective CAP_KILL, CAP_SETGID, CAP_SETUID with nothing inheritable and a root id of 0" % decoded)
    if g.mode != 0o700 or g.uid != 65532 or g.gid != 65532:
        fail("the gateway binary is mode %04o owned by %d:%d; it must be 0700 and the signer's (65532), since it carries file capabilities" % (g.mode, g.uid, g.gid))
    for name, e in fs.items():
        if name != GATEWAY and e.capability is not None:
            fail("%s carries a capability attribute; only the gateway binary may" % name)
        if not e.isdir and not e.islink and e.mode & 0o6000:
            fail("%s is set-user-id or set-group-id (mode %04o); nothing in the image may be" % (name, e.mode))
    trusted_path(fs, "home")
    for name, uid in HOMES.items():
        e = entry(fs, name)
        if not e.isdir or e.mode != 0o700 or e.uid != uid or e.gid != uid:
            fail("%s is type %r mode %04o uid %d gid %d; it must be a directory, 0700, owned by %d:%d" % (name, e.type, e.mode, e.uid, e.gid, uid, uid))
    if any(name == "mkhomes" or name.endswith("/mkhomes") for name in fs):
        fail("the mkhomes helper is still in the image")
    for name in ADAPTERS:
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
                there = "usr/share/engine/%s/%s" % (top, os.path.relpath(here, root).replace(os.sep, "/"))
                trusted_path(fs, there)
                if content(fs, archive, there) != open(here, "rb").read():
                    fail("%s differs from %s" % (there, here))
    trusted_path(fs, "etc/passwd")
    passwd = {line.split(":")[0]: int(line.split(":")[2]) for line in content(fs, archive, "etc/passwd").decode().splitlines() if line.count(":") >= 6}
    for user, uid in USERS.items():
        if passwd.get(user) != uid:
            fail("/etc/passwd names %s as uid %s, not %d" % (user, passwd.get(user), uid))
    if config.get("Entrypoint") != ["/usr/local/bin/gateway"] or config.get("Cmd") != ["serve", "--config", "/etc/engine/engine.json"] or config.get("User") not in ("engine", "65532"):
        fail("the image starts %r %r as %r" % (config.get("Entrypoint"), config.get("Cmd"), config.get("User")))
    return "the image holds: gateway with exactly CAP_SETUID, CAP_SETGID, CAP_KILL, 0700, engine's, on a root-owned path; nothing else privileged; %d homes at 0700 under a root-owned /home; adapters, catalog and corpus root's, unwritable by others, as in the checkout; users; entrypoint and command" % len(HOMES)


def load_config(path):
    """The image configuration as `docker image inspect` prints it (a list
    of one) or as an OCI config blob."""
    data = json.load(open(path))
    if isinstance(data, list):
        data = data[0]
    return data.get("Config") or data.get("config")


def main(export, config_path, checkout):
    fs, archive = read_export(export)
    return check(fs, archive, load_config(config_path), checkout)


if __name__ == "__main__":
    try:
        print(main(sys.argv[1], sys.argv[2], sys.argv[3]))
    except Failure as failure:
        sys.exit(str(failure))
