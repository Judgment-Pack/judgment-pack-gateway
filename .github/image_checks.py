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
runtime with its notices and conformance statement, the catalog, the corpus, the passwd file -- and
every home is reached through directories owned by root that nobody else
may write, with no link on the way; the adapters, the runtime, the
catalog and the corpus are root's and unwritable by others, the catalog
and corpus byte for byte the checkout's and the runtime byte for byte
the released binary the Dockerfile pins, when that binary is given; every
home is its user's alone at 0700; the users are in /etc/passwd with their
uids; the helper that made the homes is gone; and the image's
configuration starts the gateway as engine with serve --config
/etc/engine/engine.json.

The exporter omits the root directory itself and normalises a revision-3
capability attribute to revision 2, so two things are held elsewhere: the
root's ownership and mode by CI's write probes as a platform user and as
the signer (neither may create a top-level path), and the attribute's
revision and root id by a scan of the saved image's layer headers for
that one attribute -- every entry that carries it, in any layer, must be
the gateway with exactly the stated capabilities, which needs no model of
how the layers combine, since a later layer cannot make an earlier
attribute more than it was.

Usage: image_checks.py <export.tar> <image config json> <repository checkout> [<docker save dir> [<pinned runtime binary>]]
The invariants are each held by a negative case in test_image_checks.py.
"""
import json, os, posixpath, re, struct, sys, tarfile


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


def trusted_path(fs, name, readable=False, passable=False):
    """Every directory on the way to name, and name itself, is root's and
    writable by root alone, none of them a link: what a platform user
    reaches under this name is what root put there, and nobody can rename
    it away. Every directory on the way is passable by everyone, since the
    signer and the platform users are not root; with readable, the leaf is
    readable by everyone too."""
    parts = name.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        e = entry(fs, prefix)
        if e.islink:
            fail("%s is a symbolic link; the image must not reach %s through one" % (prefix, name))
        if i < len(parts) and not e.isdir:
            fail("%s is not a directory on the way to %s" % (prefix, name))
        if e.uid != 0:
            fail("%s is uid %d; every path to %s must be root's" % (prefix, e.uid, name))
        if e.gid != 0:
            fail("%s is gid %d; every path to %s must be root's group" % (prefix, e.gid, name))
        if e.mode & 0o022:
            fail("%s is mode %04o; every path to %s must be unwritable by others" % (prefix, e.mode, name))
        if i < len(parts) and e.mode & 0o005 != 0o005:
            fail("%s is mode %04o; every directory on the way to %s must be passable by everyone" % (prefix, e.mode, name))
        if i == len(parts) and readable and (e.mode & 0o004 == 0 or (e.isdir and e.mode & 0o001 == 0)):
            fail("%s is mode %04o; it must be readable by everyone" % (name, e.mode))
        if i == len(parts) and passable and (not e.isdir or e.mode & 0o005 != 0o005):
            fail("%s is mode %04o; it must be a directory passable by everyone" % (name, e.mode))


def canonical_lines(data, what, fields):
    """The lines of an account file, each exactly as the lookup would read
    it: no surrounding whitespace, not blank, not a comment, the stated
    number of fields, no field of a name empty."""
    out = []
    for raw in data.decode("utf-8", "surrogateescape").split("\n"):
        if raw == "":
            continue
        if raw != raw.strip() or raw.startswith("#"):
            fail("%s carries a line the lookup would read otherwise than written: %r" % (what, raw))
        parts = raw.split(":")
        if len(parts) != fields or parts[0] == "":
            fail("%s carries a line that is not %d fields with a name: %r" % (what, fields, raw))
        out.append(parts)
    return out


def canonical_id(text, what):
    """A uid or gid spelled as a number is spelled: ASCII digits, no
    leading zero, so that two spellings cannot name one id and no
    spelling passes here that the engine's lookup (strconv.Atoi) would
    refuse -- str.isdigit would take a fullwidth digit."""
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        fail("%s carries an id spelled %r, which is not a number as one is spelled" % (what, text))
    return int(text)


HOMES = {"home/engine": 65532, "home/engine-mcp": 65533}
HOMES.update({"home/engine-%d" % n: 65600 + n for n in range(1, 9)})
USERS = {"engine": 65532, "engine-mcp": 65533, **{"engine-%d" % n: 65600 + n for n in range(1, 9)}}
GATEWAY = "usr/local/bin/gateway"
# The MCP server's copy of the executable (docs/design/mcp-server.md):
# the same bytes as the signer's, root's, executable by everyone, and with
# no capability attribute, since the process that runs it holds none.
MCP = "usr/local/bin/engine-mcp"
# The MCP server's user and home, and the paths a deployment mounts a
# seed, a store, a configuration or a credential at, which the image never
# ships: what that user must not reach is held by absence where it can be,
# and by closure where a derived image might add it.
FRONTEND_UID = 65533
FRONTEND_HOME = "home/engine-mcp"
UNSHIPPED = ("etc/engine", "var/lib/engine", "run/secrets")
ADAPTERS = ("usr/local/bin/adapter-airbyte", "usr/local/bin/adapter-mcp", "usr/local/bin/adapter-http", "usr/local/bin/adapter-document")
RUNTIME = "usr/local/bin/jpack"
RUNTIME_DOCUMENTS = ("usr/share/engine/runtime/LICENSE", "usr/share/engine/runtime/NOTICE", "usr/share/engine/runtime/THIRD_PARTY_NOTICES", "usr/share/engine/runtime/CONFORMANCE.md")


def check(fs, archive, config, checkout, runtime=None):
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
    trusted_path(fs, MCP, readable=True)
    m = entry(fs, MCP)
    if not m.isfile or m.mode != 0o755 or m.uid != 0 or m.gid != 0:
        fail("%s is type %r mode %04o owned by %d:%d; it must be a regular file, 0755, root's" % (MCP, m.type, m.mode, m.uid, m.gid))
    if m.capability is not None:
        fail("%s carries a capability attribute; the MCP server holds no capability" % MCP)
    if content(fs, archive, MCP) != content(fs, archive, GATEWAY):
        fail("%s is not the gateway executable byte for byte" % MCP)
    for name, e in fs.items():
        if name != GATEWAY and e.capability is not None:
            fail("%s carries a capability attribute; only the gateway binary may" % name)
        if not e.isdir and not e.islink and e.mode & 0o6000:
            fail("%s is set-user-id or set-group-id (mode %04o); nothing in the image may be" % (name, e.mode))
    trusted_path(fs, "home", passable=True)
    for name, uid in HOMES.items():
        e = entry(fs, name)
        if not e.isdir or e.mode != 0o700 or e.uid != uid or e.gid != uid:
            fail("%s is type %r mode %04o uid %d gid %d; it must be a directory, 0700, owned by %d:%d" % (name, e.type, e.mode, e.uid, e.gid, uid, uid))
    if any(name == "mkhomes" or name.endswith("/mkhomes") for name in fs):
        fail("the mkhomes helper is still in the image")
    for name in ADAPTERS + (RUNTIME,):
        trusted_path(fs, name, readable=True)
        e = entry(fs, name)
        if not e.isfile or e.mode & 0o111 != 0o111:
            fail("%s is type %r mode %04o; it must be a regular file executable by every user" % (name, e.type, e.mode))
    # The runtime is the released binary the Dockerfile pins, byte for
    # byte, when CI hands that binary over from the pinned image; its
    # notices and its conformance statement -- the document every evaluation
    # payload points at -- are there, readable, under a root-owned directory.
    if runtime is not None and content(fs, archive, RUNTIME) != open(runtime, "rb").read():
        fail("%s differs from the pinned runtime binary" % RUNTIME)
    for name in RUNTIME_DOCUMENTS:
        trusted_path(fs, name, readable=True)
        if not entry(fs, name).isfile:
            fail("%s is not a regular file" % name)
    # The catalog and the corpus: the checkout's trees exactly -- every
    # file of the checkout there and identical, and nothing there that the
    # checkout does not have -- each entry root's, unwritable by others and
    # readable by everyone, since the signer reads them and is not root.
    for top in ("catalog", "corpus"):
        root = os.path.join(checkout, top)
        there_root = "usr/share/engine/" + top
        trusted_path(fs, there_root, readable=True)
        expected_files, expected_dirs = set(), set()
        for dirpath, dirs, files in os.walk(root):
            for d in dirs:
                rel = os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/")
                expected_dirs.add(rel)
                trusted_path(fs, there_root + "/" + rel, readable=True)
            for f in files:
                here = os.path.join(dirpath, f)
                rel = os.path.relpath(here, root).replace(os.sep, "/")
                expected_files.add(rel)
                there = there_root + "/" + rel
                trusted_path(fs, there, readable=True)
                if content(fs, archive, there) != open(here, "rb").read():
                    fail("%s differs from %s" % (there, here))
        for name, e in fs.items():
            if name.startswith(there_root + "/"):
                rel = name[len(there_root) + 1:]
                if e.isdir and rel not in expected_dirs:
                    fail("%s is a directory in the image and not in the checkout's %s" % (name, top))
                if not e.isdir and rel not in expected_files:
                    fail("%s is in the image and not in the checkout's %s" % (name, top))
    # The users, as the engine looks them up: by the first line naming
    # them, so a name or a uid twice is refused rather than read
    # last-wins; each with its own group as its primary and its home
    # under /home; and the groups the supplementary lookup reads.
    trusted_path(fs, "etc/passwd", readable=True)
    trusted_path(fs, "etc/group", readable=True)
    # The engine's lookup (Go's os/user) trims each line, skips blank and
    # comment lines, takes the first line naming a user, and reads an id
    # as a number. What is held here is stricter than what it reads: every
    # line canonical -- no surrounding whitespace, no comment, ids spelled
    # as numbers are, so no line can mean one thing to the lookup and
    # another to this check -- and no name or id twice.
    names, uids = {}, {}
    for line in canonical_lines(content(fs, archive, "etc/passwd"), "/etc/passwd", 7):
        name, uid, gid, home = line[0], canonical_id(line[2], "/etc/passwd"), canonical_id(line[3], "/etc/passwd"), line[5]
        if name in names:
            fail("/etc/passwd names %s twice" % name)
        if uid in uids:
            fail("/etc/passwd gives uid %d to %s and to %s" % (uid, uids[uid], name))
        names[name], uids[uid] = (uid, gid, home), name
    for user, uid in USERS.items():
        if user not in names:
            fail("/etc/passwd does not name %s" % user)
        got_uid, got_gid, home = names[user]
        if got_uid != uid or got_gid != uid or home != "/home/" + user:
            fail("/etc/passwd has %s as uid %d gid %d home %s; it must be uid %d, gid %d, home /home/%s" % (user, got_uid, got_gid, home, uid, uid, user))
    groups, gids = {}, {}
    for line in canonical_lines(content(fs, archive, "etc/group"), "/etc/group", 4):
        gid = canonical_id(line[2], "/etc/group")
        if line[0] in groups:
            fail("/etc/group names %s twice" % line[0])
        if gid in gids:
            fail("/etc/group gives gid %d twice" % gid)
        groups[line[0]], gids[gid] = gid, line[0]
        # the MCP server's user is in no group but its own: a member list
        # naming it would admit that process to what the group's files admit
        members = [m for m in line[3].split(",") if m]
        if "engine-mcp" in members:
            fail("/etc/group makes engine-mcp a member of %s; the MCP server's user belongs to no group but its own" % line[0])
    for user, uid in USERS.items():
        if groups.get(user) != uid:
            fail("/etc/group has %s as gid %s, not %d" % (user, groups.get(user), uid))
    closed_to_the_frontend(fs)
    if config.get("Entrypoint") != ["/usr/local/bin/gateway"] or config.get("Cmd") != ["serve", "--config", "/etc/engine/engine.json"] or config.get("User") not in ("engine", "65532"):
        fail("the image starts %r %r as %r" % (config.get("Entrypoint"), config.get("Cmd"), config.get("User")))
    return "the image holds: gateway with exactly CAP_SETUID, CAP_SETGID, CAP_KILL, 0700, engine's, on a root-owned path; the MCP server's copy of it root's, 0755, without a capability, the same bytes; nothing else privileged; %d homes at 0700 under a root-owned /home; adapters, runtime%s, catalog and corpus root's, unwritable by others, readable by all, the trees exactly the checkout's; users and groups as the engine reads them, engine-mcp in no group but its own, owning nothing outside its home, every entry under /home but its own closed to it and no link under /home, and no seed, store, configuration or credential path shipped; entrypoint and command" % (len(HOMES), " (the pinned binary, byte for byte)" if runtime is not None else "")


def closed_to_the_frontend(fs):
    """What the MCP server's user (uid 65533) must not reach, the image
    does not give it: nothing outside its own home is owned by that user
    or its group; no symbolic link is under /home at all; every entry
    under /home, but under its own home, carries no bit for others, so a seed, a store or a credentials file put there
    by a derived image is closed to it as the home itself is -- the homes
    this check holds are those under /home, and a home elsewhere in
    /etc/passwd (root's) is not held by it; and the paths a
    deployment mounts a seed, a store, a configuration or a credential at
    are not in the image at all -- an image check can prove absence and
    closure, and no more."""
    for name, e in sorted(fs.items()):
        # a symbolic link under /home is a way out of the closure the modes
        # describe -- /home is root's and traversable, and a link there
        # reaches wherever it points -- so there is none, the MCP server's
        # own home included
        if name.startswith("home/") and e.islink:
            fail("%s is a symbolic link under /home; no link there may lead the MCP server out of the closure the homes' modes describe" % name)
        if name == FRONTEND_HOME or name.startswith(FRONTEND_HOME + "/"):
            continue
        if e.uid == FRONTEND_UID or e.gid == FRONTEND_UID:
            fail("%s is owned by the MCP server's user or group (%d:%d); nothing outside /%s is" % (name, e.uid, e.gid, FRONTEND_HOME))
        if name.startswith("home/") and name != "home" and not e.islink and e.mode & 0o007:
            fail("%s is mode %04o, open to others; a home's contents are closed to every other user, the MCP server's among them" % (name, e.mode))
    for prefix in UNSHIPPED:
        shipped = [name for name in fs if name == prefix or name.startswith(prefix + "/")]
        if shipped:
            fail("the image ships %s; a seed, a store, a configuration or a credential is the deployment's mount, never the image's, and the MCP server must be denied each" % shipped[0])


def scan_layers(image_dir):
    """Every entry in every layer of a saved image that carries the
    capability attribute: each must be the gateway's path with exactly the
    stated capabilities, revision 2 or 3 with a root id of 0. This reads
    the attribute as the layer wrote it, which the exporter normalises,
    and needs no model of how layers combine: an attribute an earlier
    layer carried and a later one removed is refused too, which is the
    safe side."""
    manifest = json.load(open(os.path.join(image_dir, "manifest.json")))
    if len(manifest) != 1:
        fail("the save holds %d images, not one" % len(manifest))
    seen = 0
    for layer in manifest[0]["Layers"]:
        try:
            t = tarfile.open(os.path.join(image_dir, layer), "r:*")
        except tarfile.ReadError:
            fail("layer %s is not a tar archive" % layer)
        for m in t.getmembers():
            raw = m.pax_headers.get("SCHILY.xattr.security.capability")
            if raw is None:
                continue
            name = m.name.strip("/")
            name = name[2:] if name.startswith("./") else name
            if name != GATEWAY:
                fail("layer %s gives %s a capability attribute; only the gateway binary may carry one" % (layer, name))
            decoded = decode_capability(raw.encode("utf-8", "surrogateescape"))
            if decoded["permitted"] != 1 << 5 | 1 << 6 | 1 << 7 or decoded["inheritable"] != 0 or not decoded["effective"] or decoded["rootid"] != 0:
                fail("layer %s gives the gateway capabilities %r as written" % (layer, decoded))
            seen += 1
    if seen == 0:
        fail("no layer gives the gateway a capability attribute")
    return "the layers give the capability attribute to the gateway alone, as stated, revision and root id included"


def load_config(path):
    """The image configuration as `docker image inspect` prints it (a list
    of one) or as an OCI config blob."""
    data = json.load(open(path))
    if isinstance(data, list):
        data = data[0]
    return data.get("Config") or data.get("config")


def main(export, config_path, checkout, saved=None, runtime=None):
    fs, archive = read_export(export)
    report = check(fs, archive, load_config(config_path), checkout, runtime)
    if saved:
        report += "; " + scan_layers(saved)
    return report


if __name__ == "__main__":
    try:
        print(main(*sys.argv[1:6]))
    except Failure as failure:
        sys.exit(str(failure))
