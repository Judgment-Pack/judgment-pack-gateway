"""Each invariant image_checks.py holds, with its own negative case on an
exported filesystem built in memory: one thing wrong per case, so that no
other refusal can mask the one under test. Run from the repository root:
python3 .github/test_image_checks.py"""
import io, os, struct, sys, tarfile, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import image_checks as ic

CAPS = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0)
CONFIG = {"Entrypoint": ["/usr/local/bin/gateway"], "Cmd": ["serve", "--config", "/etc/engine/engine.json"], "User": "engine"}
PASSWD = b"root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:e:/home/engine:/sbin/nologin\n" + b"".join(
    b"engine-%d:x:%d:%d:p:/home/engine-%d:/sbin/nologin\n" % (n, 65600 + n, 65600 + n, n) for n in range(1, 9))


class Export:
    """An exported filesystem as a tar, one entry per call, in order."""

    def __init__(self):
        self.path = tempfile.mktemp(suffix=".tar")
        self.tar = tarfile.open(self.path, "w")

    def dir(self, name, mode=0o755, uid=0, gid=0):
        info = tarfile.TarInfo(name)
        info.type, info.mode, info.uid, info.gid = tarfile.DIRTYPE, mode, uid, gid
        self.tar.addfile(info)
        return self

    def file(self, name, data=b"", mode=0o644, uid=0, gid=0, caps=None):
        info = tarfile.TarInfo(name)
        info.type, info.mode, info.uid, info.gid, info.size = tarfile.REGTYPE, mode, uid, gid, len(data)
        if caps is not None:
            info.pax_headers = {"SCHILY.xattr.security.capability": caps.decode("utf-8", "surrogateescape")}
        self.tar.addfile(info, io.BytesIO(data))
        return self

    def link(self, name, target):
        info = tarfile.TarInfo(name)
        info.type, info.linkname = tarfile.SYMTYPE, target
        self.tar.addfile(info)
        return self

    def hardlink(self, name, target, mode=0o644, uid=0, caps=None):
        info = tarfile.TarInfo(name)
        info.type, info.linkname, info.mode, info.uid = tarfile.LNKTYPE, target, mode, uid
        if caps is not None:
            info.pax_headers = {"SCHILY.xattr.security.capability": caps.decode("utf-8", "surrogateescape")}
        self.tar.addfile(info)
        return self

    def done(self):
        self.tar.close()
        return self.path


def good(**over):
    """The exported filesystem the design states, with named entries
    overridden: over["usr/local/bin/gateway"] = dict(mode=..., ...) or
    over[name] = None to leave it out."""
    e = Export()
    spec = {}
    for d in ("usr", "usr/local", "usr/local/bin", "usr/share", "usr/share/engine", "usr/share/engine/catalog", "usr/share/engine/corpus", "etc", "home"):
        spec[d] = dict(kind="dir")
    spec["usr/local/bin/gateway"] = dict(kind="file", data=b"g", mode=0o700, uid=65532, gid=65532, caps=CAPS)
    spec["usr/local/bin/adapter-airbyte"] = dict(kind="file", data=b"a", mode=0o755)
    spec["usr/local/bin/adapter-mcp"] = dict(kind="file", data=b"m", mode=0o755)
    spec["usr/share/engine/catalog/postgres.json"] = dict(kind="file", data=b'{"bindingVersion":"1"}')
    spec["usr/share/engine/corpus/canon.json"] = dict(kind="file", data=b"[]")
    spec["etc/passwd"] = dict(kind="file", data=PASSWD)
    spec["home/engine"] = dict(kind="dir", mode=0o700, uid=65532, gid=65532)
    for n in range(1, 9):
        spec["home/engine-%d" % n] = dict(kind="dir", mode=0o700, uid=65600 + n, gid=65600 + n)
    for name, change in over.items():
        if change is None:
            del spec[name]
        else:
            spec.setdefault(name, dict(kind="file")).update(change)
    for name, s in spec.items():
        if s.get("kind") == "dir":
            e.dir(name, s.get("mode", 0o755), s.get("uid", 0), s.get("gid", 0))
        elif s.get("kind") == "link":
            e.link(name, s["target"])
        else:
            e.file(name, s.get("data", b""), s.get("mode", 0o644), s.get("uid", 0), s.get("gid", 0), s.get("caps"))
    return e


class Checks(unittest.TestCase):
    def setUp(self):
        self.checkout = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.checkout, "catalog"))
        os.makedirs(os.path.join(self.checkout, "corpus"))
        open(os.path.join(self.checkout, "catalog", "postgres.json"), "wb").write(b'{"bindingVersion":"1"}')
        open(os.path.join(self.checkout, "corpus", "canon.json"), "wb").write(b"[]")

    def run_check(self, export, config=CONFIG):
        fs, archive = ic.read_export(export.done() if isinstance(export, Export) else export)
        return ic.check(fs, archive, config, self.checkout)

    def refused(self, export, fragment, config=CONFIG):
        with self.assertRaises(ic.Failure) as refused:
            self.run_check(export, config)
        self.assertIn(fragment, str(refused.exception))

    def test_the_stated_image_holds(self):
        self.assertIn("the image holds", self.run_check(good()))

    # The gateway: each of its properties on its own.
    def test_gateway_mode(self):
        self.refused(good(**{"usr/local/bin/gateway": dict(mode=0o750)}), "must be 0700")

    def test_gateway_owner(self):
        self.refused(good(**{"usr/local/bin/gateway": dict(uid=0, gid=0)}), "the signer's (65532)")

    def test_gateway_group(self):
        self.refused(good(**{"usr/local/bin/gateway": dict(gid=0)}), "the signer's (65532)")

    def test_gateway_without_capabilities(self):
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=None)}), "carries no capability attribute")

    def test_gateway_capabilities_not_effective(self):
        caps = struct.pack("<IIIII", 0x02000000, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

    def test_gateway_capabilities_inheritable(self):
        caps = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 1 << 7, 0, 0)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

    def test_gateway_capabilities_more_than_three(self):
        caps = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7 | 1 << 1, 0, 0, 0)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

    def test_gateway_capabilities_fewer_than_three(self):
        caps = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6, 0, 0, 0)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

    def test_gateway_capabilities_v3_is_read(self):
        v3 = struct.pack("<IIIIII", 0x03000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0, 0)
        self.assertIn("the image holds", self.run_check(good(**{"usr/local/bin/gateway": dict(caps=v3)})))

    def test_gateway_capabilities_v3_rooted_elsewhere(self):
        v3 = struct.pack("<IIIIII", 0x03000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0, 1000)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=v3)}), "root id of 0")

    def test_gateway_missing(self):
        self.refused(good(**{"usr/local/bin/gateway": None}), "usr/local/bin/gateway is not in the image")

    # Nothing else privileged.
    def test_another_file_with_capabilities(self):
        self.refused(good(**{"usr/local/bin/adapter-mcp": dict(caps=CAPS)}), "adapter-mcp carries a capability attribute")

    def test_a_set_uid_file(self):
        self.refused(good(**{"opt/evil": dict(mode=0o4755)}), "opt/evil is set-user-id")

    def test_a_set_gid_file(self):
        self.refused(good(**{"opt/evil": dict(mode=0o2755)}), "opt/evil is set-user-id or set-group-id")

    def test_a_hard_link_to_a_set_uid_file(self):
        e = good(**{"opt/evil": dict(mode=0o4755)})
        e.hardlink("opt/link", "opt/evil")
        self.refused(e, "set-user-id")

    def test_a_hard_link_whose_own_header_claims_capabilities(self):
        e = good()
        e.hardlink("usr/local/bin/other", "usr/local/bin/adapter-mcp", caps=CAPS)
        # The link is its target's inode: the target carries no
        # capability, so neither does the link, and the check reads the
        # inode -- but the header the unpacker would have applied to the
        # inode is what an exported filesystem no longer carries, which is
        # why the export, not a model of the layers, is what is judged.
        self.assertIn("the image holds", self.run_check(e))

    # The way to what runs.
    def test_a_writable_directory_on_the_way(self):
        self.refused(good(**{"usr/local/bin": dict(kind="dir", mode=0o777)}), "usr/local/bin is uid 0 gid 0 mode 0777")

    def test_a_group_writable_directory_on_the_way(self):
        self.refused(good(**{"usr/local": dict(kind="dir", mode=0o775)}), "unwritable by others")

    def test_a_directory_on_the_way_owned_by_the_signer(self):
        self.refused(good(**{"usr/local": dict(kind="dir", uid=65532, gid=65532)}), "must be root's")

    def test_a_link_on_the_way(self):
        self.refused(good(**{"usr/local": dict(kind="link", target="/nowhere")}), "usr/local is a symbolic link")

    def test_a_file_on_the_way(self):
        self.refused(good(**{"usr/local": dict(kind="file")}), "not a directory on the way")

    def test_a_writable_adapter(self):
        self.refused(good(**{"usr/local/bin/adapter-airbyte": dict(mode=0o777)}), "unwritable by others")

    def test_an_adapter_not_executable(self):
        self.refused(good(**{"usr/local/bin/adapter-airbyte": dict(mode=0o644)}), "executable by every user")

    def test_an_adapter_owned_by_a_platform(self):
        self.refused(good(**{"usr/local/bin/adapter-airbyte": dict(uid=65601)}), "must be root's")

    def test_a_writable_catalog_file(self):
        self.refused(good(**{"usr/share/engine/catalog/postgres.json": dict(mode=0o666)}), "unwritable by others")

    def test_the_catalog_must_match_the_checkout(self):
        self.refused(good(**{"usr/share/engine/catalog/postgres.json": dict(data=b"{}")}), "differs from")

    def test_the_corpus_must_match_the_checkout(self):
        self.refused(good(**{"usr/share/engine/corpus/canon.json": dict(data=b"{}")}), "differs from")

    # The homes.
    def test_a_writable_home_parent(self):
        self.refused(good(**{"home": dict(kind="dir", mode=0o777)}), "home is uid 0 gid 0 mode 0777")

    def test_a_home_parent_owned_by_a_platform(self):
        self.refused(good(**{"home": dict(kind="dir", uid=65601, gid=65601)}), "must be root's")

    def test_a_home_at_the_wrong_mode(self):
        self.refused(good(**{"home/engine-3": dict(kind="dir", mode=0o755, uid=65603, gid=65603)}), "home/engine-3 is type")

    def test_a_home_owned_by_another_user(self):
        self.refused(good(**{"home/engine-3": dict(kind="dir", mode=0o700, uid=65604, gid=65603)}), "home/engine-3 is type")

    def test_a_home_with_another_group(self):
        self.refused(good(**{"home/engine": dict(kind="dir", mode=0o700, uid=65532, gid=0)}), "home/engine is type")

    def test_a_home_missing(self):
        self.refused(good(**{"home/engine-8": None}), "home/engine-8 is not in the image")

    def test_the_helper_left_behind(self):
        self.refused(good(**{"mkhomes": dict(mode=0o755)}), "mkhomes helper")

    # The users, and what the image starts.
    def test_a_user_with_another_uid(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine-4:x:65604:65604", b"engine-4:x:65614:65604"))}), "names engine-4 as uid 65614")

    def test_a_user_missing(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine:x:65532:65532:e:/home/engine:/sbin/nologin\n", b""))}), "names engine as uid None")

    def test_the_entrypoint(self):
        self.refused(good(), "the image starts", {"Entrypoint": ["/bin/sh"], "Cmd": CONFIG["Cmd"], "User": "engine"})

    def test_the_command(self):
        self.refused(good(), "the image starts", {"Entrypoint": CONFIG["Entrypoint"], "Cmd": ["serve"], "User": "engine"})

    def test_the_user(self):
        self.refused(good(), "the image starts", {"Entrypoint": CONFIG["Entrypoint"], "Cmd": CONFIG["Cmd"], "User": "root"})

    # The export itself.
    def test_a_path_named_twice(self):
        e = good()
        e.file("etc/passwd", PASSWD)
        self.refused(e, "names etc/passwd twice")

    def test_a_path_not_normalised(self):
        e = good()
        e.dir("home/./engine-9", 0o777, 65601, 65601)
        self.refused(e, "not a normalised path")


if __name__ == "__main__":
    unittest.main()
