"""Each invariant image_checks.py holds, with its own negative case on an
exported filesystem built in memory: one thing wrong per case, so that no
other refusal can mask the one under test. Run from the repository root:
python3 .github/test_image_checks.py"""
import io, os, struct, sys, tarfile, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import image_checks as ic

CAPS = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0)
CONFIG = {"Entrypoint": ["/usr/local/bin/gateway"], "Cmd": ["serve", "--config", "/etc/engine/engine.json"], "User": "engine"}
PASSWD = b"root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:e:/home/engine:/sbin/nologin\nengine-mcp:x:65533:65533:m:/home/engine-mcp:/sbin/nologin\n" + b"".join(
    b"engine-%d:x:%d:%d:p:/home/engine-%d:/sbin/nologin\n" % (n, 65600 + n, 65600 + n, n) for n in range(1, 9))
GROUP = b"root:x:0:\nengine:x:65532:\nengine-mcp:x:65533:\n" + b"".join(b"engine-%d:x:%d:\n" % (n, 65600 + n) for n in range(1, 9))
RUNTIME = b"released jpack"


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
    for d in ("usr", "usr/local", "usr/local/bin", "usr/share", "usr/share/engine", "usr/share/engine/catalog", "usr/share/engine/corpus", "usr/share/engine/runtime", "etc", "home"):
        spec[d] = dict(kind="dir")
    spec["usr/local/bin/gateway"] = dict(kind="file", data=b"g", mode=0o700, uid=65532, gid=65532, caps=CAPS)
    spec["usr/local/bin/engine-mcp"] = dict(kind="file", data=b"g", mode=0o755)
    spec["usr/local/bin/adapter-airbyte"] = dict(kind="file", data=b"a", mode=0o755)
    spec["usr/local/bin/adapter-mcp"] = dict(kind="file", data=b"m", mode=0o755)
    spec["usr/local/bin/adapter-http"] = dict(kind="file", data=b"h", mode=0o755)
    spec["usr/local/bin/jpack"] = dict(kind="file", data=RUNTIME, mode=0o755)
    for document in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES", "CONFORMANCE.md"):
        spec["usr/share/engine/runtime/" + document] = dict(kind="file", data=b"n")
    spec["usr/share/engine/catalog/postgres.json"] = dict(kind="file", data=b'{"bindingVersion":"1"}')
    spec["usr/share/engine/corpus/canon.json"] = dict(kind="file", data=b"[]")
    spec["etc/passwd"] = dict(kind="file", data=PASSWD)
    spec["etc/group"] = dict(kind="file", data=GROUP)
    spec["home/engine"] = dict(kind="dir", mode=0o700, uid=65532, gid=65532)
    spec["home/engine-mcp"] = dict(kind="dir", mode=0o700, uid=65533, gid=65533)
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
        self.runtime = os.path.join(self.checkout, "runtime-jpack")
        open(self.runtime, "wb").write(RUNTIME)

    def run_check(self, export, config=CONFIG, runtime="pinned"):
        fs, archive = ic.read_export(export.done() if isinstance(export, Export) else export)
        return ic.check(fs, archive, config, self.checkout, self.runtime if runtime == "pinned" else runtime)

    def refused(self, export, fragment, config=CONFIG, runtime="pinned"):
        with self.assertRaises(ic.Failure) as refused:
            self.run_check(export, config, runtime)
        self.assertIn(fragment, str(refused.exception))

    def test_the_stated_image_holds(self):
        self.assertIn("the pinned binary, byte for byte", self.run_check(good()))

    def test_the_stated_image_holds_without_the_pinned_binary_to_compare(self):
        report = self.run_check(good(), runtime=None)
        self.assertIn("the image holds", report)
        self.assertNotIn("byte for byte)", report)

    # The runtime: the released binary, held as the adapters are and to
    # the pinned bytes; its notices beside it.
    def test_runtime_missing(self):
        self.refused(good(**{"usr/local/bin/jpack": None}), "usr/local/bin/jpack is not in the image")

    def test_runtime_not_executable(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(mode=0o644)}), "usr/local/bin/jpack is type b'0' mode 0644; it must be a regular file executable by every user")

    def test_runtime_not_readable(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(mode=0o711)}), "readable by everyone")

    def test_runtime_writable(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(mode=0o777)}), "unwritable by others")

    def test_runtime_owned_by_a_platform(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(uid=65601)}), "must be root's")

    def test_runtime_with_capabilities(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(caps=CAPS)}), "jpack carries a capability attribute")

    def test_runtime_not_the_pinned_bytes(self):
        self.refused(good(**{"usr/local/bin/jpack": dict(data=b"rebuilt jpack")}), "jpack differs from the pinned runtime binary")

    def test_runtime_not_the_pinned_bytes_is_not_held_without_them(self):
        self.assertIn("the image holds", self.run_check(good(**{"usr/local/bin/jpack": dict(data=b"rebuilt jpack")}), runtime=None))

    def test_runtime_notice_missing(self):
        self.refused(good(**{"usr/share/engine/runtime/THIRD_PARTY_NOTICES": None}), "THIRD_PARTY_NOTICES is not in the image")

    def test_runtime_conformance_statement_missing(self):
        self.refused(good(**{"usr/share/engine/runtime/CONFORMANCE.md": None}), "CONFORMANCE.md is not in the image")

    def test_runtime_notice_not_readable(self):
        self.refused(good(**{"usr/share/engine/runtime/NOTICE": dict(mode=0o600)}), "readable by everyone")

    def test_runtime_notice_not_a_file(self):
        self.refused(good(**{"usr/share/engine/runtime/LICENSE": dict(kind="dir")}), "LICENSE is not a regular file")

    def test_runtime_notices_directory_writable(self):
        self.refused(good(**{"usr/share/engine/runtime": dict(kind="dir", mode=0o777)}), "unwritable by others")

    # The gateway: each of its properties on its own.
    # The MCP server's copy of the executable: root's, 0755, no capability,
    # the gateway's bytes; and its user, in no group but its own.
    def test_mcp_copy_missing(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": None}), "usr/local/bin/engine-mcp")

    def test_mcp_copy_with_capabilities(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": dict(caps=CAPS)}), "carries a capability attribute; the MCP server holds no capability")

    def test_mcp_copy_not_executable_by_all(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": dict(mode=0o700)}), "usr/local/bin/engine-mcp is mode 0700; it must be readable by everyone")

    def test_mcp_copy_not_executable(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": dict(mode=0o644)}), "it must be a regular file, 0755, root's")

    def test_mcp_copy_owned_by_the_signer(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": dict(uid=65532, gid=65532)}), "every path to usr/local/bin/engine-mcp must be root's")

    def test_mcp_copy_not_the_gateway_bytes(self):
        self.refused(good(**{"usr/local/bin/engine-mcp": dict(data=b"other")}), "is not the gateway executable byte for byte")

    def test_mcp_user_missing(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine-mcp:x:65533:65533:m:/home/engine-mcp:/sbin/nologin\n", b""))}), "does not name engine-mcp")

    def test_mcp_user_in_another_group(self):
        self.refused(good(**{"etc/group": dict(data=GROUP.replace(b"engine:x:65532:\n", b"engine:x:65532:engine-mcp\n"))}), "makes engine-mcp a member of engine")

    def test_mcp_home_missing(self):
        self.refused(good(**{"home/engine-mcp": None}), "home/engine-mcp")

    # What the MCP server's user must not reach: a closed file under another
    # home holds, an open one, one owned by that user or its group, and a
    # shipped seed, store, configuration or credential path are each refused
    def test_a_closed_file_under_the_signers_home_holds(self):
        self.run_check(good(**{"home/engine/gateway.seed": dict(data=b"s", mode=0o600, uid=65532, gid=65532)}))

    def test_a_world_readable_seed_under_the_signers_home(self):
        self.refused(good(**{"home/engine/gateway.seed": dict(data=b"s", mode=0o644, uid=65532, gid=65532)}), "home/engine/gateway.seed is mode 0644, open to others")

    def test_a_world_readable_store_under_the_signers_home(self):
        self.refused(good(**{"home/engine/store": dict(kind="dir", mode=0o755, uid=65532, gid=65532)}), "home/engine/store is mode 0755, open to others")

    def test_a_world_readable_credentials_file_under_a_platform_home(self):
        self.refused(good(**{"home/engine-1/credentials.json": dict(data=b"c", mode=0o604, uid=65601, gid=65601)}), "home/engine-1/credentials.json is mode 0604, open to others")

    def test_a_file_owned_by_the_mcp_user_outside_its_home(self):
        self.refused(good(**{"home/engine-1/credentials.json": dict(data=b"c", mode=0o600, uid=65533, gid=65601)}), "is owned by the MCP server's user or group (65533:65601)")

    def test_a_file_in_the_mcp_users_group_outside_its_home(self):
        self.refused(good(**{"home/engine/store": dict(kind="dir", mode=0o750, uid=65532, gid=65533)}), "is owned by the MCP server's user or group (65532:65533)")

    def test_a_shipped_configuration(self):
        self.refused(good(**{"etc/engine": dict(kind="dir"), "etc/engine/engine.json": dict(data=b"{}")}), "the image ships etc/engine")

    def test_a_shipped_seed_path(self):
        self.refused(good(**{"var": dict(kind="dir"), "var/lib": dict(kind="dir"), "var/lib/engine": dict(kind="dir", mode=0o700, uid=65532, gid=65532), "var/lib/engine/gateway.seed": dict(data=b"s", mode=0o600, uid=65532, gid=65532)}), "the image ships var/lib/engine")

    def test_a_shipped_secret(self):
        self.refused(good(**{"run": dict(kind="dir"), "run/secrets": dict(kind="dir"), "run/secrets/warehouse": dict(data=b"c", mode=0o600, uid=65601, gid=65601)}), "the image ships run/secrets")

    def test_gateway_mode(self):
        self.refused(good(**{"usr/local/bin/gateway": dict(mode=0o750)}), "must be 0700")

    def test_gateway_owner(self):
        # The uid alone: the group stays the signer's.
        self.refused(good(**{"usr/local/bin/gateway": dict(uid=0, gid=65532)}), "the signer's (65532)")

    def test_gateway_group(self):
        # The group alone: the uid stays the signer's.
        self.refused(good(**{"usr/local/bin/gateway": dict(uid=65532, gid=0)}), "the signer's (65532)")

    def test_gateway_capabilities_upper_permitted_word(self):
        caps = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 1, 0)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

    def test_gateway_capabilities_upper_inheritable_word(self):
        caps = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 1)
        self.refused(good(**{"usr/local/bin/gateway": dict(caps=caps)}), "capabilities are")

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

    def test_a_hard_link_takes_its_targets_entry(self):
        # Read directly: the link's entry is the target's, bits and all,
        # whatever its own header said.
        e = good(**{"opt/target": dict(mode=0o640, uid=65601, gid=65601)})
        e.hardlink("opt/link", "opt/target", mode=0o777, uid=0)
        fs, _ = ic.read_export(e.done())
        link, target = fs["opt/link"], fs["opt/target"]
        self.assertIs(link, target)
        self.assertEqual((link.mode, link.uid, link.gid, link.capability), (0o640, 65601, 65601, None))

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
        self.refused(good(**{"usr/local/bin": dict(kind="dir", mode=0o777)}), "usr/local/bin is mode 0777")

    def test_a_group_writable_directory_on_the_way(self):
        self.refused(good(**{"usr/local": dict(kind="dir", mode=0o775)}), "unwritable by others")

    def test_a_directory_on_the_way_owned_by_the_signer(self):
        self.refused(good(**{"usr/local": dict(kind="dir", uid=65532, gid=0)}), "must be root's")

    def test_a_directory_on_the_way_with_another_group(self):
        self.refused(good(**{"usr/local": dict(kind="dir", uid=0, gid=65601)}), "must be root's group")

    def test_a_directory_on_the_way_not_passable(self):
        self.refused(good(**{"usr/share/engine": dict(kind="dir", mode=0o750)}), "passable by everyone")

    def test_a_catalog_directory_not_readable(self):
        self.refused(good(**{"usr/share/engine/catalog": dict(kind="dir", mode=0o700)}), "readable by everyone")

    def test_a_catalog_file_not_readable(self):
        self.refused(good(**{"usr/share/engine/catalog/postgres.json": dict(mode=0o600)}), "readable by everyone")

    def test_an_adapter_not_readable(self):
        self.refused(good(**{"usr/local/bin/adapter-mcp": dict(mode=0o711)}), "readable by everyone")

    def test_the_http_adapter_missing(self):
        self.refused(good(**{"usr/local/bin/adapter-http": None}), "usr/local/bin/adapter-http is not in the image")

    def test_the_http_adapter_writable(self):
        self.refused(good(**{"usr/local/bin/adapter-http": dict(mode=0o777)}), "unwritable by others")

    def test_the_http_adapter_not_executable(self):
        self.refused(good(**{"usr/local/bin/adapter-http": dict(mode=0o644)}), "executable by every user")

    def test_the_http_adapter_with_capabilities(self):
        self.refused(good(**{"usr/local/bin/adapter-http": dict(caps=CAPS)}), "adapter-http carries a capability attribute")

    def test_a_file_in_the_catalog_the_checkout_lacks(self):
        self.refused(good(**{"usr/share/engine/catalog/extra.json": dict(data=b"{}", mode=0o666, uid=65601)}), "not in the checkout's catalog")

    def test_a_corpus_file_writable(self):
        self.refused(good(**{"usr/share/engine/corpus/canon.json": dict(mode=0o666)}), "unwritable by others")

    def test_the_passwd_file_writable(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD, mode=0o666)}), "unwritable by others")

    def test_the_group_file_writable(self):
        self.refused(good(**{"etc/group": dict(data=GROUP, mode=0o666)}), "unwritable by others")

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
        self.refused(good(**{"home": dict(kind="dir", mode=0o777)}), "home is mode 0777")

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
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine-4:x:65604:65604", b"engine-4:x:65614:65604"))}), "has engine-4 as uid 65614")

    def test_a_user_with_another_primary_group(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine-4:x:65604:65604", b"engine-4:x:65604:0"))}), "has engine-4 as uid 65604 gid 0")

    def test_a_user_with_another_home(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"/home/engine-4", b"/home/engine-3"))}), "home /home/engine-3")

    def test_a_user_missing(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine:x:65532:65532:e:/home/engine:/sbin/nologin\n", b""))}), "does not name engine")

    def test_a_user_named_twice_is_not_read_last_wins(self):
        # The engine reads the first line naming a user; a first line giving
        # engine-4 uid 0 would be what it reads, whatever a later one said.
        self.refused(good(**{"etc/passwd": dict(data=b"engine-4:x:65699:65699:p:/home/engine-4:/sbin/nologin\n" + PASSWD)}), "names engine-4 twice")

    def test_a_uid_given_twice(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD + b"other:x:65604:65604:o:/home/other:/sbin/nologin\n")}), "gives uid 65604 to engine-4 and to other")

    def test_a_group_with_another_gid(self):
        self.refused(good(**{"etc/group": dict(data=GROUP.replace(b"engine-2:x:65602:", b"engine-2:x:65612:"))}), "has engine-2 as gid 65612")

    def test_a_group_missing(self):
        self.refused(good(**{"etc/group": dict(data=GROUP.replace(b"engine:x:65532:\n", b""))}), "has engine as gid None")

    def test_a_group_named_twice(self):
        self.refused(good(**{"etc/group": dict(data=b"engine-2:x:65699:\n" + GROUP)}), "names engine-2 twice")

    def test_a_passwd_line_with_leading_whitespace(self):
        # The lookup trims and reads it as engine-4; the check refuses it.
        self.refused(good(**{"etc/passwd": dict(data=b" engine-4:x:65699:65699:p:/home/wrong:/sbin/nologin\n" + PASSWD)}), "otherwise than written")

    def test_a_passwd_comment_line(self):
        self.refused(good(**{"etc/passwd": dict(data=b"# users\n" + PASSWD)}), "otherwise than written")

    def test_a_uid_spelled_with_a_leading_zero(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD + b"other:x:065604:65699:o:/home/other:/sbin/nologin\n")}), "not a number as one is spelled")

    def test_a_uid_spelled_in_fullwidth_digits(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD.replace(b"engine-4:x:65604:65604", "engine-4:x:６５６０４:65604".encode("utf-8")))}), "not a number as one is spelled")

    def test_a_gid_spelled_in_fullwidth_digits(self):
        self.refused(good(**{"etc/group": dict(data=GROUP.replace(b"engine-4:x:65604:", "engine-4:x:６５６０４:".encode("utf-8")))}), "not a number as one is spelled")

    def test_a_gid_spelled_with_a_leading_zero(self):
        self.refused(good(**{"etc/group": dict(data=GROUP + b"other:x:065604:\n")}), "not a number as one is spelled")

    def test_home_not_passable(self):
        self.refused(good(**{"home": dict(kind="dir", mode=0o754)}), "home is mode 0754; it must be a directory passable by everyone")

    def test_a_directory_in_the_catalog_the_checkout_lacks(self):
        self.refused(good(**{"usr/share/engine/catalog/extra": dict(kind="dir")}), "a directory in the image and not in the checkout's catalog")

    def test_a_passwd_line_of_the_wrong_shape(self):
        self.refused(good(**{"etc/passwd": dict(data=PASSWD + b"broken\n")}), "not 7 fields")

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


class Layers(unittest.TestCase):
    """The layer scan: the capability attribute as each layer wrote it."""

    def saved(self, layers):
        image = tempfile.mkdtemp()
        names = []
        for i, entries in enumerate(layers):
            path = os.path.join(image, "layer-%d.tar" % i)
            t = tarfile.open(path, "w")
            for name, caps in entries:
                info = tarfile.TarInfo(name)
                info.type, info.size = tarfile.REGTYPE, 0
                if caps is not None:
                    info.pax_headers = {"SCHILY.xattr.security.capability": caps.decode("utf-8", "surrogateescape")}
                t.addfile(info, io.BytesIO(b""))
            t.close()
            names.append("layer-%d.tar" % i)
        open(os.path.join(image, "manifest.json"), "w").write('[{"Config":"c","Layers":%s}]' % str(names).replace("'", '"'))
        return image

    def test_the_gateway_alone_as_stated(self):
        self.assertIn("gateway alone", ic.scan_layers(self.saved([[("usr/local/bin/gateway", CAPS), ("usr/local/bin/adapter-mcp", None)]])))

    def test_a_v3_attribute_rooted_elsewhere_is_seen_as_written(self):
        rooted = struct.pack("<IIIIII", 0x03000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0, 1000)
        with self.assertRaises(ic.Failure) as refused:
            ic.scan_layers(self.saved([[("usr/local/bin/gateway", rooted)]]))
        self.assertIn("as written", str(refused.exception))

    def test_another_file_in_any_layer(self):
        with self.assertRaises(ic.Failure) as refused:
            ic.scan_layers(self.saved([[("usr/local/bin/gateway", CAPS)], [("opt/evil", CAPS)]]))
        self.assertIn("opt/evil a capability attribute", str(refused.exception))

    def test_no_layer_giving_the_attribute(self):
        with self.assertRaises(ic.Failure) as refused:
            ic.scan_layers(self.saved([[("usr/local/bin/gateway", None)]]))
        self.assertIn("no layer", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
