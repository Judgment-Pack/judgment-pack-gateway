"""The layer semantics image_checks.py relies on, each exercised with an
image built in memory: what an unpacker would produce is what the check
judges, and every way a wrong image was found to pass an earlier reading
is a fixture here. Run: python3 -m unittest .github/test_image_checks.py
(from the repository root)."""
import io, os, struct, sys, tarfile, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import image_checks as ic

CAPS = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0)
CONFIG = {"Entrypoint": ["/usr/local/bin/gateway"], "Cmd": ["serve", "--config", "/etc/engine/engine.json"], "User": "engine"}
PASSWD = b"root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:e:/home/engine:/sbin/nologin\n" + b"".join(
    b"engine-%d:x:%d:%d:p:/home/engine-%d:/sbin/nologin\n" % (n, 65600 + n, 65600 + n, n) for n in range(1, 9))


class Layer:
    """A layer written as a tar in a temp dir, entry by entry, in the
    order given -- so a whiteout may come before or after what it names."""

    def __init__(self, image):
        self.path = os.path.join(image, "layer-%d.tar" % len(os.listdir(image)))
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

    def hardlink(self, name, target):
        info = tarfile.TarInfo(name)
        info.type, info.linkname = tarfile.LNKTYPE, target
        self.tar.addfile(info)
        return self

    def whiteout(self, name):
        return self.file(name)

    def done(self):
        self.tar.close()
        return self.path


class Checks(unittest.TestCase):
    def setUp(self):
        self.image = tempfile.mkdtemp()
        self.checkout = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.checkout, "catalog"))
        os.makedirs(os.path.join(self.checkout, "corpus"))
        open(os.path.join(self.checkout, "catalog", "postgres.json"), "wb").write(b'{"bindingVersion":"1"}')
        open(os.path.join(self.checkout, "corpus", "canon.json"), "wb").write(b"[]")

    def good(self):
        """The image the design states, as one layer plus a second that
        made the homes and removed its helper."""
        base = Layer(self.image)
        for d in ("usr", "usr/local", "usr/local/bin", "usr/share", "usr/share/engine", "usr/share/engine/catalog", "usr/share/engine/corpus", "etc", "home"):
            base.dir(d)
        base.file("usr/local/bin/gateway", b"g", 0o700, 65532, 65532, CAPS)
        base.file("usr/local/bin/adapter-airbyte", b"a", 0o755).file("usr/local/bin/adapter-mcp", b"m", 0o755)
        base.file("usr/share/engine/catalog/postgres.json", b'{"bindingVersion":"1"}').file("usr/share/engine/corpus/canon.json", b"[]")
        base.file("etc/passwd", PASSWD).file("mkhomes", b"h", 0o755)
        layers = [base.done()]
        homes = Layer(self.image).whiteout(".wh.mkhomes")
        homes.dir("home/engine", 0o700, 65532, 65532)
        for n in range(1, 9):
            homes.dir("home/engine-%d" % n, 0o700, 65600 + n, 65600 + n)
        layers.append(homes.done())
        return layers

    def run_check(self, layers, config=CONFIG):
        return ic.check(ic.apply_layers("", layers), config, self.checkout)

    def assertRefused(self, layers, fragment):
        with self.assertRaises(ic.Failure) as refused:
            self.run_check(layers)
        self.assertIn(fragment, str(refused.exception))

    def test_the_stated_image_holds(self):
        self.assertIn("the image holds", self.run_check(self.good()))

    def test_a_dot_file_is_not_the_file_without_the_dot(self):
        # A benign ".evil" must not stand in for a set-uid "evil".
        layers = self.good()
        layers.append(Layer(self.image).file("usr/local/bin/evil", b"e", 0o4755).file("usr/local/bin/.evil", b"", 0o644).done())
        self.assertRefused(layers, "set-user-id")

    def test_a_whiteout_removes_only_what_earlier_layers_left(self):
        # The same layer adds a capability-bearing file and an opaque
        # whiteout of its directory, in that order: the file survives.
        layers = self.good()
        layers.append(Layer(self.image).dir("opt").file("opt/evil", b"e", 0o755, caps=CAPS).whiteout("opt/.wh..wh..opq").done())
        self.assertRefused(layers, "opt/evil carries a capability attribute")
        # And a plain whiteout in a later layer does remove what an earlier one left.
        layers = self.good()
        layers.append(Layer(self.image).dir("opt").file("opt/evil", b"e", 0o755, caps=CAPS).done())
        layers.append(Layer(self.image).whiteout("opt/.wh.evil").done())
        self.assertIn("the image holds", self.run_check(layers))

    def test_a_hard_link_shares_its_targets_bits(self):
        # A set-uid file, a hard link to it, then the original removed:
        # the link is the same inode and is still set-uid.
        layers = self.good()
        layers.append(Layer(self.image).dir("opt").file("opt/evil", b"e", 0o4755).hardlink("opt/link", "opt/evil").done())
        layers.append(Layer(self.image).whiteout("opt/.wh.evil").done())
        self.assertRefused(layers, "opt/link is set-user-id")

    def test_a_directory_replaced_by_a_link_loses_its_descendants(self):
        layers = self.good()
        layers.append(Layer(self.image).link("usr/local", "/nowhere").done())
        self.assertRefused(layers, "symbolic link")

    def test_a_writable_directory_on_the_way_is_refused(self):
        layers = self.good()
        layers.append(Layer(self.image).dir("usr/local/bin", 0o777).done())
        self.assertRefused(layers, "unwritable by others")
        layers = self.good()
        layers.append(Layer(self.image).dir("usr/local", 0o755, 65532, 65532).done())
        self.assertRefused(layers, "must be root's")

    def test_a_writable_adapter_is_refused(self):
        layers = self.good()
        layers.append(Layer(self.image).file("usr/local/bin/adapter-mcp", b"m", 0o777).done())
        self.assertRefused(layers, "unwritable by others")

    def test_the_homes_by_another_spelling_are_refused(self):
        layers = self.good()
        layers.append(Layer(self.image).dir("home/./engine", 0o755, 65532, 65532).done())
        self.assertRefused(layers, "not a normalised path")

    def test_a_home_at_the_wrong_mode_or_owner_is_refused(self):
        layers = self.good()
        layers.append(Layer(self.image).dir("home/engine-3", 0o755, 65603, 65603).done())
        self.assertRefused(layers, "home/engine-3")

    def test_the_helper_left_behind_is_refused(self):
        layers = self.good()
        layers.append(Layer(self.image).file("mkhomes", b"h", 0o755).done())
        self.assertRefused(layers, "mkhomes helper")

    def test_the_catalog_must_match_the_checkout(self):
        layers = self.good()
        layers.append(Layer(self.image).file("usr/share/engine/catalog/postgres.json", b"{}").done())
        self.assertRefused(layers, "differs from")

    def test_the_gateways_capabilities_are_decoded_not_compared(self):
        v3 = struct.pack("<IIIIII", 0x03000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0, 0)
        layers = self.good()
        layers.append(Layer(self.image).file("usr/local/bin/gateway", b"g", 0o700, 65532, 65532, v3).done())
        self.assertIn("the image holds", self.run_check(layers))
        more = struct.pack("<IIIII", 0x02000001, 1 << 5 | 1 << 6 | 1 << 7 | 1 << 1, 0, 0, 0)
        layers = self.good()
        layers.append(Layer(self.image).file("usr/local/bin/gateway", b"g", 0o700, 65532, 65532, more).done())
        self.assertRefused(layers, "capabilities are")
        rooted = struct.pack("<IIIIII", 0x03000001, 1 << 5 | 1 << 6 | 1 << 7, 0, 0, 0, 1000)
        layers = self.good()
        layers.append(Layer(self.image).file("usr/local/bin/gateway", b"g", 0o700, 65532, 65532, rooted).done())
        self.assertRefused(layers, "root id of 0")

    def test_the_start_is_held(self):
        with self.assertRaises(ic.Failure):
            self.run_check(self.good(), {"Entrypoint": ["/bin/sh"], "Cmd": [], "User": "engine"})


if __name__ == "__main__":
    unittest.main()
