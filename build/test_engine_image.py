#!/usr/bin/env python3
"""What build/engine-image.sh and build/engine_image.py hold, one fault at a time.

Usage: python3 build/test_engine_image.py

The index check is run on OCI archives written here, in memory and to a
temporary directory: a sound one, then each spoiled in one way. The push is
run with a stand-in for the container client, written into a directory of
its own at the head of PATH, which records the arguments it was given and
answers the read-back with bytes the case chooses: nothing reaches a
registry, and no installed container client is started.

The cases are not a proof that nothing else gets through.
"""
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import engine_image as ei

SCRIPT = os.path.join(HERE, "engine-image.sh")
PLATFORMS = ["linux/amd64", "linux/arm64"]


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def manifest_for(arch):
    return json.dumps({"schemaVersion": 2, "mediaType": ei.MANIFEST, "architecture": arch}).encode()


def descriptor(data, media=ei.MANIFEST, **extra):
    d = {"mediaType": media, "digest": digest_of(data), "size": len(data)}
    d.update(extra)
    return d


class Image:
    """An OCI archive as the builder writes one, with its parts open to change before it is written."""

    def __init__(self):
        self.blobs = {}
        self.entries = []
        for arch in ("amd64", "arm64"):
            data = manifest_for(arch)
            self.blobs[digest_of(data)] = data
            self.entries.append(descriptor(data, platform={"architecture": arch, "os": "linux"}))
        self.index_media = ei.INDEX
        self.top = None
        self.reported = None
        self.spoil_index = None

    def index(self):
        return json.dumps({"schemaVersion": 2, "mediaType": self.index_media, "manifests": self.entries}).encode()

    def write(self, out):
        index = self.index()
        named = digest_of(index)
        stored = index if self.spoil_index is None else self.spoil_index
        blobs = dict(self.blobs)
        blobs[named] = stored
        top = self.top if self.top is not None else {"schemaVersion": 2, "mediaType": ei.INDEX, "manifests": [descriptor(index, ei.INDEX)]}
        with tarfile.open(os.path.join(out, "engine-image.tar"), "w") as t:
            for name, data in [("index.json", json.dumps(top).encode()), ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')] + [
                    ("blobs/sha256/" + d.split(":")[1], b) for d, b in blobs.items()]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        with open(os.path.join(out, "engine-image.metadata.json"), "w") as f:
            json.dump({"containerimage.digest": self.reported if self.reported is not None else named}, f)
        return named, index


class IndexCheck(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out)

    def refused(self, image, fragment, platforms=PLATFORMS):
        image.write(self.out)
        with self.assertRaises(ei.Refusal) as refused:
            ei.check(self.out, platforms)
        self.assertIn(fragment, str(refused.exception))

    def test_a_sound_archive_gives_its_index_and_digest(self):
        named, index = Image().write(self.out)
        self.assertEqual(ei.check(self.out, PLATFORMS), (named, index))
        self.assertEqual(ei.main(self.out, ",".join(PLATFORMS)), 0)
        with open(os.path.join(self.out, "engine-image.index.json"), "rb") as f:
            self.assertEqual(f.read(), index)
        with open(os.path.join(self.out, "engine-image.digest")) as f:
            self.assertEqual(f.read(), named + "\n")
        self.assertEqual(digest_of(index), named)

    def test_a_refused_archive_writes_nothing(self):
        image = Image()
        image.reported = "sha256:" + "0" * 64
        image.write(self.out)
        self.assertEqual(ei.main(self.out, ",".join(PLATFORMS)), 1)
        self.assertFalse(os.path.exists(os.path.join(self.out, "engine-image.digest")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "engine-image.index.json")))

    def test_two_indexes_named_at_the_top(self):
        image = Image()
        index = image.index()
        image.top = {"manifests": [descriptor(index, ei.INDEX), descriptor(index, ei.INDEX)]}
        self.refused(image, "does not name exactly one image index")

    def test_one_platforms_manifest_at_the_top(self):
        image = Image()
        image.top = {"manifests": [image.entries[0]]}
        self.refused(image, "does not name exactly one image index")

    def test_the_index_is_not_its_digest(self):
        image = Image()
        image.spoil_index = image.index().replace(b"arm64", b"arm65")
        self.refused(image, "does not have its digest")

    def test_the_index_is_not_an_oci_index(self):
        image = Image()
        image.index_media = "application/vnd.docker.distribution.manifest.list.v2+json"
        self.refused(image, "is not an OCI image index")

    def test_a_platform_is_missing(self):
        image = Image()
        image.entries = image.entries[:1]
        self.refused(image, "the index holds linux/amd64, not exactly linux/amd64, linux/arm64")

    def test_a_platform_more(self):
        image = Image()
        data = manifest_for("riscv64")
        image.blobs[digest_of(data)] = data
        image.entries.append(descriptor(data, platform={"architecture": "riscv64", "os": "linux"}))
        self.refused(image, "not exactly linux/amd64, linux/arm64")

    def test_a_platform_twice(self):
        image = Image()
        image.entries[1] = dict(image.entries[1], platform={"architecture": "amd64", "os": "linux"})
        self.refused(image, "the index holds linux/amd64, linux/amd64, not exactly")

    def test_an_attestation_manifest(self):
        image = Image()
        data = b'{"attestation":true}'
        image.blobs[digest_of(data)] = data
        image.entries.append(descriptor(data, platform={"architecture": "unknown", "os": "unknown"},
                                        annotations={"vnd.docker.reference.type": "attestation-manifest"}))
        self.refused(image, "not exactly linux/amd64, linux/arm64")

    def test_a_platform_with_a_variant(self):
        image = Image()
        image.entries[1] = dict(image.entries[1], platform={"architecture": "arm64", "os": "linux", "variant": "v8"})
        self.refused(image, "which is not one platform's image manifest")

    def test_an_entry_with_no_platform(self):
        image = Image()
        image.entries[0] = {k: v for k, v in image.entries[0].items() if k != "platform"}
        self.refused(image, "which is not one platform's image manifest")

    def test_an_entry_of_another_media_type(self):
        image = Image()
        image.entries[0] = dict(image.entries[0], mediaType="application/vnd.docker.distribution.manifest.v2+json")
        self.refused(image, "which is not one platform's image manifest")

    def test_a_platforms_manifest_missing(self):
        image = Image()
        del image.blobs[image.entries[1]["digest"]]
        self.refused(image, "the archive holds no blob " + image.entries[1]["digest"])

    def test_a_platforms_manifest_not_its_digest(self):
        image = Image()
        image.blobs[image.entries[0]["digest"]] = manifest_for("amd65")
        self.refused(image, "does not have its digest")

    def test_a_digest_of_another_algorithm(self):
        image = Image()
        image.entries[0] = dict(image.entries[0], digest="sha512:" + "a" * 128)
        self.refused(image, "not a SHA-256 digest")

    def test_the_builder_reports_another_index(self):
        image = Image()
        image.reported = "sha256:" + "0" * 64
        self.refused(image, "the builder reports")


# The stand-in container client: every invocation's arguments, one per line
# and a blank line after, appended to $STUB_LOG; an `inspect` answered with
# the bytes of $STUB_RAW, a `copy` with nothing, and both with $STUB_EXIT.
STUB = """#!/bin/sh
for a in "$@"; do printf '%s\\n' "$a" >> "$STUB_LOG"; done
printf '\\n' >> "$STUB_LOG"
for a in "$@"; do
  if [ "$a" = inspect ]; then cat "$STUB_RAW"; fi
done
exit "${STUB_EXIT:-0}"
"""


class Push(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.bin = os.path.join(self.root, "bin")
        os.mkdir(self.bin)
        stub = os.path.join(self.bin, "docker")
        with open(stub, "w") as f:
            f.write(STUB)
        os.chmod(stub, stat.S_IRWXU)
        self.out = os.path.join(self.root, "out")
        os.mkdir(self.out)
        self.index = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
        with open(os.path.join(self.out, "engine-image.index.json"), "wb") as f:
            f.write(self.index)
        with open(os.path.join(self.out, "engine-image.digest"), "w") as f:
            f.write(digest_of(self.index) + "\n")
        self.raw = os.path.join(self.root, "raw")
        self.served(self.index)
        self.log = os.path.join(self.root, "log")

    def served(self, data):
        with open(self.raw, "wb") as f:
            f.write(data)

    def push(self, ref, **env):
        environment = {"PATH": self.bin + os.pathsep + "/usr/bin" + os.pathsep + "/bin",
                       "STUB_LOG": self.log, "STUB_RAW": self.raw}
        environment.update(env)
        return subprocess.run(["bash", SCRIPT, "push", self.out, ref], env=environment, capture_output=True, text=True)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as f:
            return [c.split("\n") for c in f.read().split("\n\n") if c]

    def test_the_tag_read_back_names_the_digest(self):
        done = self.push("ghcr.io/example/engine:1.2.3")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("pushed ghcr.io/example/engine:1.2.3@" + digest_of(self.index), done.stdout)
        copy, inspect = self.calls()
        self.assertEqual(copy[-6:], ["copy", "--all", "--preserve-digests", "--dest-tls-verify=true",
                                     "oci-archive:/image/engine-image.tar", "docker://ghcr.io/example/engine:1.2.3"])
        self.assertEqual(inspect[-3:], ["--raw", "--tls-verify=true", "docker://ghcr.io/example/engine:1.2.3"])

    def test_the_tag_read_back_names_another_image(self):
        self.served(self.index + b" ")
        done = self.push("ghcr.io/example/engine:1.2.3")
        self.assertEqual(done.returncode, 1)
        self.assertIn("names sha256:" + hashlib.sha256(self.index + b" ").hexdigest() + ", not the image built", done.stderr)
        self.assertNotIn("pushed", done.stdout)

    def test_a_copy_that_fails_is_not_read_back(self):
        done = self.push("ghcr.io/example/engine:1.2.3", STUB_EXIT="1")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(len(self.calls()), 1)

    def test_only_this_hosts_loopback_goes_without_tls(self):
        done = self.push("127.0.0.1:5000/engine:ci")
        self.assertEqual(done.returncode, 0, done.stderr)
        copy, inspect = self.calls()
        self.assertIn("--dest-tls-verify=false", copy)
        self.assertIn("--tls-verify=false", inspect)
        for ref in ("localhost:5000/engine:ci", "127.0.0.2:5000/engine:ci", "registry.example/127.0.0.1:5000/engine:ci"):
            os.remove(self.log)
            done = self.push(ref)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("--dest-tls-verify=true", self.calls()[0], ref)

    def test_the_credential_is_a_file_never_an_argument(self):
        auth = os.path.join(self.root, "auth.json")
        with open(auth, "w") as f:
            f.write('{"auths":{"ghcr.io":{"auth":"dXNlcjpzZWNyZXQtdG9rZW4="}}}')
        done = self.push("ghcr.io/example/engine:1.2.3", REGISTRY_AUTH_FILE=auth)
        self.assertEqual(done.returncode, 0, done.stderr)
        for call in self.calls():
            self.assertIn(auth + ":/auth.json:ro", call)
            self.assertEqual(call[call.index("--authfile") + 1], "/auth.json")
            self.assertFalse(any("secret-token" in a or "dXNlcjpzZWNyZXQtdG9rZW4=" in a for a in call), call)

    def test_a_reference_by_digest_is_refused(self):
        done = self.push("ghcr.io/example/engine@" + digest_of(self.index))
        self.assertEqual(done.returncode, 1)
        self.assertIn("names a digest; the push is to a tag", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_a_reference_without_a_tag_is_refused(self):
        done = self.push("ghcr.io/example/engine")
        self.assertEqual(done.returncode, 1)
        self.assertIn("is not <registry>/<repository>:<tag>", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_an_index_that_is_not_the_digest_is_refused(self):
        with open(os.path.join(self.out, "engine-image.index.json"), "ab") as f:
            f.write(b" ")
        done = self.push("ghcr.io/example/engine:1.2.3")
        self.assertEqual(done.returncode, 1)
        self.assertIn("engine-image.index.json is not the index", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_a_digest_file_that_is_not_a_digest_is_refused(self):
        with open(os.path.join(self.out, "engine-image.digest"), "w") as f:
            f.write("latest\n")
        done = self.push("ghcr.io/example/engine:1.2.3")
        self.assertEqual(done.returncode, 1)
        self.assertIn("is not a digest", done.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
