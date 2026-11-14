"""The engine image as build/engine-image.sh built it, held before anything
uses it: the OCI archive names exactly one image index; that index holds one
image manifest for each platform asked for and nothing else -- no attestation
manifest, no platform more or fewer, no variant or feature a reader would have
to choose by; every blob it names, and the index itself, has the digest it is
named by; and the builder's own report names that index. What it writes beside
the archive is the index's bytes (engine-image.index.json), whose SHA-256 is the
image digest, and that digest (engine-image.digest) -- what the release lists in
checksums.txt, attests and pushes by.

For the check of each platform's filesystem (engine-image.sh check) it also
names the one manifest of an index for a platform: the image's own index, or
the runtime pin's as its registry serves it, held to the digest the pin names.

Standard library only. Usage (build/engine-image.sh runs it):
python3 -I build/engine_image.py <dir> <platform>[,<platform>...]
python3 -I build/engine_image.py manifest <index.json> <os>/<architecture> [sha256:<hex>]"""
import hashlib
import json
import os
import sys
import tarfile

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"


class Refusal(Exception):
    pass


def blob(archive, digest):
    """The bytes of the blob a descriptor names, held to that name."""
    algorithm, _, hexdigest = str(digest).partition(":")
    if algorithm != "sha256" or len(hexdigest) != 64 or set(hexdigest) - set("0123456789abcdef"):
        raise Refusal("a descriptor names %r, not a SHA-256 digest" % (digest,))
    try:
        member = archive.extractfile("blobs/sha256/" + hexdigest)
    except KeyError:
        member = None
    if member is None:
        raise Refusal("the archive holds no blob %s" % digest)
    data = member.read()
    if hashlib.sha256(data).hexdigest() != hexdigest:
        raise Refusal("the blob %s does not have its digest" % digest)
    return data


def check(out, platforms):
    """The image index's digest and bytes, or a Refusal saying why not."""
    with tarfile.open(os.path.join(out, "engine-image.tar")) as archive:
        top = json.load(archive.extractfile("index.json"))
        manifests = top.get("manifests")
        if not isinstance(manifests, list) or len(manifests) != 1 or manifests[0].get("mediaType") != INDEX:
            raise Refusal("the archive's index.json does not name exactly one image index")
        digest = manifests[0].get("digest")
        data = blob(archive, digest)
        index = json.loads(data)
        if index.get("mediaType") != INDEX:
            raise Refusal("the image index is not an OCI image index")
        named = []
        for m in index.get("manifests", []):
            p = m.get("platform")
            if m.get("mediaType") != MANIFEST or not isinstance(p, dict) or set(p) != {"os", "architecture"}:
                raise Refusal("the index holds %r, which is not one platform's image manifest" % (m,))
            blob(archive, m.get("digest"))
            named.append(p["os"] + "/" + p["architecture"])
        if sorted(named) != sorted(platforms):
            raise Refusal("the index holds %s, not exactly %s" % (", ".join(named) or "nothing", ", ".join(platforms)))
    with open(os.path.join(out, "engine-image.metadata.json")) as f:
        reported = json.load(f).get("containerimage.digest")
    if reported != digest:
        raise Refusal("the builder reports %r, and the archive's index is %s" % (reported, digest))
    return digest, data


INDEXES = (INDEX, "application/vnd.docker.distribution.manifest.list.v2+json")


def manifest(data, platform, digest=None):
    """The digest of the one manifest an index holds for os/architecture,
    whatever variant it names; with digest, the index must be those bytes.
    Entries of another platform (an attestation's unknown/unknown among
    them) are passed over; none, or two, for this one is a Refusal."""
    if digest is not None and "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise Refusal("the index read is not %s" % digest)
    index = json.loads(data)
    if not isinstance(index, dict) or index.get("mediaType") not in INDEXES or not isinstance(index.get("manifests"), list):
        raise Refusal("that is not an image index")
    wanted = platform.split("/")
    found = [m.get("digest") for m in index["manifests"]
             if isinstance(m, dict) and isinstance(m.get("platform"), dict)
             and [m["platform"].get("os"), m["platform"].get("architecture")] == wanted]
    if len(found) != 1:
        raise Refusal("the index holds %d manifests for %s, not one" % (len(found), platform))
    algorithm, _, hexdigest = str(found[0]).partition(":")
    if algorithm != "sha256" or len(hexdigest) != 64 or set(hexdigest) - set("0123456789abcdef"):
        raise Refusal("the index names %r for %s, not a SHA-256 digest" % (found[0], platform))
    return found[0]


def main_manifest(path, platform, digest=None):
    try:
        with open(path, "rb") as f:
            print(manifest(f.read(), platform, digest))
    except (Refusal, ValueError) as refusal:
        print("engine-image: %s: %s" % (path, refusal), file=sys.stderr)
        return 1
    return 0


def main(out, platforms):
    try:
        digest, data = check(out, platforms.split(","))
    except Refusal as refusal:
        print("engine-image: %s" % refusal, file=sys.stderr)
        return 1
    with open(os.path.join(out, "engine-image.index.json"), "wb") as f:
        f.write(data)
    with open(os.path.join(out, "engine-image.digest"), "w") as f:
        f.write(digest + "\n")
    print("engine image %s for %s" % (digest, ", ".join(sorted(platforms.split(",")))))
    return 0


if __name__ == "__main__":
    if len(sys.argv) in (4, 5) and sys.argv[1] == "manifest":
        sys.exit(main_manifest(*sys.argv[2:]))
    if len(sys.argv) != 3:
        sys.exit("usage: engine_image.py <dir> <platform>[,<platform>...] | manifest <index.json> <os>/<architecture> [sha256:<hex>]")
    sys.exit(main(sys.argv[1], sys.argv[2]))
