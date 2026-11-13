"""The engine image as build/engine-image.sh built it, held before anything
uses it: the OCI archive names exactly one image index; that index holds one
image manifest for each platform asked for and nothing else -- no attestation
manifest, no platform more or fewer, no variant or feature a reader would have
to choose by; every blob it names, and the index itself, has the digest it is
named by; and the builder's own report names that index. What it writes beside
the archive is the index's bytes (engine-image.index.json), whose SHA-256 is the
image digest, and that digest (engine-image.digest) -- what the release lists in
checksums.txt, attests and pushes by.

Standard library only. Usage (build/engine-image.sh runs it):
python3 -I build/engine_image.py <dir> <platform>[,<platform>...]"""
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
    if len(sys.argv) != 3:
        sys.exit("usage: engine_image.py <dir> <platform>[,<platform>...]")
    sys.exit(main(sys.argv[1], sys.argv[2]))
