"""Run an implementation against the conformance corpus.

The corpus in `corpus/` is the arbiter. This module is how an implementation
answers to it -- the Python reference by default, or any other implementation
through a small process contract, so a second implementation in another language
needs no Python at all.

    python3 conformance.py                       # the reference, against the corpus
    python3 conformance.py --impl "./gateway"    # any implementation

THE PROCESS CONTRACT an implementation must satisfy, given `--impl CMD`:

  CMD canon
      stdin : one JSON document (the text of the value to canonicalize)
      stdout: the canonical bytes, exactly, with no trailing newline
      exit  : 0 if the value is in the canon domain, non-zero if it is refused

  CMD verify <store-root> <registry-path> <authority>
      stdin : the key, raw bytes
      stdout: {"ok": <bool>, "findings": [{"sessionId":..,"callIndex":..,"status":..}, ..]}
      exit  : 0 when it produced a verdict (a FAILED verdict is still exit 0);
              non-zero only if it could not produce one at all

Findings are compared as a multiset: order is NOT normative (see corpus/README.md).
"""

import argparse
import binascii
import glob
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")


def _key():
    # .strip(), not .rstrip(b"\n"): a checkout that converts line endings would
    # otherwise leave a \r inside the key, and every HMAC in the corpus would
    # fail for a reason that looks like a format disagreement.
    with open(os.path.join(CORPUS, "TEST-KEY"), "rb") as handle:
        return handle.read().strip()


def _materialize(case):
    """Write a store case to disk and return (root, store_root, registry_path)."""
    root = tempfile.mkdtemp()
    store_root = os.path.join(root, "store")
    for path, text in case["files"].items():
        full = os.path.join(store_root, path.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:          # bytes: never newline-translated
            handle.write(text.encode("utf-8"))
    for required in ("receipts", "artifacts"):
        os.makedirs(os.path.join(store_root, required), exist_ok=True)
    registry_path = os.path.join(root, "registry.jsonl")
    with open(registry_path, "wb") as handle:
        handle.write(case["registry"].encode("utf-8"))
    return root, store_root, registry_path


def _sorted_findings(findings):
    return sorted((json.dumps(f, sort_keys=True) for f in findings))


class Reference:
    """The in-process Python reference."""

    def canon(self, source):
        import attest
        try:
            return attest.canon(json.loads(source))
        except attest.AttestationError:
            return None

    def verify(self, store_root, registry_path, key, authority):
        import attest
        import registry as registry_module
        ok, findings = registry_module.verify_with_registry(
            attest.verify_store, store_root, key, registry_path, authority)
        return {"ok": ok, "findings": findings}


class Subprocess:
    """Any implementation satisfying the process contract above."""

    def __init__(self, command):
        self.argv = shlex.split(command)

    def canon(self, source):
        done = subprocess.run(self.argv + ["canon"], input=source.encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        return None if done.returncode != 0 else done.stdout

    def verify(self, store_root, registry_path, key, authority):
        done = subprocess.run(self.argv + ["verify", store_root, registry_path, authority],
                              input=key, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=120)
        if done.returncode != 0:
            raise RuntimeError("verify failed to produce a verdict: %s"
                               % done.stderr.decode("utf-8", "replace")[:300])
        return json.loads(done.stdout.decode("utf-8"))


def run(implementation):
    """Return (failures, counts). A failure is a human-readable disagreement."""
    failures = []
    with open(os.path.join(CORPUS, "canon.json")) as handle:
        canon_cases = json.load(handle)["vectors"]

    for vector in canon_cases:
        produced = implementation.canon(vector["inputJson"])
        if vector.get("reject"):
            if produced is not None:
                failures.append("canon %r: expected REFUSAL, produced %r (%s)"
                                % (vector["inputJson"], produced, vector["note"]))
            continue
        expected = binascii.unhexlify(vector["expectedHex"])
        if produced is None:
            failures.append("canon %r: expected bytes, got a REFUSAL (%s)"
                            % (vector["inputJson"], vector["note"]))
        elif produced != expected:
            failures.append("canon %r: expected %r, produced %r (%s)"
                            % (vector["inputJson"], expected, produced, vector["note"]))

    key = _key()
    store_cases = sorted(glob.glob(os.path.join(CORPUS, "stores", "*.json")))
    for path in store_cases:
        with open(path) as handle:
            case = json.load(handle)
        root, store_root, registry_path = _materialize(case)
        try:
            got = implementation.verify(store_root, registry_path, key, case["authority"])
        finally:
            shutil.rmtree(root, ignore_errors=True)
        if bool(got.get("ok")) != bool(case["expected"]["ok"]):
            failures.append("store %s: expected ok=%s, got ok=%s"
                            % (case["name"], case["expected"]["ok"], got.get("ok")))
        want = _sorted_findings(case["expected"]["findings"])
        have = _sorted_findings(got.get("findings", []))
        if want != have:
            failures.append("store %s: findings disagree\n    expected: %s\n    produced: %s"
                            % (case["name"], want, have))
    return failures, (len(canon_cases), len(store_cases))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--impl", help="command satisfying the process contract; "
                                       "omit to test the in-process Python reference")
    args = parser.parse_args(argv)
    implementation = Subprocess(args.impl) if args.impl else Reference()
    label = args.impl or "python reference"
    failures, (canon_count, store_count) = run(implementation)
    print("%s vs corpus: %d canon vectors, %d store vectors" % (label, canon_count, store_count))
    for failure in failures:
        print("  FAIL %s" % failure)
    print("%d disagreement(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
