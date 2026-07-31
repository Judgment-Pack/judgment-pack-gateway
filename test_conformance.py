"""The corpus must have teeth.

It is easy to ship a conformance suite that every implementation passes, which
proves nothing. These tests check the other direction: implementations that are
wrong in the specific, realistic ways a second implementation goes wrong must be
CAUGHT by the corpus. Each divergence below is one a competent author would
plausibly ship, because it is the default behaviour of a standard library.
"""

import json
import unittest

import attest
import conformance
import registry


class ReferenceAgreesWithCorpus(unittest.TestCase):
    def test_reference_passes_every_vector(self):
        failures, (canon_count, store_count) = conformance.run(conformance.Reference())
        self.assertEqual(failures, [], "reference disagrees with its own corpus")
        self.assertGreaterEqual(canon_count, 20)
        self.assertGreaterEqual(store_count, 12)


class _Divergent(conformance.Reference):
    """The reference with one realistic defect injected."""

    def __init__(self, canon_defect=None, drop_registry=False):
        self.canon_defect = canon_defect
        self.drop_registry = drop_registry

    def canon(self, source):
        if self.canon_defect is None:
            return super().canon(source)
        try:
            value = json.loads(source)
            attest.canon(value)          # keep the domain rules honest
        except attest.AttestationError:
            return None
        return self.canon_defect(value)

    def verify(self, store_root, registry_path, key, authority):
        if not self.drop_registry:
            return super().verify(store_root, registry_path, key, authority)
        # An implementation that verifies each receipt but forgets the registry
        # anchor -- exactly the gap the gateway exists to close.
        ok, findings = attest.verify_store(store_root, key, authority)
        return {"ok": ok, "findings": findings}


def _html_escaping(value):
    """Go's encoding/json escapes < > & by default."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .encode("utf-8"))


def _ascii_escaping(value):
    """Python's json.dumps defaults to ensure_ascii=True."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utf16_ordering(value):
    """Ordering member names by UTF-16 code unit -- what RFC 8785 says, and what
    the runtime's own internal/jcs does. It disagrees with code-point ordering on
    any non-BMP member name."""
    def order(node):
        if isinstance(node, dict):
            return {k: order(node[k])
                    for k in sorted(node, key=lambda s: s.encode("utf-16-be"))}
        if isinstance(node, list):
            return [order(item) for item in node]
        return node
    return json.dumps(order(value), sort_keys=False, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class CorpusCatchesRealisticDivergence(unittest.TestCase):
    def _failures(self, **kwargs):
        failures, _counts = conformance.run(_Divergent(**kwargs))
        return failures

    def test_html_escaping_is_caught(self):
        failures = self._failures(canon_defect=_html_escaping)
        self.assertTrue(any("<a>&b</a>" in f for f in failures),
                        "corpus missed Go-style HTML escaping: %s" % failures)

    def test_ascii_escaping_is_caught(self):
        failures = self._failures(canon_defect=_ascii_escaping)
        self.assertTrue(any("caf" in f or "u00e9" in f for f in failures),
                        "corpus missed ensure_ascii escaping: %s" % failures)

    def test_utf16_member_ordering_is_caught(self):
        failures = self._failures(canon_defect=_utf16_ordering)
        self.assertTrue(failures, "corpus missed UTF-16 member ordering")
        self.assertTrue(any("CODE POINT" in f or "\\ud83d" in f or "\U0001f600" in f
                            for f in failures),
                        "caught something, but not the ordering vector: %s" % failures)

    def test_forgetting_the_registry_anchor_is_caught(self):
        failures = self._failures(drop_registry=True)
        joined = "\n".join(failures)
        for missed in ("tail-rollback", "unregistered-session", "count-exceeds-seal",
                       "sealed-session-missing"):
            self.assertIn(missed, joined,
                          "corpus did not catch a verifier ignoring the registry")


if __name__ == "__main__":
    unittest.main()
