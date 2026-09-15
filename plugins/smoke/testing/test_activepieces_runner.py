"""The Activepieces smoke runner (plugins/smoke/activepieces/run.mjs) held
to its refusals, against the stand-in engine.

run.mjs drives the built piece's actions as the framework calls them and
checks each answer. These tests run it against the stand-in engine as the
engine answers, and once for each wrong answer in answers.FAULTS that this
runner reads, and require it to fail on each at the check the fault names
-- the first failure, which ends the run. They need Node and the piece
built (npm run build in plugins/activepieces/judgment-pack); without either
they skip, unless SMOKE_REQUIRE_PIECE is set, as CI sets it where the piece
is built, and then they fail.
"""
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import answers  # noqa: E402
from harness import StandIn  # noqa: E402

RUNNER = os.path.join(HERE, "..", "activepieces", "run.mjs")
PIECE = os.path.normpath(os.path.join(HERE, "..", "..", "activepieces", "judgment-pack"))


def failed_checks(stdout):
    return [line.split(":", 2)[1].strip() for line in stdout.splitlines() if line.startswith("FAIL: ")]


class RunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        node = shutil.which("node")
        built = os.path.exists(os.path.join(PIECE, "dist", "src", "index.js"))
        if not (node and built):
            why = "node is not on the path" if not node else "the piece is not built"
            if os.environ.get("SMOKE_REQUIRE_PIECE"):
                raise AssertionError("the Activepieces runner cannot run: " + why)
            raise unittest.SkipTest(why)
        cls.node = node

    def run_runner(self, *flags):
        with StandIn(*flags) as engine:
            return subprocess.run([self.node, RUNNER, PIECE, f"http://127.0.0.1:{engine.port}"], capture_output=True, text=True, timeout=120)

    def test_the_answers_the_engine_gives_pass(self):
        done = self.run_runner()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ACTIVEPIECES SMOKE OK", done.stdout)
        self.assertEqual(failed_checks(done.stdout), [])

    def test_each_wrong_answer_fails_its_check(self):
        for fault in answers.FAULTS:
            if "activepieces" not in fault.checkers:
                continue
            with self.subTest(fault=fault.name):
                done = self.run_runner("--fault", fault.name)
                self.assertNotEqual(done.returncode, 0, f"{fault.name}: the runner passed a wrong answer\n{done.stdout}")
                self.assertNotIn("ACTIVEPIECES SMOKE OK", done.stdout)
                self.assertEqual(failed_checks(done.stdout), [fault.check], done.stdout + done.stderr)

    def test_a_server_that_takes_no_chunked_upload_is_answered(self):
        # the piece states its body's length, so a server that refuses a
        # chunked upload still takes the piece's requests
        done = self.run_runner("--require-length")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ACTIVEPIECES SMOKE OK", done.stdout)


if __name__ == "__main__":
    unittest.main()
