"""The Activepieces smoke runner (plugins/smoke/activepieces/run.mjs) held to
its refusals, against the stand-in engine.

run.mjs drives the built piece's actions as the framework calls them and
asserts each answer. These tests run it against the stand-in engine as the
engine answers, and once for each wrong answer the stand-in can give, and
require it to fail on every one. They need Node and the piece built
(npm run build in plugins/activepieces/judgment-pack); without either they
skip, unless SMOKE_REQUIRE_PIECE is set, as CI sets it where the piece is
built, and then they fail.
"""
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "stand_in_engine.py")
RUNNER = os.path.join(HERE, "..", "activepieces", "run.mjs")
PIECE = os.path.normpath(os.path.join(HERE, "..", "..", "activepieces", "judgment-pack"))
FAULTS = ("kind", "index", "session", "signature", "result", "salt", "act-accepted", "seal-count", "seal-session")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class StandIn:
    def __init__(self, *flags):
        self.port = free_port()
        self.proc = subprocess.Popen([sys.executable, ENGINE, str(self.port), *flags], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.proc.stdout.readline()  # "stand-in engine on ..."
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("the stand-in engine did not start")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)


def runnable():
    node = shutil.which("node")
    built = os.path.exists(os.path.join(PIECE, "dist", "src", "index.js"))
    return node, built


class RunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        node, built = runnable()
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

    def test_every_wrong_answer_fails_the_run(self):
        for fault in FAULTS:
            with self.subTest(fault=fault):
                done = self.run_runner("--fault", fault)
                self.assertNotEqual(done.returncode, 0, f"{fault}: the runner passed a wrong answer\n{done.stdout}")
                self.assertNotIn("ACTIVEPIECES SMOKE OK", done.stdout)

    def test_a_server_that_takes_no_chunked_upload_is_answered(self):
        # the piece states its body's length, so a server that refuses a
        # chunked upload still takes the piece's requests
        done = self.run_runner("--require-length")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
