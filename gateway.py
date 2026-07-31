"""The open reference gateway — the hosted deployment shape of the
trustworthy-input-acquisition line (judgment-pack-evaluator-experiments,
ADR-0002).

A small HTTP service that holds a *protected signing identity* (the key lives in
the service, not in any client or downstream), attests each acquired result under
that one identity, and seals each session in the registry so a verifier can catch
whole-session replay and tail rollback. This is the OPEN reference: the format,
the registry contract, and the verifier are all here and inspectable, because an
attestation nobody can verify is worth nothing. A managed, credentialed,
multi-source operation of this same mechanism is a separate commercial concern
(see README).

Standard library only. This reference gateway binds to localhost and is for
development, demonstration, and self-hosting a trust root -- not a hardened
public deployment.
"""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import attest
import registry


class Gateway:
    """Holds the protected identity and the per-session attestation state."""

    def __init__(self, store_root, key, authority, registry_path, sources):
        self.store = attest.Store(store_root, key, authority)
        self.store_root = store_root
        self.key = key
        self.authority = authority
        self.registry = registry.Registry(registry_path, key)
        self.registry_path = registry_path
        self.sources = dict(sources)  # source name -> argv that reads args JSON on stdin, emits result JSON
        self._sessions = {}           # session id -> {"index": int, "prev": str|None, "sealed": bool}
        self._lock = threading.Lock()

    def acquire(self, session_id, source, arguments):
        """Run a configured source, attest its result under the gateway identity,
        chain and retain it, and return the result plus a receipt summary. The
        gateway -- not the caller -- produces the receipt; the caller cannot
        supply one."""
        if source not in self.sources:
            raise KeyError("unknown source: %s" % source)
        completed = subprocess.run(
            self.sources[source], input=attest.canon(arguments),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError("source failed: %s" % completed.stderr.decode("utf-8", "replace")[:200])
        result = json.loads(completed.stdout.decode("utf-8"))
        with self._lock:
            state = self._sessions.setdefault(session_id, {"index": 0, "prev": None, "sealed": False})
            if state["sealed"]:
                raise RuntimeError("session is sealed: %s" % session_id)
            index, prev = state["index"], state["prev"]
            result_digest = self.store.retain(attest.canon(result))
            core = {
                "receiptVersion": attest.RECEIPT_VERSION, "sessionId": session_id,
                "callIndex": index, "prevHmac": prev, "source": source,
                "argumentsDigest": self.store.keyed_digest("args", attest.canon(arguments)),
                "resultDigest": result_digest, "servedAt": attest.now(),
                "authority": self.authority,
            }
            stored = self.store.stamp(core)
            state["index"] = index + 1
            state["prev"] = stored["hmac"]
        return {"result": result, "receipt": {
            "sessionId": session_id, "callIndex": index, "resultDigest": result_digest,
            "authority": self.authority}}

    def seal(self, session_id):
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                raise KeyError("no such session: %s" % session_id)
            record = self.registry.seal(session_id, state["index"], attest.now())
            state["sealed"] = True
        return record

    def verify(self):
        ok, findings = registry.verify_with_registry(
            attest.verify_store, self.store_root, self.key, self.registry_path, self.authority)
        return {"ok": ok, "findings": findings}

    def registry_bytes(self):
        if not os.path.exists(self.registry_path):
            return b""
        with open(self.registry_path, "rb") as handle:
            return handle.read()


def _handler(gateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body):
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        def do_GET(self):
            try:
                if self.path == "/verify":
                    self._send(200, gateway.verify())
                elif self.path == "/registry":
                    self._send(200, gateway.registry_bytes())
                else:
                    self._send(404, {"error": "not found"})
            except Exception as error:  # noqa: BLE001 -- reference service, report and continue
                self._send(500, {"error": str(error)})

        def do_POST(self):
            try:
                body = self._read_json()
                if self.path == "/acquire":
                    out = gateway.acquire(body["session"], body["source"], body.get("arguments", {}))
                    self._send(200, out)
                elif self.path == "/seal":
                    self._send(200, gateway.seal(body["session"]))
                else:
                    self._send(404, {"error": "not found"})
            except (KeyError, RuntimeError, ValueError) as error:
                self._send(400, {"error": str(error)})
            except Exception as error:  # noqa: BLE001
                self._send(500, {"error": str(error)})

        def log_message(self, *args):
            pass  # quiet

    return Handler


def serve(host, port, gateway):
    server = ThreadingHTTPServer((host, port), _handler(gateway))
    return server


def main(argv):
    if len(argv) < 5:
        sys.stderr.write(
            "usage: gateway.py <store> <keyfile> <authority> <registry> "
            "[--source NAME=CMD ...] [--port N]\n")
        return 2
    store_root, key_path, authority, registry_path = argv[1:5]
    with open(key_path, "rb") as handle:
        key = handle.read()
    sources, port = {}, 8787
    rest = argv[5:]
    i = 0
    while i < len(rest):
        if rest[i] == "--source" and i + 1 < len(rest):
            name, cmd = rest[i + 1].split("=", 1)
            sources[name] = cmd.split()
            i += 2
        elif rest[i] == "--port" and i + 1 < len(rest):
            port = int(rest[i + 1])
            i += 2
        else:
            i += 1
    gw = Gateway(store_root, key, authority, registry_path, sources)
    server = serve("127.0.0.1", port, gw)
    sys.stderr.write("gateway on http://127.0.0.1:%d (authority %s)\n" % (port, authority))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
