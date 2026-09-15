"""A stand-in for the engine the smoke runs talk to: the four routes a client
plugin calls, answered as a local engine with one synthetic source and no
identity answers them (plugins/smoke/README.md, "The engine") -- and, on
request, answered wrongly in one named way, so that a checker's refusal of
that wrong answer can be tested without the engine, n8n or a container.
Standard library only. Nothing it answers is signed; it stands in for the
shape of the engine's answers, never for their verification.

    python3 stand_in_engine.py <port> [--fault NAME] [--require-length]

Faults, one at a time:
  kind         the receipt's kind is "action", not "acquisition"
  index        the receipt's callIndex is 1, not 0
  session      the receipt names another session than the one asked for
  signature    the receipt's signature is not 128 lowercase hex characters
  result       the result is not the source's echo of the arguments
  salt         the answer carries no arguments salt
  act-accepted /act answers 200 instead of the engine's 401
  seal-count   the seal's finalCount is one more than the session holds
  seal-session the seal names another session

--require-length refuses a request body sent without a Content-Length
(411), as a server that does not take chunked uploads would.
"""
import argparse
import http.server
import json
import threading

FAULTS = ("kind", "index", "session", "signature", "result", "salt", "act-accepted", "seal-count", "seal-session")


def make_handler(fault, require_length):
    counts = {}
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                if require_length:
                    return None
                raw = b""
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    raw += self.rfile.read(size)
                    self.rfile.readline()
                return raw
            length = self.headers.get("Content-Length")
            if length is None:
                return None if require_length else b""
            return self.rfile.read(int(length))

        def do_GET(self):
            if self.path == "/publickey":
                self._send(200, {"algorithm": "ed25519", "keyId": "0" * 16, "publicKey": "0" * 64, "authority": "gateway:smoke"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            raw = self._body()
            if raw is None:
                self._send(411, {"error": "a request body needs a Content-Length here"})
                return
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                self._send(400, {"error": "the body is not JSON"})
                return
            session = body.get("session")
            if self.path == "/acquire":
                with lock:
                    index = counts.get(session, 0)
                    counts[session] = index + 1
                receipt = {
                    "receiptVersion": "3",
                    "kind": "action" if fault == "kind" else "acquisition",
                    "sessionId": "another-session" if fault == "session" else session,
                    "callIndex": index + (1 if fault == "index" else 0),
                    "signature": ("A" * 128) if fault == "signature" else ("a" * 128),
                }
                result = {"synthetic": True, "arguments": body.get("arguments")}
                if fault == "result":
                    result = {"synthetic": True, "arguments": {"subject": "someone else"}}
                answer = {"result": result, "receipt": receipt, "salts": {} if fault == "salt" else {"args": "b" * 64}}
                self._send(200, answer)
            elif self.path == "/act":
                if fault == "act-accepted":
                    self._send(200, {"result": {}, "receipt": {"kind": "action"}, "salts": {}})
                else:
                    self._send(401, {"error": "a requester is required; this engine has no identity configured", "refusedAt": "requester"})
            elif self.path == "/seal":
                with lock:
                    count = counts.get(session, 0)
                self._send(200, {
                    "sessionId": "another-session" if fault == "seal-session" else session,
                    "finalCount": count + (1 if fault == "seal-count" else 0),
                    "sealedAt": "2026-09-15T00:00:00Z",
                    "keyId": "0" * 16,
                    "signature": "c" * 128,
                })
            else:
                self._send(404, {"error": "not found"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("port", type=int)
    parser.add_argument("--fault", choices=FAULTS)
    parser.add_argument("--require-length", action="store_true")
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.fault, args.require_length))
    print(f"stand-in engine on 127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
