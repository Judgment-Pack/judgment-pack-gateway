"""A stand-in for the engine the smoke runs talk to: the routes a client
plugin calls, answered as the local engine of plugins/smoke/README.md ("The
engine") answers them -- one synthetic source named screening, no identity
-- and, on request, answered wrongly in one named way (answers.FAULTS), so
that a checker's refusal of that wrong answer can be tested without the
engine, n8n or a container. Standard library only. Nothing it answers is
signed: it stands in for the shape of the engine's answers, never for their
verification. test_stand_in_engine.py holds it to the engine itself,
request for request.

    python3 stand_in_engine.py <port> [--fault NAME] [--require-length]

As the engine does, it answers, routing by path whatever the query:
  /publickey       the key document, to any method (HEAD without a body)
  POST /acquire    reads the body as the engine does -- at most 1 MiB, one
                   value, decoded into its struct with member names matched
                   without regard to case, the last of several taking the
                   place, a string's lone surrogates and bytes that are not
                   UTF-8 read as U+FFFD, others ignored, nested as deep as
                   Go's decoder takes -- then holds
                   the arguments to the canonical domain, then refuses a
                   session that is not a flat token, then a source other
                   than screening, then a sealed session: each a 400 in the
                   engine's words (a malformed body's words are Go's
                   decoder's, and differ here). Otherwise the source's echo
                   of the arguments -- {} when the member is absent, as given
                   (null included) when it is there -- with a complete
                   version 3 receipt chained to the session's last, and the
                   arguments salt
  POST /act        401 with a Bearer challenge, the handler's decision made
                   before the body is read, as an engine with no identity
                   refuses every action; it then takes what the client still
                   sends, briefly, and closes
  POST /seal       reads the session as /acquire does and refuses, 400, one
                   that is not a flat token, one it does not hold, or one
                   already sealed; otherwise the seal at the count the
                   session holds
  another method on /acquire, /act or /seal: 404 {"error": "not found"}
  any other path: 404 page not found, as the engine's router answers
It sends the engine's headers: no Server, a Date, on the router's 404
X-Content-Type-Options: nosniff, and a Content-Length, except on an answer
past the 2048 bytes the engine's server buffers, which it chunks.

--require-length refuses a request body sent chunked (411) before any route
answers, as a server or proxy in front of the engine that takes no chunked
upload would -- the engine itself takes one.
"""
import argparse
import http.server
import json
import os
import socket
import sys
import threading
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import answers  # noqa: E402

ROUTES = ("/publickey", "/acquire", "/act", "/seal")


def flat_token(session):
    return answers.SESSION_PATTERN.fullmatch(session) is not None and session not in (".", "..")


def make_handler(fault, require_length):
    lock = threading.Lock()
    # session -> its count, its last receipt's signature, and whether sealed
    sessions = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def send_response(self, code, message=None):
            # the engine sends a Date and no Server
            self.log_request(code)
            self.send_response_only(code, message)
            self.send_header("Date", self.date_time_string())

        def _send(self, code, body, headers=()):
            if isinstance(body, str):
                data, kind = body.encode(), "text/plain; charset=utf-8"
                headers = (*headers, ("X-Content-Type-Options", "nosniff"))
            else:
                data, kind = answers.go_json(body).encode(), "application/json"
            # the engine's server buffers 2048 bytes of an answer whose
            # length it was not told, and chunks one that outgrows them
            chunked = len(data) > 2048 and self.command != "HEAD"
            self.send_response(code)
            self.send_header("Content-Type", kind)
            for name, value in headers:
                self.send_header(name, value)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if chunked:
                self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n0\r\n\r\n")
            elif self.command != "HEAD":
                self.wfile.write(data)

        def _answer(self, route, code, body, headers=()):
            # the fault, when it is at this route, in place of the answer
            if fault and fault.route == route:
                if fault.status:
                    code, body = fault.status, fault.value
                    headers = (("WWW-Authenticate", "Bearer"),) if fault.status == 401 else ()
                else:
                    body = answers.apply(fault, body)
            self._send(code, body, headers)

        def _chunked(self):
            return "chunked" in self.headers.get("Transfer-Encoding", "").lower()

        def _body(self):
            """The body, read to one byte past the engine's bound and no
            further, as its limitBody reads it: what lies past that is left
            unread, and the answer's close lingers over it."""
            limit = answers.MAX_BODY_BYTES + 1
            if self._chunked():
                raw = b""
                while len(raw) < limit:
                    size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                            pass
                        return raw
                    raw += self.rfile.read(min(size, limit - len(raw)))
                    if len(raw) < limit:
                        self.rfile.readline()
                self.close_unread = True
                return raw
            declared = int(self.headers.get("Content-Length") or 0)
            if declared > limit:
                self.close_unread = True
            return self.rfile.read(min(declared, limit))

        def _linger(self):
            # answered before the body was read: end the answer, then take
            # what the client still sends, briefly, so that closing does not
            # reset a connection it is still writing to -- the engine's
            # server lingers the same way
            try:
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(0.5)
                while self.connection.recv(65536):
                    pass
            except OSError:
                pass

        def _route(self):
            return urllib.parse.urlsplit(self.path).path

        def _fields(self, names):
            """The request's fields as the engine reads them, or None once
            refused."""
            try:
                return answers.request_fields(self._body(), names)
            except answers.Refusal as refusal:
                self._send(400, {"error": refusal.message})
                if getattr(self, "close_unread", False):
                    self._linger()
                return None

        def _elsewhere(self):
            route = self._route()
            if route == "/publickey":
                self._answer("publickey", 200, answers.public_key())
            elif route in ROUTES:
                self._send(404, {"error": "not found"})
            else:
                self._send(404, "404 page not found\n")
            self._linger()

        do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _elsewhere

        def do_POST(self):
            route = self._route()
            if route not in ROUTES:
                self._send(404, "404 page not found\n")
                self._linger()
                return
            if require_length and self._chunked():
                self._send(411, {"error": "a request body needs a Content-Length here"})
                self._linger()
                return
            if route == "/publickey":
                self._answer("publickey", 200, answers.public_key())
                self._linger()
            elif route == "/act":
                self._act()
            elif route == "/acquire":
                self._acquire()
            else:
                self._seal()

        def _act(self):
            if fault and fault.route == "act":
                self._body()
                self._answer("act", 200, {})
                return
            # no identity: nobody is a requester, and the body is not read
            self._send(401, answers.ACT_REFUSAL, [("WWW-Authenticate", "Bearer")])
            self._linger()

        def _acquire(self):
            fields = self._fields(("session", "source", "arguments"))
            if fields is None:
                return
            arguments = {}
            if "arguments" in fields:
                try:
                    arguments = answers.canonical_arguments(fields["arguments"])
                except answers.Refusal as refusal:
                    return self._send(400, {"error": refusal.message})
            session, source = fields.get("session", ""), fields.get("source", "")
            if not flat_token(session):
                return self._send(400, {"error": answers.SESSION_REFUSAL})
            if source != answers.SOURCE:
                return self._send(400, {"error": f"unknown source: {source}"})
            with lock:
                state = sessions.setdefault(session, {"count": 0, "last": None, "sealed": False})
                if state["sealed"]:
                    answer = None
                else:
                    answer = answers.acquisition(session, state["count"], state["last"], arguments, answers.stamp())
                    state["count"] += 1
                    state["last"] = answer["receipt"]["signature"]
            if answer is None:
                return self._send(400, {"error": f"session is sealed: {session}"})
            self._answer("acquire", 200, answer)

        def _seal(self):
            fields = self._fields(("session",))
            if fields is None:
                return
            session = fields.get("session", "")
            if not flat_token(session):
                return self._send(400, {"error": answers.SESSION_REFUSAL})
            with lock:
                state = sessions.get(session)
                if state is None:
                    refusal = f"no such session: {session}"
                elif state["sealed"]:
                    refusal = f"session already sealed: {session}"
                else:
                    refusal = None
                    state["sealed"] = True
                    answer = answers.seal(session, state["count"], answers.stamp())
            if refusal:
                return self._send(400, {"error": refusal})
            self._answer("seal", 200, answer)

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("port", type=int)
    parser.add_argument("--fault", choices=answers.FAULT_NAMES)
    parser.add_argument("--require-length", action="store_true")
    args = parser.parse_args()
    fault = answers.fault_named(args.fault) if args.fault else None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(fault, args.require_length))
    print(f"stand-in engine on 127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
