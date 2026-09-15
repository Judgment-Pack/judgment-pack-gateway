"""What the checkers' tests share: a free port, the stand-in engine and the
engine itself as local processes, and one HTTP exchange with either, read
the way a client reads it. Standard library only."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STAND_IN = os.path.join(HERE, "stand_in_engine.py")

# the synthetic source of plugins/smoke/README.md ("The engine"): it echoes
# the canonical arguments it was given
SOURCE_SCRIPT = """#!/bin/sh
args=$(cat)
printf '{"synthetic":true,"arguments":%s}\\n' "${args:-null}"
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_ready(port, proc, what):
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{what} exited before it listened")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"{what} did not listen on {port}")


class StandIn:
    """The stand-in engine on a port of its own, stopped on exit."""

    def __init__(self, *flags):
        self.port = free_port()
        self.proc = subprocess.Popen([sys.executable, STAND_IN, str(self.port), *flags], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_ready(self.port, self.proc, "the stand-in engine")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)


class Engine:
    """The engine binary started as plugins/smoke/README.md starts it, in a
    directory of its own, stopped on exit."""

    def __init__(self, binary):
        self.dir = tempfile.mkdtemp()
        subprocess.run([binary, "keygen", "gateway.seed"], cwd=self.dir, capture_output=True, check=True)
        source = os.path.join(self.dir, "my_source")
        with open(source, "w") as f:
            f.write(SOURCE_SCRIPT)
        os.chmod(source, 0o755)
        self.port = free_port()
        self.proc = subprocess.Popen(
            [binary, "serve", "./store", "gateway.seed", "gateway:smoke", "./registry.jsonl", "--source", "screening=./my_source", "--port", str(self.port)],
            cwd=self.dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wait_ready(self.port, self.proc, "the engine")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)


def read_answer(status, kind, challenge, raw):
    text = raw.decode()
    body = json.loads(text) if kind.startswith("application/json") else text
    return {"status": status, "type": kind, "challenge": challenge, "body": body, "text": text}


def exchange(port, method, path, body=None, raw=None, chunked=False):
    """One request, sent whole with its length unless chunked, on a
    connection closed with the answer -- as the Activepieces piece sends --
    and the answer as a client reads it."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Connection": "close"}
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    try:
        if data is None:
            conn.request(method, path, headers=headers)
        elif chunked:
            headers.update({"Content-Type": "application/json", "Transfer-Encoding": "chunked"})
            conn.request(method, path, body=iter([data]), headers=headers, encode_chunked=True)
        else:
            headers["Content-Type"] = "application/json"
            conn.request(method, path, body=data, headers=headers)
        res = conn.getresponse()
        return read_answer(res.status, res.getheader("Content-Type", ""), res.getheader("WWW-Authenticate"), res.read())
    finally:
        conn.close()


def early_act(port):
    """An action whose body has not arrived: the head, a length of 1000, and
    eleven bytes of it, on a connection the client asks to close; the answer
    read as it comes, and whether it came within two seconds."""
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.sendall(b"POST /act HTTP/1.1\r\nHost: engine\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"session\":")
    started, data = time.time(), b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    head, _, text = data.partition(b"\r\n\r\n")
    if not head:
        return {"status": 0, "early": False}
    lines = head.decode().split("\r\n")
    fields = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
    answer = read_answer(int(lines[0].split()[1]), fields.get("content-type", ""), fields.get("www-authenticate"), text)
    answer["early"] = time.time() - started < 2
    return answer
