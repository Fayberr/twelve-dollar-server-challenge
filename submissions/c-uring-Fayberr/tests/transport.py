#!/usr/bin/env python3
"""Exercise multiple file tables, descriptor reuse, backpressure and keep-alive."""
import argparse
import http.client
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
p = argparse.ArgumentParser()
p.add_argument("--idle", action="store_true")
a = p.parse_args()
raw = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"

def read(stream):
    assert stream.readline().startswith(b"HTTP/1.1 200 ")
    headers = {}
    while True:
        line = stream.readline()
        if line == b"\r\n":
            break
        key, value = line.split(b":", 1)
        headers[key.lower()] = value.strip()
    return json.loads(stream.read(int(headers[b"content-length"])))

def limits():
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "feed.db"
    shutil.copyfile(ROOT / "seed/feed.db", path)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, HOST="127.0.0.1", PORT=str(port), SQLITE_PATH=str(path), JWT_SECRET="test-only")
    proc = subprocess.Popen([os.environ.get("SERVER_BINARY", str(HERE / "bin/server"))], env=env, preexec_fn=limits)
    clients = []
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(.05)
        for _ in range(600):
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall(raw)
            clients.append(s)
        for s in clients:
            with s.makefile("rb") as stream:
                assert read(stream)["status"] == "ok"
        # Reuse sockets belonging to several different io_uring file tables.
        for s in clients[::17]:
            s.sendall(raw)
            with s.makefile("rb") as stream:
                assert read(stream)["status"] == "ok"
        s = clients[0]
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        s.sendall(b"GET /feed HTTP/1.1\r\nHost: x\r\n\r\n" * 128)
        time.sleep(.2)
        with s.makefile("rb") as stream:
            for _ in range(128):
                result = read(stream)
                assert len(result["posts"]) == 20
                assert result["posts"][0]["id"] == 500000
        for s in clients:
            s.close()
        clients.clear()
        for _ in range(400):
            with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
                s.sendall(b"POST /posts HTTP/1.1\r\nContent-Length: 512\r\n")
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(raw)
            with s.makefile("rb") as stream:
                assert read(stream)["status"] == "ok"
            if a.idle:
                time.sleep(66)
                s.sendall(raw)
                with s.makefile("rb") as stream:
                    assert read(stream)["status"] == "ok"
        assert proc.poll() is None
        print("600 clients with nofile=256, multiple tables, reuse, 128 backpressured feeds and 400 abandoned uploads passed" + ("; 66-second keep-alive passed" if a.idle else ""))
    finally:
        for s in clients:
            s.close()
        proc.terminate()
        proc.wait(timeout=10)
