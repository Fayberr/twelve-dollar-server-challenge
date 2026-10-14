#!/usr/bin/env python3
"""Independent API, transport and persistence checks against SPEC.md and SQLite."""
import concurrent.futures
import hashlib
import hmac
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
SECRET = "test-only-signing-key"

def token(payload=None, header=None):
    payload = payload or dict(sub="1", username="claim name", exp=time.time() + 3600)
    enc = lambda x: base64.urlsafe_b64encode(json.dumps(x).encode()).rstrip(b"=")
    msg = enc(header or {"alg": "HS256"}) + b"." + enc(payload)
    return (msg + b"." + base64.urlsafe_b64encode(hmac.digest(SECRET.encode(), msg, "sha256")).rstrip(b"=")).decode()

def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "feed.db"
        shutil.copyfile(ROOT / "seed/feed.db", db)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        env = dict(os.environ, SQLITE_PATH=str(db), JWT_SECRET=SECRET, HOST="127.0.0.1", PORT=str(port))
        server = None
        def start():
            proc = subprocess.Popen([os.environ.get("SERVER_BINARY", str(HERE / "bin/server"))], env=env)
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError("server exited during startup")
                try:
                    if request("GET", "/health")[0] == 200:
                        return proc
                except OSError:
                    time.sleep(.05)
            proc.kill()
            raise AssertionError("startup timed out")
        def request(method, path, body=None, auth=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            headers = {"Authorization": "Bearer " + (auth or token())} if method == "POST" else {}
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            c.request(method, path, body, headers)
            r = c.getresponse()
            result = r.status, json.loads(r.read())
            c.close()
            return result
        def reference():
            with sqlite3.connect(db) as c:
                rows = c.execute("SELECT p.id,p.body,p.created_at,u.username,(SELECT count(*) FROM likes l WHERE l.post_id=p.id) FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC,p.id DESC LIMIT 20").fetchall()
            return dict(posts=[dict(zip(("id", "body", "created_at", "author", "like_count"), r)) for r in rows])
        try:
            expected = reference()
            # A killed io_uring process can release registered sockets asynchronously.
            with socket.socket() as fresh:
                fresh.bind(("127.0.0.1", 0))
                port = fresh.getsockname()[1]
            env["PORT"] = str(port)
            server = start()
            assert request("GET", "/feed") == (200, expected)
            for text in ["\u00a0\u2003hello\ufeff", "\u00e9" * 500, "\U0001f642" * 500, "a\x00b", "line\n\t\"\\end"]:
                status, result = request("POST", "/posts", dict(body=text))
                assert status == 201, (status, result)
                post = result["post"]
                want = "hello" if text.startswith("\u00a0") else text
                assert post["body"] == want
                assert post["author"] == "claim name"
                read = request("GET", f'/posts/{post["id"]}')[1]["post"]
                assert read["body"] == want and read["author"] == "golden_ember_1"
            assert request("POST", "/posts", dict(body="\U0001f642" * 501))[0] == 400
            assert request("POST", "/posts", dict(body="\u2003\ufeff\u00a0"))[0] == 400
            assert request("POST", "/posts", dict(body="complex document", padding=[0] * 5000))[0] == 201
            for body in [b'{"body":"x"} trailing', b'{"body":"\xff"}', b'{"body":"\\ud800"}', b'[]']:
                assert request("POST", "/posts", body)[0] == 400
            for header in [{"alg": "none"}, {"alg": "HS512"}, {"alg": 256}]:
                assert request("POST", "/posts", dict(body="x"), token(header=header))[0] == 401
            for payload in [dict(sub="1", username="x", exp=0), dict(sub="1", username="x", exp="future"), dict(sub="1", username="x"), dict(sub="1", username="x", exp=time.time()+10, nbf=time.time()+3600)]:
                assert request("POST", "/posts", dict(body="x"), token(payload))[0] == 401
            for sub in ["0", "-1", "1.5", "1\x00", 1]:
                assert request("POST", "/posts", dict(body="x"), token(dict(sub=sub, username="x", exp=time.time()+10)))[0] == 401
            status, result = request("POST", "/posts", dict(body="concurrent likes"))
            post_id = result["post"]["id"]
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(lambda _: request("POST", f"/posts/{post_id}/like"), range(32)))
            assert sum(s == 201 for s, _ in results) == 1
            assert all(s in (200, 201) for s, _ in results)
            assert request("GET", f"/posts/{post_id}")[1]["post"]["like_count"] == 1
            bad_user = token(dict(sub="999999999", username="missing", exp=time.time()+60))
            assert request("POST", "/posts", dict(body="FK must fail"), bad_user)[0] == 500
            assert request("POST", f"/posts/{post_id}/like", auth=bad_user)[0] == 500
            # Fragmented headers, pipelining, chunked JSON and 100-continue.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.connect()
            raw = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
            for b in raw:
                c.sock.sendall(bytes([b]))
            r = http.client.HTTPResponse(c.sock); r.begin()
            assert r.status == 200; r.read()
            c.sock.sendall(raw * 128)
            stream = c.sock.makefile("rb")
            for _ in range(128):
                assert stream.readline().startswith(b"HTTP/1.1 200 ")
                headers = {}
                while True:
                    line = stream.readline()
                    if line == b"\r\n":
                        break
                    name, value = line.split(b":", 1)
                    headers[name.lower()] = value.strip()
                result = json.loads(stream.read(int(headers[b"content-length"])))
                assert result["status"] == "ok"
            stream.close()
            c.close()
            with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
                s.sendall(raw * 32)
                s.shutdown(socket.SHUT_WR)
                with s.makefile("rb") as stream:
                    for _ in range(32):
                        assert stream.readline().startswith(b"HTTP/1.1 200 ")
                        headers = {}
                        while True:
                            line = stream.readline()
                            if line == b"\r\n":
                                break
                            name, value = line.split(b":", 1)
                            headers[name.lower()] = value.strip()
                        assert json.loads(stream.read(int(headers[b"content-length"])))["status"] == "ok"
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/posts", iter([b'{"body":', b'"chunked"}']), {"Authorization": "Bearer " + token()}, encode_chunked=True)
            r = c.getresponse(); assert r.status == 201; r.read(); c.close()
            # Every acknowledged write must survive abrupt process termination.
            server.kill(); server.wait(); server = None
            with sqlite3.connect(db) as c:
                assert c.execute("SELECT count(*) FROM likes WHERE post_id=?", (post_id,)).fetchone()[0] == 1
                assert c.execute("SELECT body FROM posts WHERE id=?", (post_id,)).fetchone()[0] == "concurrent likes"
                # Alter timestamps and IDs to exercise order-independent fallback.
                c.execute("UPDATE posts SET created_at='2099-01-01T00:00:00.000Z' WHERE id IN (1,31,702,1400)")
                c.execute("DELETE FROM posts WHERE id=499999")
            expected = reference()
            # A killed io_uring process can release registered sockets asynchronously.
            with socket.socket() as fresh:
                fresh.bind(("127.0.0.1", 0))
                port = fresh.getsockname()[1]
            env["PORT"] = str(port)
            server = start()
            assert request("GET", "/feed") == (200, expected)
            print("independent API, Unicode, HTTP, concurrent likes, FK, crash durability and feed differential checks passed")
        finally:
            if server:
                server.terminate(); server.wait(timeout=10)

if __name__ == "__main__":
    main()
