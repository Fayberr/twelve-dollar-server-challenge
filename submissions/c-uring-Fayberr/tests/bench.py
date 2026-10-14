#!/usr/bin/env python3
"""Same-host mixed-load diagnostic. The generator is an external comparison tool."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
import time
import urllib.request

p = argparse.ArgumentParser()
p.add_argument("binary")
p.add_argument("generator")
p.add_argument("--root", default=str(Path(__file__).resolve().parents[3]))
p.add_argument("--users", type=int, default=256)
p.add_argument("--hold", type=int, default=30)
p.add_argument("--ramp", type=int, default=5)
p.add_argument("--think", default="0")
p.add_argument("--cpu", default="2")
p.add_argument("--port", type=int, default=3090)
p.add_argument("--label", default="candidate")
p.add_argument("--output")
p.add_argument("--memory-mib", type=int, default=0)
p.add_argument("--k6")
a = p.parse_args()
root = Path(a.root).resolve()
hz = os.sysconf("SC_CLK_TCK")
page = os.sysconf("SC_PAGE_SIZE")
cgroup = None
if a.memory_mib:
    cgroup = Path(f"/sys/fs/cgroup/system.slice/twelve-bench-{os.getpid()}")
    cgroup.mkdir()
    (cgroup / "memory.max").write_text(str(a.memory_mib * 1048576))
    (cgroup / "memory.swap.max").write_text("0")
    if (cgroup / "cpu.max").exists():
        (cgroup / "cpu.max").write_text("100000 100000")

def limits():
    resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
    if cgroup:
        (cgroup / "cgroup.procs").write_text(str(os.getpid()))

def client_limits():
    descriptors = max(65535, a.users + 1024)
    resource.setrlimit(resource.RLIMIT_NOFILE, (descriptors, descriptors))

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "feed.db"
    shutil.copyfile(root / "seed/feed.db", db)
    env = dict(os.environ, SQLITE_PATH=str(db), JWT_SECRET="twelve-dollar-challenge", HOST="127.0.0.1", PORT=str(a.port))
    with open(Path(tmp) / "server.log", "w+") as log:
        cmd = [str(Path(a.binary).resolve())]
        if a.cpu != "none":
            cmd = ["taskset", "-c", a.cpu] + cmd
        server = subprocess.Popen(cmd, env=env, stderr=log, stdout=log, preexec_fn=limits)
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{a.port}/health", timeout=1) as r:
                        if r.status == 200:
                            break
                except OSError:
                    if server.poll() is not None:
                        log.seek(0); raise RuntimeError(log.read())
                    time.sleep(.05)
            else:
                raise RuntimeError("no health")
            def ticks():
                stat = Path(f"/proc/{server.pid}/stat").read_text().split()
                return int(stat[13]) + int(stat[14])
            before = ticks()
            generator_env = dict(os.environ, THINK=a.think)
            if a.users > 50000:
                generator_env["SRC_IPS"] = ",".join(f"127.0.0.{i}" for i in range(1, 33))
            cmd = [str(Path(a.generator).resolve()), "127.0.0.1", str(a.port), str(a.users), str(a.ramp), str(a.hold), "4", str(root / "seed/tokens.json")]
            if a.k6:
                cmd = [a.k6, "run", "--quiet", "--summary-export", str(Path(tmp) / "summary.json"), "-e", f"BASE_URL=http://127.0.0.1:{a.port}", "-e", f"VUS={a.users}", "-e", f"DURATION={a.hold}s", "-e", f"RAMP_UP={a.ramp}s", "-e", f"TOKENS={root / 'seed/tokens.json'}", str(root / "bench/load.js")]
            if a.cpu != "none":
                # Separate physical cores on the Ryzen, separate vCPUs on ARM.
                cmd = ["taskset", "-c", "4-7" if os.cpu_count() >= 8 else "0-1,3"] + cmd
            start = time.monotonic()
            load = subprocess.Popen(cmd, env=generator_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, preexec_fn=client_limits)
            peak_rss = 0
            while load.poll() is None:
                peak_rss = max(peak_rss, int(Path(f"/proc/{server.pid}/statm").read_text().split()[1]) * page)
                time.sleep(.25)
            output = load.communicate()[0]
            elapsed = time.monotonic() - start
            seconds = (ticks() - before) / hz
            print(output, end="")
            if a.k6:
                summary = json.loads((Path(tmp) / "summary.json").read_text())
                metrics = summary["metrics"]
                requests = metrics["http_reqs"]["count"]
                percent = metrics["http_req_failed"]["value"] * 100
                failures = metrics["http_req_failed"]["passes"]
                connfail = 0
            else:
                match = re.search(r"TOTAL n=(\d+) fail=(\d+) \(([\d.]+)%\) connfail=(\d+)", output)
                assert match, "missing generator result"
                requests, failures, percent, connfail = match.groups()
            result = dict(label=a.label, users=a.users, think=a.think, ramp_s=a.ramp, hold_s=a.hold, elapsed_s=round(elapsed, 3), requests=int(requests), failed=int(failures), failed_percent=float(percent), connection_failures=int(connfail), server_cpu_s=round(seconds, 3), cpu_us_per_request=round(seconds*1e6/int(requests), 3), server_peak_rss_mib=round(peak_rss/1048576, 2), generator_output=output)
            if a.k6:
                result["k6_summary"] = summary
                result["k6_exit_code"] = load.returncode
            if cgroup:
                result["cgroup_memory_peak_mib"] = round(int((cgroup / "memory.peak").read_text()) / 1048576, 2)
                result["cgroup_memory_events"] = (cgroup / "memory.events").read_text()
            print(json.dumps(result, indent=2))
            if a.output:
                Path(a.output).write_text(json.dumps(result, indent=2) + "\n")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
            if cgroup:
                cgroup.rmdir()
