# C / io_uring / SQLite

Direct HTTP/1.1, implemented in GNU C11. No Nginx and no HTTP framework.
The server reads only `SQLITE_PATH`, `JWT_SECRET`, `HOST` and `PORT`.

## Build and run

```sh
sudo bash install.sh
bash build.sh
SQLITE_PATH=/path/to/fresh-feed.db JWT_SECRET=your-key HOST=0.0.0.0 PORT=80 bash start.sh
```

Ubuntu 24.04, GCC 13 and Linux 6.1 or newer are required. The kernel must permit
io_uring. A container that blocks io_uring through seccomp cannot run this server.
It fails at startup with a diagnostic if the ring cannot be created.

Source dependencies are pinned and SHA-256 verified by `build.sh`:

| Component | Version |
| --- | --- |
| SQLite amalgamation | 3.53.4 |
| liburing, static | 2.15 |
| yyjson | 0.12.0 |
| picohttpparser | `465a7ff09fbd3432fe56c673451f5460154d1f07` |
| OpenSSL | Ubuntu 24.04 libcrypto 3.0.13, distribution security updates |

GCC uses `-O3 -march=native -flto=2 -fno-plt`. SQLite, yyjson and the application
are compiled with profile-guided optimization. `train.c` creates a separate
synthetic database during the build and exercises reads, writes, escaping and
authentication. The training database and compiler profiles stay in ignored
build directories. The release server contains no training or benchmark mode.
The compiler treats warnings in our source as errors.

## Design

- One event-loop thread owns one SQLite connection. There are no database locks
  between application threads and no thread-pool dispatches per request.
- Multishot receives borrow from a provided-buffer ring. An idle connection
  owns no request or response buffer. Complete requests are parsed in place;
  only fragments and pipelined requests are retained.
- Receives and sends are submitted in batches. Under sustained activity the
  loop waits for up to 256 completions or 8 ms. At low activity it waits for
  the first event. The same policy applies to all clients and all routes.
- Socket descriptors live in registered file tables. Tables are created
  lazily, up to eight tables of 65,000 slots, bounded by `RLIMIT_NOFILE` per
  table. A window of up to 512 one-shot accepts reserves capacity before accepting.
  This avoids resetting a newly accepted client when a multishot accept fills
  its table. Receive operations remain multishot. `TASKRUN_FLAG` lets idle
  secondary rings advertise deferred completions to the loop. Every secondary
  ring also receives a zero-timeout completion wait each iteration, ensuring
  its deferred receive work runs even when the primary ring stays busy.
- Response buffers use reusable size classes. The ordinary request path
  needs no heap allocation after its size-class pool is warm. Complex JSON
  documents can use an ordinary yyjson allocation if the small parse arena
  is insufficient. Buffers and partially sent responses remain owned until
  their kernel operations complete. Generations distinguish reused slots.
- Feed reads execute three prepared range queries when the request's newest
  IDs are consecutive in the required timestamp order: newest IDs, grouped
  like counts, and posts joined to users. Other ID orders use the reference
  query. The property is established afresh for each request. Nothing relies
  on a seed-specific ID or timestamp.
- WAL, `synchronous=NORMAL`, foreign keys, exclusive database ownership,
  32 MiB SQLite page cache and up to 512 MiB of file mapping. No schema changes.
- Writes in a batch share a transaction. Every response produced while that
  transaction is open, including reads, waits for COMMIT. A failed commit
  rolls back and replaces pending responses with HTTP 500. Statement-level
  constraint failures are isolated from other successful writes.
- Every authenticated request computes and checks its HS256 signature,
  expiration and claims. Only the HMAC key's initial hash states are reused.
  There is no token-verification cache or data cache outside SQLite.
- JSON output uses ordered fields, UTF-8 and length-aware escaping, including
  embedded NUL. Post length counts Unicode code points. Trimming recognizes
  Unicode whitespace rather than counting UTF-8 bytes as characters.
- HTTP framing uses picohttpparser, with chunked bodies, fragmented requests,
  `100 Continue`, pipelining, backpressure and half-close handling. Conflicting
  Content-Length and Transfer-Encoding framing is rejected.
- Idle sockets remain open for 120 seconds. Incomplete requests and stalled
  responses have a 30-second progress timeout. Input retained per connection
  is bounded at 36 KiB. Once per second, available cgroup or host memory is
  checked. Accepts pause below 128 MiB of headroom; idle sockets are trimmed
  below 64 MiB. No host limits or kernel parameters are changed.

## Verification

From the challenge root, with the official seed generated:

```sh
bash test/run.sh submissions/c-uring-Fayberr
python3 submissions/c-uring-Fayberr/tests/check.py
python3 submissions/c-uring-Fayberr/tests/transport.py --idle
```

`check.py` compares feed data to independent SQLite queries and checks
Unicode, complex JSON, JWT failures, foreign keys, concurrent duplicate likes,
fragmentation, chunking, pipelining, half-closes and acknowledged writes surviving
SIGKILL. It changes timestamps and deletes a row to check the feed fallback.
`transport.py` holds 600 connections with the server's descriptor limit set to
256, exercises several tables, reads 128 backpressured feeds, abandons 400
uploads, and optionally verifies reuse after 66 idle seconds.

For AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
SANITIZE=1 bash submissions/c-uring-Fayberr/build.sh
ASAN_OPTIONS=detect_leaks=1 python3 submissions/c-uring-Fayberr/tests/check.py
ASAN_OPTIONS=detect_leaks=1 python3 submissions/c-uring-Fayberr/tests/transport.py
bash submissions/c-uring-Fayberr/build.sh
```

## Local performance methodology

`tests/bench.py` can compare this binary against other submissions on the same
machine. It uses a fresh seed copy for each run, puts the server on one CPU,
limits its descriptors to 65,535, measures process CPU time and peak RSS, and
can place the server in a 2 GiB cgroup with no swap. Client CPUs are separate.
CPU affinity and resource limits are applied by the diagnostic harness, never
by the submission's build or startup scripts.

The diagnostic accepts the external C generator from
[PR #26](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/26).
That generator follows the browsing request mix and think times, but is not
k6. `--think 0` removes the think times to measure sustained throughput. Neither
test establishes an official challenge score. `--k6 /path/to/k6` instead runs
the unchanged official `bench/load.js`.

```sh
sudo python3 submissions/c-uring-Fayberr/tests/bench.py \
  submissions/c-uring-Fayberr/bin/server /path/to/loadgen \
  --users 150000 --think 1 --ramp 30 --hold 300 --memory-mib 2048 \
  --label fayber --output /tmp/fayber-result.json
```

The test host and load generator differ from the organizer's DigitalOcean
droplet and separate client machine. Local results must not be presented as
an official score or proof of first place.

## Measured diagnostics (2026-10-14)

The final ARM64 build on a Neoverse N1 sustained 1,227,610 requests in a
25-second hold with 256 clients and think times disabled: about 49,104 req/s,
zero errors, p95 7.39 ms and p99 28.03 ms. The complete ramp plus hold used
18.08 microseconds of server CPU per request and peaked at 33.3 MiB RSS.
This is approximately level with PR #26 in the paired local comparisons;
it does not demonstrate an overall win.

On the Ryzen 7 5700X3D under WSL2, the unchanged official k6 script completed
15,000 users, a 60-second ramp and a five-minute hold with zero failed
requests, p95 8.80 ms and p99 16.52 ms. That run preceded the secondary-ring
scheduling fix, which the larger connection diagnostics exercise separately.

The final build also completed a 30-second ramp and a five-minute hold with
150,000 actual C-generator clients on one x86 CPU in a 2 GiB no-swap cgroup.
Across 5,068,043 requests there were zero HTTP errors and zero connection
failures. The hold achieved 15,852 req/s, p95 48.94 ms and p99 63.39 ms;
maximum observed latency was 255.3 ms. Peak RSS was 130.4 MiB and the entire
cgroup, including socket and file-cache memory, peaked at 721.5 MiB.
This is a same-host C-generator diagnostic, not the official k6 score.

A subsequent 200,000-client diagnostic with a 30-second ramp and 60-second
hold failed the latency requirements: hold p95 5.26 seconds and p99 7.37
seconds, with 285 failed requests out of 1,449,122 total. Consequently,
150,000 is the highest sustained passing level verified here; the maximum
capacity has not been established.

## License

MIT, under the challenge repository's license. Feed range scans and group
commit are informed by the designs documented in
[PR #26](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/26)
and [PR #32](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/32).
The application and event-loop source in this folder was written for this
submission.
