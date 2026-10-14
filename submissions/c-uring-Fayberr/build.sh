#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p deps bin build
fetch() {
  local name=$1 url=$2 hash=$3
  if ! echo "$hash  deps/$name.tar.gz" | sha256sum -c --quiet - >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$url" -o "deps/$name.tar.gz"
    echo "$hash  deps/$name.tar.gz" | sha256sum -c --quiet -
  fi
  if [ ! -d "deps/$name/src" ] && [ ! -f "deps/$name/sqlite3.c" ] && [ ! -f "deps/$name/picohttpparser.c" ]; then
    mkdir -p "deps/$name"
    tar -xzf "deps/$name.tar.gz" -C "deps/$name" --strip-components=1
  fi
}
fetch sqlite https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz 0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c
fetch yyjson https://codeload.github.com/ibireme/yyjson/tar.gz/refs/tags/0.12.0 b16246f617b2a136c78d73e5e2647c6f1de1313e46678062985bdcf1f40bb75d
fetch liburing https://codeload.github.com/axboe/liburing/tar.gz/refs/tags/liburing-2.15 8d052f2622dcb3678cbaee5ff582a87572672a6c0a56533cdda5b65cb636120a
fetch pico https://codeload.github.com/h2o/picohttpparser/tar.gz/465a7ff09fbd3432fe56c673451f5460154d1f07 d65d80b362fcb11f6e982ebc4515442d93b937b166558120031c38a8b6c173cd
if [ ! -f deps/liburing/src/liburing.a ]; then
  (cd deps/liburing && ./configure --cc=gcc >/dev/null && make -s -C src -j2 liburing.a)
fi
CFLAGS=(-O3 -march=native -flto=2 -fno-plt -std=gnu11 -g0 -Wall -Wextra -Werror -Wno-deprecated-declarations)
SQLITE_FLAGS=(-DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_DQS=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_USE_ALLOCA -DSQLITE_MAX_EXPR_DEPTH=0)
INCLUDES=(-Ideps/sqlite -Ideps/yyjson/src -Ideps/pico -Ideps/liburing/src/include)
if [ "${SANITIZE:-0}" = 1 ]; then
  CFLAGS=(-O1 -g -std=gnu11 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -Wno-deprecated-declarations)
fi
profile_hash="$(sha256sum app.c train.c deps/sqlite/sqlite3.c deps/yyjson/src/yyjson.c | sha256sum | cut -d' ' -f1)"
if [ "${SANITIZE:-0}" != 1 ]; then
  if [ "$(cat build/profile-hash 2>/dev/null || true)" != "$profile_hash" ]; then
    rm -rf build/profile
    mkdir -p build/profile
    train_flags=(-fprofile-generate=build/profile)
    gcc "${CFLAGS[@]}" "${SQLITE_FLAGS[@]}" "${train_flags[@]}" -w -c deps/sqlite/sqlite3.c -o build/sqlite.o
    gcc "${CFLAGS[@]}" "${train_flags[@]}" -w -c deps/yyjson/src/yyjson.c -o build/yyjson.o
    gcc "${CFLAGS[@]}" "${INCLUDES[@]}" "${train_flags[@]}" -c app.c -o build/app.o
    gcc "${CFLAGS[@]}" "${INCLUDES[@]}" "${train_flags[@]}" train.c build/{app,sqlite,yyjson}.o -lcrypto -lm -o build/train
    build/train build/training.db
    rm -f build/training.db build/training.db-wal build/training.db-shm build/sqlite.o build/yyjson.o
    printf '%s' "$profile_hash" > build/profile-hash
  fi
  PROFILE=(-fprofile-use=build/profile -fprofile-partial-training -Wno-missing-profile)
else
  PROFILE=()
fi
options="${CFLAGS[*]} ${SQLITE_FLAGS[*]} ${PROFILE[*]} $profile_hash"
if [ "$(cat build/options 2>/dev/null || true)" != "$options" ]; then
  rm -f build/sqlite.o build/yyjson.o build/pico.o
  printf '%s' "$options" > build/options
fi
if [ ! -f build/sqlite.o ] || [ deps/sqlite/sqlite3.c -nt build/sqlite.o ]; then
  gcc "${CFLAGS[@]}" "${SQLITE_FLAGS[@]}" "${PROFILE[@]}" -w -c deps/sqlite/sqlite3.c -o build/sqlite.o
fi
if [ ! -f build/yyjson.o ] || [ deps/yyjson/src/yyjson.c -nt build/yyjson.o ]; then
  gcc "${CFLAGS[@]}" "${PROFILE[@]}" -w -c deps/yyjson/src/yyjson.c -o build/yyjson.o
fi
if [ ! -f build/pico.o ] || [ deps/pico/picohttpparser.c -nt build/pico.o ]; then
  gcc "${CFLAGS[@]}" -w "${INCLUDES[@]}" -c deps/pico/picohttpparser.c -o build/pico.o
fi
gcc "${CFLAGS[@]}" "${PROFILE[@]}" "${INCLUDES[@]}" -c app.c -o build/app.o
gcc "${CFLAGS[@]}" "${INCLUDES[@]}" -c server.c -o build/server.o
gcc "${CFLAGS[@]}" "${PROFILE[@]}" build/{server,app,sqlite,yyjson,pico}.o deps/liburing/src/liburing.a -lcrypto -lm -o bin/server
echo 'built bin/server'
