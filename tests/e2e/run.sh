#!/bin/bash
# Builds and runs the end-to-end scenarios inside a container that has the toolchain, the
# dependencies and a Postgres server, for a machine that lacks any of them.  The test itself is the
# `e2e` build target (see README.md); this only packages it.
#
# usage: [E2E_SANITIZER=thread|address] [E2E_TARGET=e2e-...] tests/e2e/run.sh [e2e.py options...]
#
# E2E_TARGET picks the build target to run (default e2e-fast); the arguments go to e2e.py.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

docker build -q -t spns-e2e -f "$here/Dockerfile" "$root/contrib" >/dev/null

opts=()
flags="-O2 -g"
build=/build/spns
case "${E2E_SANITIZER:-}" in
    "") ;;
    thread)
        flags="-O1 -g -fsanitize=thread"
        build=/build/spns-thread
        # TSan needs address randomisation off (setarch -R), which Docker's default seccomp
        # profile refuses.
        opts+=(--security-opt seccomp=unconfined)
        ;;
    address)
        flags="-O1 -g -fsanitize=address -fno-omit-frame-pointer"
        build=/build/spns-address
        ;;
    *) echo "unknown E2E_SANITIZER '$E2E_SANITIZER'" >&2; exit 1 ;;
esac

# Builds live in a named volume, so a rerun only recompiles what changed.  The image's Postgres
# cluster, with the spns role and its spns_e2e database already created, is started before the
# build and test.
exec docker run --rm --init "${opts[@]}" -v "$root:/src:ro" -v spns-e2e-build:/build \
    -e CCACHE_DIR=/build/ccache -e PGUSER=spns -e E2E_ARGS="$*" spns-e2e \
    sh -c "pg_ctlcluster \"\$(ls /usr/lib/postgresql)\" main start \
           && cmake -S /src -B $build -DCMAKE_BUILD_TYPE=None \
                -DCMAKE_CXX_FLAGS='$flags' -DCMAKE_EXE_LINKER_FLAGS='$flags' \
                -DCMAKE_SHARED_LINKER_FLAGS='$flags' >/dev/null \
           && make -C $build -j\$(nproc) --no-print-directory ${E2E_TARGET:-e2e-fast}"
