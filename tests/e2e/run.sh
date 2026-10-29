#!/bin/bash
# Builds the hivemind and the fakes in a container and runs the end-to-end scenarios against them.
#
# usage: tests/e2e/run.sh [--slow] [--sanitize thread|address] [SCENARIO...]
#
# See tests/e2e/README.md.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

docker build -q -t spns-e2e "$here" >/dev/null

opts=()
# TSan needs address randomisation off (setarch -R), which Docker's default seccomp profile refuses.
if [[ " $* " == *" thread "* || " $* " == *" --sanitize=thread "* ]]; then
    opts+=(--security-opt seccomp=unconfined)
fi

# Builds live in a named volume, so a rerun only recompiles what changed.
exec docker run --rm --init "${opts[@]}" -v "$root:/src:ro" -v spns-e2e-build:/build \
    -e CCACHE_DIR=/build/ccache spns-e2e python3 -u /src/tests/e2e/e2e.py "$@"
