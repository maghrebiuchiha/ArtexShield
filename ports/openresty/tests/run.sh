#!/bin/sh
# The Lua suites, run with OpenResty's resty (the -fat Docker images have it):
#
#   tests/run.sh                    # vectors, store, adapter and cost
#   tests/run.sh vectors cost       # some of them
#   docker run --rm -v "$PWD:/w:ro" -w /w/ports/openresty openresty/openresty:1.27.1.2-bookworm-fat sh tests/run.sh
set -e
cd "$(dirname "$0")/.."
for name in ${*:-vectors store adapter cost}; do
    echo "== tests/$name.lua"
    resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' --shdict 'artex_shield_tiny 12k' \
        -I lib -I tests "tests/$name.lua"
done
