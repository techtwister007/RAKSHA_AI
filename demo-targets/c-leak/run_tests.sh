#!/usr/bin/env sh
# Benign-path regression suite: a non-'X' first byte frees its copy and does not leak.
set -e
printf 'abc' > /tmp/raksha_leak_t1
[ "$(./harness /tmp/raksha_leak_t1)" = "stash=97" ] || { echo "FAIL t1: $(./harness /tmp/raksha_leak_t1)"; exit 1; }
echo "1 test passed"
