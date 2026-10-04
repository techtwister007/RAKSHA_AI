#!/usr/bin/env sh
# Benign-path regression suite: a non-'H' first byte returns promptly.
set -e
printf 'abc' > /tmp/raksha_hang_t1
[ "$(./harness /tmp/raksha_hang_t1)" = "process=38" ] || { echo "FAIL t1: $(./harness /tmp/raksha_hang_t1)"; exit 1; }
echo "1 test passed"
