#!/usr/bin/env sh
# Benign-path regression suite: short inputs fold without overflowing.
set -e
printf 'abc' > /tmp/raksha_io_t1
[ "$(./harness /tmp/raksha_io_t1)" = "fold=86436" ] || { echo "FAIL t1: $(./harness /tmp/raksha_io_t1)"; exit 1; }
echo "1 test passed"
