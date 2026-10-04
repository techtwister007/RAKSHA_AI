#!/usr/bin/env sh
# The target's own regression suite: normal-path behaviour that must survive the fix.
set -e
printf 'abc' > /tmp/raksha_t1; printf 'hello' > /tmp/raksha_t2
[ "$(./harness /tmp/raksha_t1)" = "sum=38" ] || { echo "FAIL t1: $(./harness /tmp/raksha_t1)"; exit 1; }
[ "$(./harness /tmp/raksha_t2)" = "sum=20" ] || { echo "FAIL t2: $(./harness /tmp/raksha_t2)"; exit 1; }
echo "2 tests passed"
