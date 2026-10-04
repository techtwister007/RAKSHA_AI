#!/usr/bin/env sh
# The target's own regression suite: sequential-path behaviour that must survive the fix.
set -e
printf 'abc' > /tmp/raksha_r1; printf '\001\002\003\004' > /tmp/raksha_r2
[ "$(./harness /tmp/raksha_r1)" = "digest=$(( (97+98+99)*4000 % 256 ))" ] || { echo "FAIL r1: $(./harness /tmp/raksha_r1)"; exit 1; }
[ "$(./harness /tmp/raksha_r2)" = "digest=$(( 10*4000 % 256 ))" ] || { echo "FAIL r2: $(./harness /tmp/raksha_r2)"; exit 1; }
echo "2 tests passed"
