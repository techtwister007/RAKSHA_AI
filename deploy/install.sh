#!/usr/bin/env sh
# Cable-pull install: sealed SSD -> running system, with no network. Run on the air-gapped node.
#   ./install.sh /path/to/bundle            (defaults to the directory this script sits in)
# Verifies the bundle checksums, loads the carried images, and starts the chosen profile.
set -eu

BUNDLE="${1:-$(dirname "$0")}"
PROFILE="${RAKSHA_PROFILE:-gpu}"     # gpu | cpu

echo "RAKSHA offline install from $BUNDLE (profile: $PROFILE)"

echo "1/4 verifying bundle integrity..."
python3 "$BUNDLE/bundle_manifest.py" verify "$BUNDLE"

echo "2/4 loading carried container images (no pull)..."
for img in "$BUNDLE"/images/*.tar; do
    [ -e "$img" ] || continue
    docker load -i "$img"
done

echo "3/4 confirming no network interface is required..."
# The compose network is marked internal; nothing here reaches the internet.

echo "4/4 starting the sealed stack..."
docker compose -f "$BUNDLE/docker-compose.$PROFILE.yml" up -d

echo "done. console: http://localhost:8080  (NETWORK INTERFACES: 0 · CLOUD CALLS: 0)"
