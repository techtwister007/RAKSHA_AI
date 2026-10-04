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

echo "3/4 confirming the sandbox image is present (target code never runs outside it)..."
docker image inspect raksha-sandbox:latest >/dev/null 2>&1 || {
    echo "raksha-sandbox:latest not loaded — refusing to start (RAKSHA_REQUIRE_SANDBOX=1)"; exit 1; }

echo "4/4 starting the sealed stack..."
mkdir -p /var/lib/raksha-scratch
docker compose -f "$BUNDLE/docker-compose.$PROFILE.yml" up -d

echo "done. console: http://127.0.0.1:8080 (this host only)."
echo "     the badges on it are measured: they read 0 only if nothing ran outside the sandbox."
