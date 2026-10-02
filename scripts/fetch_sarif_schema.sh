#!/usr/bin/env sh
# Vendor the OASIS SARIF 2.1.0 schema. Run this ONCE, on a networked machine, before
# building the offline bundle -- the product itself must never fetch anything at runtime.
set -eu
dir="$(dirname "$0")/../schemas"
mkdir -p "$dir"
curl -sSL --max-time 60 -o "$dir/sarif-2.1.0.json" \
  "https://json.schemastore.org/sarif-2.1.0.json"
echo "vendored: $dir/sarif-2.1.0.json"
