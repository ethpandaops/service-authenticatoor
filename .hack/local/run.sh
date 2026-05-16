#!/usr/bin/env bash
set -euo pipefail

# Run the authenticatoor with the local test config. Relative paths in
# config.yaml (e.g. signing.rs256.privateKeyFile) are resolved against CWD,
# so the script cd's into its own directory first.
cd "$(dirname "$0")"

REPO_ROOT="$(cd ../.. && pwd)"

CONFIG_FILE="./config.yaml"
if [ -f "./custom-config.yaml" ]; then
    CONFIG_FILE="./custom-config.yaml"
fi

exec go run "$REPO_ROOT/cmd/authenticatoor" --config "$CONFIG_FILE"
