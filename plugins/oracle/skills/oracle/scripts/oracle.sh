#!/bin/bash
# Oracle wrapper - calls TypeScript implementation with Codex SDK
# Falls back to CLI version if SDK fails

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try SDK version first
if command -v bun &> /dev/null; then
    exec bun "$SCRIPT_DIR/oracle.ts" "$@"
else
    echo "Warning: bun not found, falling back to CLI version" >&2
    exec "$SCRIPT_DIR/oracle-cli.sh" "$@"
fi
