#!/bin/bash
# Oracle wrapper for codex exec with pre-configured settings
# Uses GPT-5.2 with xhigh reasoning effort
# Read-only mode: can explore but cannot edit files

set -eo pipefail

# Determine skill directory - use CLAUDE_PLUGIN_ROOT if set, otherwise derive from script location
if [[ -n "${CLAUDE_PLUGIN_ROOT:-}" ]]; then
    SKILL_DIR="${CLAUDE_PLUGIN_ROOT}/skills/oracle"
else
    # Fallback: derive from script location
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SKILL_DIR="$(dirname "$SCRIPT_DIR")"
fi

# Read system prompt from file
SYSTEM_PROMPT=$(cat "$SKILL_DIR/system-prompt.txt")
USER_QUESTION="$*"

if [[ -z "$USER_QUESTION" ]]; then
    echo "Usage: oracle.sh <question>"
    echo "Example: oracle.sh 'What is the best approach for implementing rate limiting?'"
    exit 1
fi

# Create temp file for clean output
OUTPUT_FILE=$(mktemp)
trap "rm -f $OUTPUT_FILE" EXIT

# Combine system prompt and user question, pass via stdin
# Configuration:
#   -m gpt-5.2                          : Use GPT-5.2 model
#   -c model_reasoning_effort=xhigh     : Maximum reasoning depth
#   -c approval_policy=never            : No approval prompts (advisory only)
#   -s read-only                        : Cannot write to filesystem
#   --disable apply_patch_freeform      : Disable file editing tool
#   --enable web_search_request         : Enable web search
#   -o $OUTPUT_FILE                     : Capture clean final response
#   --skip-git-repo-check               : Allow running outside git repos

cat <<EOF | codex exec \
    -m gpt-5.2 \
    -c model_reasoning_effort=xhigh \
    -c approval_policy=never \
    -s read-only \
    --disable apply_patch_freeform \
    --enable web_search_request \
    -o "$OUTPUT_FILE" \
    --skip-git-repo-check \
    - >/dev/null 2>&1
$SYSTEM_PROMPT

---
User Question: $USER_QUESTION
EOF

# Output only the clean response
cat "$OUTPUT_FILE"
