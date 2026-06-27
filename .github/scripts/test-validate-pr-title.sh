#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
validator="$script_dir/validate-pr-title.sh"

valid_titles=(
  "feat(xmldsig): add key resolver"
  "fix!: reject unsafe default"
  "chore: release v0.1.8"
)

invalid_titles=(
  "Add key resolver"
  "feat: Add key resolver"
  "feature(xmldsig): add key resolver"
)

for title in "${valid_titles[@]}"; do
  "$validator" "$title"
done

for title in "${invalid_titles[@]}"; do
  if "$validator" "$title" >/dev/null 2>&1; then
    echo "expected invalid title to fail: $title" >&2
    exit 1
  fi
done
