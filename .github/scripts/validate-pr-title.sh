#!/usr/bin/env bash
set -euo pipefail

title="${1:-}"
pattern='^(feat|fix|perf|refactor|docs|test|build|ci|chore|style)(\([a-z0-9][a-z0-9._/-]*\))?(!)?: [a-z0-9].*$'

if [[ ${#title} -gt 72 ]]; then
  echo "PR title exceeds 72 characters: ${#title}" >&2
  exit 1
fi

if [[ ! $title =~ $pattern ]]; then
  echo "PR title must use Conventional Commits, for example: feat(xmldsig): add key resolver" >&2
  exit 1
fi
