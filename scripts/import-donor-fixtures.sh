#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_root="$repo_root/donors/xmlsec/tests"
fixture_root="$repo_root/tests/fixtures/xmldsig"

install -m 0644 \
  "$donor_root/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml" \
  "$fixture_root/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml"
