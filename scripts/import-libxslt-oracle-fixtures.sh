#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE_DIR="${LIBXSLT_SOURCE_DIR:-}"
readonly DESTINATION="crates/xml-sec-xslt/tests/fixtures/libxslt-1.1.45"
readonly CASES=(
  test-10-1
  test-10-2
  test-10-3
  test-11.2-1
  test-11.2-2
  test-11.2-3
  test-11.2-4
  test-11.2-5
  test-11.2-6
  test-12.2-1
  test-12.2-2
  test-15-1
  test-16.1-1
  test-16.1-2
  test-2.3-1
  test-2.3-2
  test-2.6.2-1
  test-3.4-1
  test-3.4-2
  test-3.4-3
  test-5.2-1
  test-5.2-11
  test-5.2-12
  test-5.2-13
  test-5.2-14
  test-5.2-15
  test-5.2-16
  test-5.2-17
  test-5.2-18
  test-5.2-19
  test-5.2-2
  test-5.2-20
  test-5.2-21
  test-5.2-22
  test-5.2-3
  test-5.2-4
  test-5.2-5
  test-5.2-6
  test-5.2-7
  test-5.2-8
  test-5.2-9
  test-5.3
  test-5.4-1
  test-5.4-2
  test-5.4-3
  test-5.4-4
  test-5.4-5
  test-5.5-1
  test-5.8
  test-6
  test-7.1.1-2
  test-7.1.1-3
  test-7.1.1
  test-7.1.3
  test-7.1.4
  test-7.3
  test-7.4
  test-7.5-1
  test-7.6.1-1
  test-7.6.1-2
  test-7.6.1-3
  test-7.6.2-1
  test-7.6.2-2
  test-7.7-1
  test-7.7-2
  test-7.7-3
  test-7.7-4
  test-7.7-5
  test-7.7-6
  test-9.1-1
)
readonly HTML_CASES=(
  test-2.5-1
  test-8-1
  test-9.1-2
)
readonly SEMANTIC_CASES=(
  test-12.4-1
)
readonly DTD_CASES=(
  stand-2.7-1
  test-5.2-10
)
readonly STATIC_ERROR_CASES=(
  test-6.1
)

if [[ -z "$SOURCE_DIR" || ! -d "$SOURCE_DIR/tests/REC" ]]; then
  echo "LIBXSLT_SOURCE_DIR must point to a libxslt checkout" >&2
  exit 2
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage"

for case_name in "${CASES[@]}" "${HTML_CASES[@]}" "${SEMANTIC_CASES[@]}"; do
  for extension in xsl xml out; do
    source="$SOURCE_DIR/tests/REC/$case_name.$extension"
    if [[ ! -f "$source" ]]; then
      echo "missing oracle fixture: $source" >&2
      exit 2
    fi
    cp "$source" "$stage/$case_name.$extension"
  done
done

for case_name in "${CASES[@]}"; do
  printf '%s\texact\n' "$case_name" >> "$stage/cases.tsv"
done
for case_name in "${HTML_CASES[@]}"; do
  printf '%s\thtml\n' "$case_name" >> "$stage/cases.tsv"
done
for case_name in "${SEMANTIC_CASES[@]}"; do
  printf '%s\tsemantic\n' "$case_name" >> "$stage/cases.tsv"
done

for case_name in "${DTD_CASES[@]}"; do
  for extension in xsl xml out; do
    source="$SOURCE_DIR/tests/REC/$case_name.$extension"
    if [[ ! -f "$source" ]]; then
      echo "missing DTD policy fixture: $source" >&2
      exit 2
    fi
    cp "$source" "$stage/$case_name.$extension"
  done
done

for case_name in "${DTD_CASES[@]}"; do
  printf '%s\tdtd-rejected\n' "$case_name" >> "$stage/cases.tsv"
done

for case_name in "${STATIC_ERROR_CASES[@]}"; do
  for extension in xsl xml err; do
    source="$SOURCE_DIR/tests/REC/$case_name.$extension"
    if [[ ! -f "$source" ]]; then
      echo "missing static-error fixture: $source" >&2
      exit 2
    fi
    cp "$source" "$stage/$case_name.$extension"
  done
  printf '%s\tstatic-rejected\n' "$case_name" >> "$stage/cases.tsv"
done

for module in article.xsl bigfont.xsl; do
  cp "$SOURCE_DIR/tests/REC/$module" "$stage/$module"
done

cat > "$stage/README.md" <<'EOF'
# libxslt XSLT 1.0 oracle fixtures

These files contain every self-contained positive `tests/REC` triplet from libxslt 1.1.45,
commit `35323d6a15f6e63c9919ddbc0abe64c90a0dd88a`. The `.out` files are oracle
output bytes; integration tests execute the corresponding `.xsl` and `.xml`
through `xml-sec-xslt`. `cases.tsv` records whether each case uses exact bytes,
HTML whitespace normalization, semantic `generate-id()` checks, deliberate
DTD rejection, or a static-error expectation.

The two DTD-bearing source cases are retained as security-policy regressions:
libxslt accepts them, while `xml-sec-xslt` deliberately rejects XML containing
a DTD. `article.xsl` and `bigfont.xsl` are dependencies of `test-2.6.2-1`.

The fixtures retain libxslt's MIT license. See `LICENSE` in this directory.
EOF
cp "$SOURCE_DIR/Copyright" "$stage/LICENSE"

if [[ "${1:-}" == "--check" ]]; then
  diff -ru "$DESTINATION" "$stage"
else
  rm -rf "$DESTINATION"
  mkdir -p "$DESTINATION"
  cp "$stage"/* "$DESTINATION"/
fi
