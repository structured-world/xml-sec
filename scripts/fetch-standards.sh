#!/usr/bin/env bash
# Keep reference payloads out of source control; preserve publisher bytes/notices.
set -euo pipefail
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
destination="$root/.refs/standards"
mkdir -p "$destination"
while IFS=$'\t' read -r name url; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    printf 'Fetching %s\n' "$name"
    curl --fail --location --retry 2 --connect-timeout 20 --max-time 120 \
        --silent --show-error "$url" -o "$destination/$name.part"
    if [[ "$name" == *.pdf ]] && [[ "$(head -c 5 "$destination/$name.part")" != '%PDF-' ]]; then
        printf 'Expected PDF, received another payload: %s\n' "$url" >&2
        exit 1
    fi
    mv "$destination/$name.part" "$destination/$name"
    if [[ "$name" == rfc*.txt ]]; then
        rfc="${name%.txt}"
        curl --fail --location --retry 2 --silent --show-error --max-time 120 \
            "https://www.rfc-editor.org/rfc/$rfc.json" -o "$destination/$rfc.json.part"
        mv "$destination/$rfc.json.part" "$destination/$rfc.json"
    fi
done < "$root/docs/standards-sources.tsv"
(
    cd "$destination"
    find . -type f ! -name '*.part' ! -name SHA256SUMS ! -name retrieved-at.txt \
        -exec shasum -a 256 {} + > SHA256SUMS
)
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$destination/retrieved-at.txt"
printf 'Reference corpus: %s\n' "$destination"
