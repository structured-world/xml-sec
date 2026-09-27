#!/usr/bin/env bash

set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-support-crate-versions.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
git -C "$fixture" init -q
git -C "$fixture" config user.name "Test"
git -C "$fixture" config user.email "test@example.invalid"
mkdir -p "$fixture/crates/xml-sec-xslt/src" "$fixture/consumer/src"
printf '[workspace]\nmembers = ["crates/xml-sec-xslt", "consumer"]\nresolver = "2"\n' > "$fixture/Cargo.toml"
printf '[package]\nname = "xml-sec-xslt"\nversion = "0.1.0"\n' > "$fixture/crates/xml-sec-xslt/Cargo.toml"
printf 'pub fn version() {}\n' > "$fixture/crates/xml-sec-xslt/src/lib.rs"
printf '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nxml-sec-xslt = { version = "0.1.0", path = "../crates/xml-sec-xslt" }\n' > "$fixture/consumer/Cargo.toml"
printf 'pub fn consumer() {}\n' > "$fixture/consumer/src/lib.rs"
git -C "$fixture" add .
git -C "$fixture" commit -qm initial
base="$(git -C "$fixture" rev-parse HEAD)"

printf 'pub fn changed() {}\n' > "$fixture/crates/xml-sec-xslt/src/lib.rs"
git -C "$fixture" add .
git -C "$fixture" commit -qm changed
if (cd "$fixture" && bash "$script" "$base"); then
  echo "changed crate without a version bump was accepted" >&2
  exit 1
fi

printf '[package]\nname = "xml-sec-xslt"\nversion = "0.0.9"\n' > "$fixture/crates/xml-sec-xslt/Cargo.toml"
printf '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nxml-sec-xslt = { version = "0.0.9", path = "../crates/xml-sec-xslt" }\n' > "$fixture/consumer/Cargo.toml"
git -C "$fixture" add .
git -C "$fixture" commit -qm downgraded
if (cd "$fixture" && bash "$script" "$base"); then
  echo "support-crate version downgrade was accepted" >&2
  exit 1
fi

printf '[package]\nname = "xml-sec-xslt"\nversion = "0.1.1"\n' > "$fixture/crates/xml-sec-xslt/Cargo.toml"
git -C "$fixture" add .
git -C "$fixture" commit -qm bumped
if (cd "$fixture" && bash "$script" "$base"); then
  echo "consumer depending on the old support version was accepted" >&2
  exit 1
fi
printf '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nxml-sec-xslt = { version = "0.1.1", path = "../crates/xml-sec-xslt" }\n' > "$fixture/consumer/Cargo.toml"
git -C "$fixture" add .
git -C "$fixture" commit -qm dependency
(cd "$fixture" && bash "$script" "$base")
