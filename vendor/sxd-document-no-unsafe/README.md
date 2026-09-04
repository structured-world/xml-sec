# xml-sec-sxd-document

Maintained fork of `sxd-document-no-unsafe` for the safe-Rust XPath and XSLT
engines in [`xml-sec`](https://github.com/structured-world/xml-sec). It retains
the upstream DOM contract and adds allocation-free child-count preflight so
resource budgets can reject wide traversals before child handles are allocated.

The crate is an implementation dependency. Applications should normally use
`xml-sec-xslt` rather than depending on it directly.

The safe indexed arena is the default backend. The legacy pointer backend is
available only through `--no-default-features --features raw-pointer-backend`.

## Provenance

Based on `sxd-document-no-unsafe` 0.4.2. The original MIT license is retained
in `LICENSE.txt`.
