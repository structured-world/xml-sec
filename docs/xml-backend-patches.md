# Maintained XML parser kernels

The XML backend choices remain roxmltree 0.21.1 and xmloxide 0.5.0. Their
maintained sources live inside this package so downstream users receive the
same parser implementation. Cargo workspace patches alone do not propagate to
applications depending on a published crate.

`scripts/import-xml-backends.sh` verifies the released crate archive's SHA-256
before importing or comparing source. The corresponding maintained deltas live
in `scripts/patches/`. Original license notices and README files accompany each
kernel under `src/parser_roxmltree/` and `src/parser_xmloxide/`.

```sh
bash scripts/import-xml-backends.sh roxmltree --verify
bash scripts/import-xml-backends.sh xmloxide --verify
```

After deliberately editing a kernel, regenerate and inspect its delta with
`--refresh-patch`, then repeat verification. Import refuses to overwrite an
existing maintained directory. Verification works from the checksum-verified
Cargo archive cache when present and otherwise downloads the pinned archive
from crates.io.

The embedding changes crate-relative module paths and adapts Rust 2024 match
ergonomics. roxmltree retains source positions. xmloxide includes its existing
XML parser, DOM, encoding and DTD kernel, not its unrelated HTML, XPath, schema
validation or resource acquisition APIs. Its XML serializer is compiled only
for the original parser regression tests; production C14N remains xml-sec's
canonicalization implementation. Original test assertions are retained using
Rust's standard assertion macro.

Original Rust documentation examples are generated as internal tests by
`cargo run -p xml-sec-tools -- kernel-examples`, so they exercise the embedded
kernel rather than an external crate with the same name. The import/verification
command regenerates these tests. Compile-only examples remain compile-only;
runnable examples retain their assertions and literal bytes, and an example of
a `cfg`-gated item carries the same `cfg`. Their source documentation
is kept beside the implementation using `text,xml-sec-example` fences.

The roxmltree kernel rejects prefixed namespace undeclaration, as required by
Namespaces in XML 1.0 Third Edition §5 (No Prefix Undeclaring). Its original
empty-prefix-URI example is adjusted to check that rejection and permitted
default namespace undeclaration instead. This is an intentional correction of
the donor's acceptance, not adoption of Namespaces in XML 1.1 semantics.

The roxmltree delta moves uniquely owned normalization buffers into the parse
tree instead of copying them into reference-counted strings. Text coalescing
reuses the first owned fragment and does not duplicate single-fragment text.
The xmloxide delta returns its completed document by value, avoiding construction
of a replacement node arena solely to drop the consumed parser.

The maintained construction kernels specialize storage without changing parser
selection or grammar. Scoped reference replay pays raw parser state, DTD models,
namespace indexes, source positions and the semantic arena with its current
execution. DTD entity/default tables move into runtime state; entity fragments
move node payloads while rebasing links instead of cloning recursive subtrees.
Element and DTD-group parsing use bounded, paid continuation stacks. Diagnostic
labels retain their allocation charges, and resource refusal is terminal rather
than a malformed-input rejection or a reason to try another backend.

The backend adapters continue to use the shared lexical preflight and semantic
arena. Backend selection does not introduce implicit fallback, a second ID
resolver or an external entity acquisition path. Differential mode still
compares the two semantic projections rather than choosing whichever parser
accepts an input.
