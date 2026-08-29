# xml-sec-xslt

Safe-Rust XSLT 1.0 compiler and runtime for parser-independent XML processing.
The crate is an independent engine: it has no XMLDSig, XMLEnc, crypto, filesystem,
network, environment, or global registry coupling.

Compilation produces an immutable `Stylesheet` that can be shared and executed
repeatedly. Callers provide explicit compile/execution budgets and a resolver
contract; `NoResolver` denies external access.

The engine implements template matching and precedence, modes, named templates,
variables and parameters, keys, whitespace declarations, decimal formats,
namespace aliases, attribute sets, XSLT instruction execution, result-tree
construction, numbering, sorting, and XML/HTML/text serialization.

XPath node sets retain element, attribute, and namespace identities. Converting a
public `Value` to a string therefore requires the associated `Document`; result-tree
fragments remain owned temporary trees rather than flattened text.

Runtime external-document resolution and the XMLDSig transform adapter are kept
outside this crate's current execution path so their policy and identity contracts
can be layered without introducing XML-security types into the reusable engine.

## Compatibility oracle

The integration suite includes every self-contained positive triplet in libxslt
1.1.45's XSLT 1.0 REC corpus. Portable output is compared byte-for-byte; HTML
indentation and `generate-id()` use semantic comparisons where XSLT permits
implementation-defined values. Two DTD-bearing cases assert this engine's
deliberate fail-closed XML policy, and the standalone upstream negative case
asserts typed static rejection. CI also builds pinned libxml2 2.15.1 and libxslt
1.1.45 revisions, verifies the vendored fixture snapshot, and executes the same
cases with `xsltproc` to detect oracle or fixture drift independently of the
Rust implementation.

Refresh or verify the snapshot from a matching donor checkout with:

```console
LIBXSLT_SOURCE_DIR=/path/to/libxslt scripts/import-libxslt-oracle-fixtures.sh
LIBXSLT_SOURCE_DIR=/path/to/libxslt scripts/import-libxslt-oracle-fixtures.sh --check
```
