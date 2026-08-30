# xml-sec-xslt

Safe-Rust XSLT 1.0 compiler and runtime for parser-independent XML processing.
The crate is an independent engine: it has no XMLDSig, XMLEnc, crypto, filesystem,
network, environment, or global registry coupling.

Compilation produces an immutable `Stylesheet` that can be shared and executed
repeatedly. Callers provide explicit compile/execution budgets and a resolver
contract; `NoResolver` denies external access.

Execution capabilities are explicit through `ExecutionEnvironment`: a caller-owned
resolver, clock, and typed extension policy. The compatibility entry point uses the
host local clock. Security-sensitive or reproducible transforms can inject
`FixedClock`, while `ExtensionPolicy::Deterministic` rejects zero-argument EXSLT date
functions that depend on ambient time. Extension capability therefore does not imply
permission to use nondeterministic behavior.

The engine implements template matching and precedence, modes, named templates,
variables and parameters, keys, whitespace declarations, decimal formats,
namespace aliases, attribute sets, XSLT instruction execution, result-tree
construction, numbering, sorting, and XML/HTML/text serialization.

XPath node sets retain element, attribute, and namespace identities. Converting a
public `Value` to a string therefore requires the associated `Document`; result-tree
fragments remain owned temporary trees rather than flattened text.

Stylesheet modules and runtime `document()` resources use the same explicit
resolver contract with purpose, base URI, stable resource identity, and byte
budgeting. The XMLDSig transform adapter remains outside this crate so no
XML-security types enter the reusable engine.

## Compatibility oracle

The repository vendors the complete libxslt 1.1.45 test tree and registers all
554 transformations driven by its core, REC/REC2, EXSLT, XSLTMark, DocBook,
multiple-output, XInclude, and xmlspec suites. Every registered case executes
through this engine. Portable output is compared byte-for-byte; comparisons are
normalized only where the donor output is stale or XSLT permits
implementation-defined lexical values. The harness projects donor DTD defaults,
ID and tokenized attributes, entities, and unparsed-entity system identifiers
without granting production code implicit filesystem access.

`files.sha256` accounts for all 2,021 files in the pinned upstream source tree, so
the importer and CI detect fixture omissions and byte drift independently of
engine behavior.

Refresh or verify the snapshot from a matching donor checkout with:

```console
LIBXSLT_SOURCE_DIR=/path/to/libxslt scripts/import-libxslt-oracle-fixtures.sh
LIBXSLT_SOURCE_DIR=/path/to/libxslt scripts/import-libxslt-oracle-fixtures.sh --check
```
