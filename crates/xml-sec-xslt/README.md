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

Runtime external-document resolution and the XMLDSig transform adapter are kept
outside this crate's current execution path so their policy and identity contracts
can be layered without introducing XML-security types into the reusable engine.
