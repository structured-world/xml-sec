# libxslt 1.1.45 oracle corpus

`upstream/tests` is the complete test tree from libxslt 1.1.45 commit
`35323d6a15f6e63c9919ddbc0abe64c90a0dd88a`, not a curated fixture subset.
It includes the core `runtest.c` suites, REC/REC2, EXSLT, XSLTMark, DocBook,
multiple-output, XInclude, xmlspec, fuzz inputs, dependencies, and golden files.

`cases.tsv` is generated from the suite directories registered by `runtest.c`.
`files.sha256` accounts for every upstream file and makes accidental corpus
truncation or fixture rewriting visible in CI. The original MIT license is in
`LICENSE`.
