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
