# xml-sec SXD-XPath

An XML XPath library in Rust, modified to use a `no-unsafe` flag which uses the modified sxd-document XML library.

[![Current Version](https://img.shields.io/crates/v/xml-sec-sxd-xpath.svg)](https://crates.io/crates/xml-sec-sxd-xpath)
[![Documentation](https://docs.rs/xml-sec-sxd-xpath/badge.svg)](https://docs.rs/xml-sec-sxd-xpath/)

## Overview

This vendored fork carries bounded, panic-free XPath evaluation changes required by xml-sec,
including string-allocation accounting, tokenizer failure fusion, namespace-error propagation,
parser nesting limits, result-tree-fragment comparisons, and XPath 1.0 comma disambiguation.
Keep these changes when refreshing the upstream source.

The safe indexed DOM is selected by default. The legacy pointer backend requires
`--no-default-features --features raw-pointer-backend` explicitly.

The project is broken into two crates:

1. [`document`][sxd-document] - Basic DOM manipulation and reading/writing XML from strings.
2. `xpath` - Implementation of XPath 1.0 expressions.

There are also scattered utilities for playing around at the command
line.

[sxd-document]: https://github.com/shepmaster/sxd-document/

## Goals

This project has a lofty goal: replace [libxml] and [libxslt].

[libxml]: http://xmlsoft.org/
[libxslt]: http://xmlsoft.org/

## Contributing

1. Fork the xml-sec repository.
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Add a failing test.
4. Add code to pass the test.
5. Commit your changes (`git commit -am 'Add some feature'`)
6. Ensure tests pass.
7. Push to the branch (`git push origin my-new-feature`)
8. Create a new Pull Request

## License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
