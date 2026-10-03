# Maintained RustCrypto ML-DSA Patch

The experimental ML-DSA backend uses RustCrypto `ml-dsa` 0.1.1, with a local
checked expanded-key decoder. The released source corresponds to upstream
commit `f75d5b829948988f18d9463f286805fb9410bcdd`. Its crate archive SHA-256 is
`add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d`.

The maintained sources are embedded in the single published `xml-sec` package.
This is necessary because Cargo `[patch]` overrides are not inherited by package
consumers. The unmodified registry implementation is used only by development
tests to generate independent interoperable inputs.

The patch preserves RustCrypto's Apache-2.0/MIT licensing and notices. Its
functional change adds fallible expanded-key import: packed secret coefficients
are checked before decoding, and derived `t0` and `tr` are checked for consistency
using the existing RustCrypto lattice arithmetic. FIPS 204 section 7.2,
Algorithms 19 and 24-25 describe the encoding; Algorithm 6 derives these fields.
This is an import-time safety check, not a claim to reconstruct the original seed.
The checked decoder has been proposed upstream in
[RustCrypto/signatures #1452](https://github.com/RustCrypto/signatures/pull/1452).
The embedded patch remains necessary until an accepted upstream release supplies it.

The XML-security adapter implements all three private-key representations from
[RFC 9881 section 6](https://www.rfc-editor.org/rfc/rfc9881.html#section-6).
Seed/expanded consistency follows
[section 8.2](https://www.rfc-editor.org/rfc/rfc9881.html#section-8.2).
Expanded-only keys are exported as expanded keys, never a fabricated seed.
Secret staging buffers are zeroized. All public signing and verification still
pass through `CryptoProvider`.

Namespace, feature and Rust 1.92 lint adaptations let the same algorithm live as a private
module. They do not change cryptographic behavior. Inspect the generated delta
in `scripts/patches/ml-dsa-0.1.1.patch` when updating the donor.

To verify reproducibility, run:

```sh
bash scripts/import-rustcrypto-ml-dsa.sh --verify
```

After deliberate edits to the maintained sources, regenerate the delta with
`--refresh-patch`, inspect it, and run `--verify` again. An ordinary import refuses
to overwrite an existing maintained source tree.
