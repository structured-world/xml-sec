# Embedded RustCrypto SHA-3 adaptation

The production SHA-3 implementation is derived from RustCrypto `sha3` 0.12.0
(`src/lib.rs`, `src/utils.rs`, and `src/oids.rs`), published at
https://crates.io/crates/sha3/0.12.0. The source archive SHA-256 is
`bc9bad02c26382724b2d2692c6f179285e4b54eeecd7968f52a50059c3c11759`.
Original Apache-2.0 and MIT notices are preserved in `src/rustcrypto_sha3/`.

XMLEnc ConcatKDF accepts bit strings, not only octet strings. Upstream's byte
update API cannot finalize a partial octet. The local `finalize_with_bits`
method accepts zero to seven low-order bits in FIPS 202 Appendix B.1 order;
nonzero unused bits are rejected. Its domain suffix and padding follow
[FIPS 202 sections 5.1 and 6.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
including suffixes crossing the sponge rate boundary. The XMLEnc adapter
converts its high-order partial octet into that representation.

The adaptation retains the upstream byte-oriented implementation, digest
traits, OIDs, serialization and RustCrypto Keccak permutation. It contains
only the four SHA-3 variants used by this product, reuses the existing digest
dependency and always zeroizes state on drop. Bit finalization uses stack
storage and does not concatenate input buffers or allocate a workspace.
Embedding the adaptation ensures that the published package uses the same
implementation as the repository, without relying on a workspace-only patch.

Validation uses the unmodified upstream crate as a development-only byte
oracle and all 3,652 vectors in the four NIST CAVP bit-oriented ShortMsg files.
`bash scripts/import-sha3-bit-vectors.sh` imports these files unchanged from
the official archive, verifying SHA-256
`339454bb4b96e299fefcad403797523f1952462a28d2418c108aea30263643ae`.
Tests cover empty messages, every partial-octet width, rate-boundary padding,
multi-block byte messages and invalid final-bit representations.
