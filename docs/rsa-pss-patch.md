# Parameterized RSA-PSS Adaptation

`src/provider/rsa_pss.rs` adapts sad-rsa 0.10.2's PSS encoding and MGF1 from
`src/pss.rs` and `src/algorithms/{pss,mgf}.rs`. RSA arithmetic, blinding and
fault checking remain in that dependency's `hazmat` primitives. No additional
RSA engine or separately published crate is introduced.

The dependency's PSS API uses one digest for both the message and MGF1.
[RFC 9231 section 2.3.9](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3.9)
permits independent hashes and an explicit salt length. The local adaptation
implements those parameters using the existing SHA implementations. MGF1 hashes
borrowed chunks into stack storage rather than allocating a digest object or
buffer for every block.

[RFC 8017 sections 9.1.1 and 9.1.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.1)
govern encoding and checking. Verification requires the exact selected salt
length; it never guesses one from the signature. Modulus capacity is checked
before randomness or padding allocation, and nonzero leading representative
octets are rejected rather than silently truncated for non-byte-aligned keys.
RSAVP1 rejects signature integers greater than or equal to the modulus before
exponentiation, as required by [RFC 8017 section 5.2.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-5.2.2);
raw modular exponentiation would otherwise accept aliases of a valid signature.
The signing padding buffer, including its random salt, is zeroized on drop.

When updating sad-rsa, compare the named donor functions and hazmat interfaces
with this module. Independent dependency and XML-security oracle tests protect
the standard encodings and the parameterized extension.
