# Fixed-Width RSA Recovery Adaptation

`src/provider/rsa_pkcs1v15.rs` adapts the PKCS#1 v1.5 padding recovery of
[`sad-rsa` 0.10.2](https://github.com/sadco-io/sad-rsa), specifically
`src/pkcs1v15.rs::decrypt` and `src/algorithms/pkcs1v15.rs::decrypt_inner`.
The existing dependency remains responsible for RSA arithmetic, blinding and fault checking
through its `hazmat::rsa_decrypt_and_check` primitive. No second RSA engine is introduced.

The general-message donor API implements implicit rejection but discards padding validity.
That API cannot safely decide whether an enclosing unauthenticated CBC content operation
may return plaintext: fallback bytes may accidentally satisfy CBC padding. The local adaptation
returns an opaque fixed-width candidate with the original constant-time validity mask.
The operation performs content work first, then rejects an invalid recovery and zeroizes any
successful fallback plaintext. Key-ring wrappers preserve the opaque candidate.

[RFC 8017 §7.2.2](https://www.rfc-editor.org/rfc/rfc8017#section-7.2.2) defines the encoding
checks. Since the CEK length is known from the content algorithm, its delimiter position is
public. A single linear padding scan replaces the donor's variable-length alignment buffers.
All width-correct ciphertexts, including representatives at least as large as the modulus,
perform blinded RSA; out-of-range values are normalized but keep an invalid mask. Operational
RNG or arithmetic failures still fail closed. Secret decoded integers, encoded blocks and
candidate bytes are zeroized on drop.

This is a narrow embedded adaptation, not a whole dependency fork or a separately published
crate. It remains in the single `xml-sec` package. Updating `sad-rsa` requires checking the
named donor functions and its arithmetic API against this adaptation. Regression tests cover
all supported CEK lengths, header/delimiter/nonzero-padding checks, out-of-range values, and
successful CBC output following invalid recovery.

The mask does not make CBC authenticated or claim comprehensive padding-oracle resistance.
[XMLEnc 1.1 §6.1.2](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-bleichenbacher-attack)
specifically warns that random-key fallback does not defeat CBC-based chosen-ciphertext attacks.
Prefer RSA-OAEP with authenticated content; legacy CBC requires external authentication.
