# XMLEnc Donor Fixtures

These fixtures are tracked so decryption interoperability tests do not depend
on network access or a local xmlsec1 checkout. They were imported from the
`xmlsec_1_3_13` tag of
[lsh123/xmlsec](https://github.com/lsh123/xmlsec/tree/xmlsec_1_3_13/tests).
The commit recorded in the canonical
[`libxmlsec1-1.3.13-donor-commit.txt`](../../../compatibility/libxmlsec1-1.3.13-donor-commit.txt)
contains no changes to these
fixture bytes; reciprocal CLI tests run against that newer snapshot.

Imported donor artifacts are kept byte-for-byte, including upstream wording
and spelling. Repository-specific clarifications belong in this wrapper rather
than in the corpus files whose provenance the tests are intended to preserve.

All private keys in this directory are public test material from that corpus.
They must never be used outside tests.

## Fixture Families

### `aleksey-xmlenc-01`

xmlsec1-produced direct-key vectors for AES-128/256-CBC and
AES-128/256-GCM, plus RSA-OAEP wrapped AES-256-CBC vectors covering SHA-1,
an explicit OAEP label, SHA-256, an explicit XMLEnc 1.1 MGF child under the
legacy OAEP URI, and XMLEnc 1.1 SHA-512/MGF1-SHA512. Tests
compare standalone bytes or complete decrypted documents with each tracked
`.data` file.

### `nist-aesgcm`

The complete xmlsec1 NIST AES-GCM subset: 180 XML vectors and their key and
plaintext inventories. With `legacy-algorithms`, all three AES widths are
executed: valid vectors must decrypt and authentication-negative vectors must
fail. The secure default profile refuses AES-192 explicitly. The complete
snapshot is included in `corpora.sha256`; see `nist-aesgcm/README.txt` for the
upstream generation format.

### `merlin-xmlenc-five`

Original Merlin XML Encryption vectors and their AES key inventory. The
tracked cases cover standalone AES-128-CBC binary data and AES-256-CBC
encrypted XML content, including `KeyName`, inherited namespaces, document
replacement, and informational `EncryptionProperties`.

### `xmlenc11-interop-2012`

The complete 79-file snapshot includes 17 ciphertexts, 13 templates, public test
credentials, and original variants. `xmlenc11_corpus` executes AES-GCM, RSA-OAEP
digest/MGF/label combinations, AES-KW, ConcatKDF, PBKDF2, ECDH P-256/P-384/P-521
and DH-ES through public Rust APIs and every compiled XML backend. Every original
template executes against the pinned native oracle; Rust encryption results are
also decrypted independently. Agreement wrapping composes the public, budgeted
agreement/KDF API with the AES-KW builder and retains the template's party/KDF
metadata. These checks do not claim CLI support for agreement or derived keys.

Fifteen original ciphertexts decrypt; both DH ciphertext variants are rejected
because `DH-1024_SHA256WithDSA.der` has an even 1023-bit `q`, contrary to the
prime-order domain requirements of [RFC 2631 §2.2](https://www.rfc-editor.org/rfc/rfc2631.html#section-2.2).
The DH template instead executes with the donor's valid RFC 5114 credentials.
No `Unsupported` result counts as successful complete-corpus coverage.

Four historical CBC vectors were encrypted without adding padding. Their
`-orig.data` bytes are retained, but decryption must return the corrected `.data`
files after removing eight bytes as required by
[XMLEnc 1.1 §5.2.1](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Padding).
The pinned files end in `0x08`; the upstream README's `0x07` wording is inaccurate.

XML plaintext is compared after canonicalization: element encryption does not
include the document declaration. The oracle only registers
`xmldsig-more#sha384`, unlike the normative `xmlenc#sha384` identifier in
[XMLEnc 1.1 §5.8.3](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-SHA384).
Template interoperability retains the original alias without changing our
standards-correct serializer.

### `01-phaos-xmlenc-3`

The complete independent Phaos XML Encryption corpus, including its public test
keys and templates. Five vectors are inside the crate's secure profile and must
decrypt end-to-end: AES-128/256-CBC with RSA-OAEP-SHA1 and AES-128/256 Key Wrap.
All remaining ciphertexts are exhaustively classified as fail-closed because
they use Triple-DES, RSA-PKCS#1 v1.5 encryption, AES-192, unsupported key-wrap
algorithms, Diffie-Hellman agreement, or deliberately malformed metadata.

## Importing Vectors

Point the repository helper at the pinned xmlsec1 1.3.13 development checkout
and pass paths under the destination corpus. A directory argument imports its
complete tree:

```sh
XMLSEC_DONOR_ROOT=/path/to/xmlsec/tests \
  scripts/import-donor-fixtures.sh \
  xmlenc/01-phaos-xmlenc-3
```

Every imported positive vector must be exercised through the full public
decryption pipeline. Invalid vectors must assert the specific fail-closed
boundary rather than merely checking for any error.
