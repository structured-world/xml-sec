# XMLEnc Donor Fixtures

These fixtures are tracked so decryption interoperability tests do not depend
on network access or a local xmlsec1 checkout. They were imported from the
`xmlsec_1_3_12` tag of
[lsh123/xmlsec](https://github.com/lsh123/xmlsec/tree/xmlsec_1_3_12/tests).

All private keys in this directory are public test material from that corpus.
They must never be used outside tests.

## Fixture Families

### `aleksey-xmlenc-01`

xmlsec1-produced direct-key vectors for AES-128/256-CBC and
AES-128/256-GCM, plus RSA-OAEP wrapped AES-256-CBC vectors covering SHA-1,
an explicit OAEP label, SHA-256, and XMLEnc 1.1 SHA-512/MGF1-SHA512. Tests
compare standalone bytes or complete decrypted documents with each tracked
`.data` file.

### `nist-aesgcm`

The complete xmlsec1 NIST AES-GCM subset: 180 XML vectors and their key and
plaintext inventories. AES-128 and AES-256 valid vectors must decrypt, their
authentication-negative vectors must fail, and unsupported AES-192 vectors
must be explicitly classified. See `nist-aesgcm/README.txt` for the upstream
generation format.

### `merlin-xmlenc-five`

Original Merlin XML Encryption vectors and their AES key inventory. The
tracked cases cover standalone AES-128-CBC binary data and AES-256-CBC
encrypted XML content, including `KeyName`, inherited namespaces, document
replacement, and informational `EncryptionProperties`.

### `xmlenc11-interop-2012`

Independent XML Encryption 1.1 interoperability vectors for RSA-OAEP. The
tracked cases cover legacy RSA-OAEP-MGF1P, independent OAEP digest/MGF
selection, and a non-empty OAEP label with 2048-, 3072-, and 4096-bit keys.
Decrypted XML is compared with donor plaintext after canonicalization because
xmlsec1 encrypts parsed XML rather than preserving declaration and empty-tag
serialization.

### `01-phaos-xmlenc-3`

The complete independent Phaos XML Encryption corpus, including its public test
keys and templates. Five vectors are inside the crate's secure profile and must
decrypt end-to-end: AES-128/256-CBC with RSA-OAEP-SHA1 and AES-128/256 Key Wrap.
All remaining ciphertexts are exhaustively classified as fail-closed because
they use Triple-DES, RSA-PKCS#1 v1.5 encryption, AES-192, unsupported key-wrap
algorithms, Diffie-Hellman agreement, or deliberately malformed metadata.

## Importing Vectors

Point the repository helper at an xmlsec1 1.3.12 test checkout and pass paths
under the destination corpus. A directory argument imports its complete tree:

```sh
XMLSEC_DONOR_ROOT=/path/to/xmlsec/tests \
  scripts/import-donor-fixtures.sh \
  xmlenc/01-phaos-xmlenc-3
```

Every imported positive vector must be exercised through the full public
decryption pipeline. Invalid vectors must assert the specific fail-closed
boundary rather than merely checking for any error.
