# C API

The `xml-sec-capi` crate builds a shared and a static library that C and C++
programs call through `crates/xml-sec-capi/include/xml_sec.h`. It exposes the
policy-bound Rust API, not the libxmlsec1 interface: every operation runs under
one compiled policy snapshot, loaded from a schema-v1 TOML configuration. The
crate is not published yet; build it from this repository.

```sh
cargo build --release -p xml-sec-capi
# target/release/libxml_sec_capi.{so,dylib,a} or xml_sec_capi.{dll,dll.lib,lib}
```

The XML backend is selected with the same features as the core crate
(`xml-backend-xmloxide` by default, `xml-backend-roxmltree`,
`xml-backend-differential`, `xml-backends-all`); `aws-lc-fips` adds
`xs_provider_new_aws_lc_fips`.

## Handles

Every object is a typed handle such as `XsPolicy` or `XsDocument`: a 64-bit
value naming a slot and generation in a table the library owns, never a
pointer. Passing a handle of another type, a handle whose object was destroyed,
or a handle whose slot now holds a newer object returns `XS_WRONG_HANDLE`,
`XS_DESTROYED_HANDLE` or `XS_STALE_HANDLE` instead of touching memory. The zero
handle names nothing.

Each handle is released with its own `xs_*_destroy`. An object that holds
another (a signer holds its policy and provider) keeps it alive, so handles may
be destroyed in any order. Destroying an object while a call on another thread
uses it returns `XS_BUSY` and leaves the handle valid.

Handles may be used from any thread. A document serves one operation at a time
and returns `XS_BUSY` to a concurrent one; every other object serves concurrent
calls.

## Values, buffers and errors

- Inputs are `XsBytes` (pointer and length, borrowed for the call) and plain
  structures. A null pointer is accepted only with a zero length; text must be
  UTF-8.
- Outputs are written only when a call succeeds.
- `xs_document_serialize` returns an `XsBuffer` the library allocated; release
  it with `xs_buffer_free`, never with `free`.
- Text read from an audit, evidence, policy or error handle is borrowed from
  that handle and stays valid until it is destroyed.
- Every function returns an `xs_status`. A call given a non-null `XsError *`
  stores an error handle on failure (zero on success); `xs_error_status`,
  `xs_error_policy_violation` (an `XS_VIOLATION_*` for a policy refusal, zero
  otherwise) and `xs_error_message` read it, and it is destroyed like any
  handle. Messages are the diagnostics the Rust API reports for the same
  failure; key bytes and passwords never enter them. There is no thread-local
  or global last error.
- No Rust panic crosses the boundary; an internal failure returns
  `XS_INTERNAL`.

| Status | Meaning |
| --- | --- |
| `XS_INVALID_ARGUMENT` | A pointer, length, enumerator or byte string was not acceptable |
| `XS_WRONG_HANDLE`, `XS_STALE_HANDLE`, `XS_DESTROYED_HANDLE` | The handle does not name a live object of the declared type |
| `XS_BUSY`, `XS_HANDLE_LIMIT` | The object is in use; the handle table is full |
| `XS_OPERATION_DISABLED`, `XS_POLICY` | The compiled policy disables the operation or refused the input |
| `XS_CONFIGURATION` | The TOML configuration could not be read or compiled |
| `XS_DOCUMENT`, `XS_KEY`, `XS_CANONICALIZATION` | XML, key or canonicalization processing failed |
| `XS_VERIFICATION`, `XS_SIGNING`, `XS_ENCRYPTION` | The operation could not complete |
| `XS_INTERNAL` | The library failed internally |

A signature that does not verify is evidence, not a failed call.

## Policy

`xs_policy_store_new` compiles one profile of a [schema-v1
configuration](policy-schema-v1.md) for a provider and publishes it as
revision 1. `xs_policy_store_replace` compiles a complete replacement first and
publishes it atomically as the next revision; a refused replacement publishes
nothing. `xs_policy_store_load` returns the current snapshot: operations created
from it keep enforcing it after later publications, and `xs_policy_identity`
reports its profile, schema version, revision and settings digest. The library
reads no files or environment; the application supplies the configuration
text.

## Operations

```c
XsSigner signer;
xs_signer_new(policy, provider, keys, name, rsa_sha256, &signer, &error);
xs_sign(signer, document, &audit, &error);         /* fills the template */

XsVerifier verifier;
xs_verifier_new(policy, provider, keys, &verifier, &error);
xs_verify(verifier, document, &request, &evidence, &error);
xs_evidence_accepted(evidence, document, &accepted, &error);
```

- Keys are imported into an `XsKeys` manager from PEM or raw symmetric bytes,
  with usage bits, bounded by the resource policy of one operation.
- Documents are parsed under the compiled policy of an operation
  (`XS_OPERATION_*`). Signing, encryption and decryption replace the document
  with its new generation; a failure leaves it unchanged.
- Signing fills the `Signature` template the document already contains.
- Verification names the element IDs that must be authenticated. Success is a
  report: `xs_evidence_accepted` answers whether the request holds for the
  verified generation of the same document.
- Encryption replaces an element by `EncryptedData` for an RSA-OAEP recipient;
  decryption recovers it with the recipient's private key.
- Each operation can return an `XsAudit` listing what the policy decided:
  algorithms, URI classes, Manifest processing, exceptions and refusals, with
  the snapshot identity. `xs_evidence_signature_audit` returns the audit of one
  signature, whatever its outcome.

Callbacks, external resources and PKCS#11 tokens are not exposed yet.

## Qualification

`cargo run -p xml-sec-tools -- capi` builds the library, builds
`crates/xml-sec-capi/tests/c/roundtrip.c` (C99) and `tests/cpp/roundtrip.cpp`
(C++17) with the platform's compiler against the header and that library, runs
them, and checks that the library exports exactly the functions the header
declares. The C program signs, verifies a valid and a tampered document,
encrypts, decrypts, replaces the policy and exercises policy refusals and
wrong, destroyed and invalid arguments. CI runs it on Linux, macOS and Windows.
`capi --sanitize` repeats it on Linux with the library and the crate's own
tests (handle table, argument validation, panic containment) under
AddressSanitizer and the programs under AddressSanitizer, LeakSanitizer and
UndefinedBehaviorSanitizer. `SAFETY.md` in the crate records the invariants of
its one `unsafe` module.
