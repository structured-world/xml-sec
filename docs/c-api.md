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
xs_verify(verifier, document, &request, NULL, &evidence, &error);
xs_evidence_accepted(evidence, document, &accepted, &error);
```

- Keys are imported into an `XsKeys` manager from PEM or raw symmetric bytes,
  with usage bits, bounded by the resource policy of one operation.
- Documents are parsed under the compiled policy of an operation
  (`XS_OPERATION_*`). A document beyond its byte, depth or parse-work ceiling
  is refused as `XS_POLICY` with `XS_VIOLATION_RESOURCE_LIMIT`; the byte
  ceiling is checked before the library copies the input. Signing, encryption and decryption replace the document
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

External resources and PKCS#11 tokens are not exposed yet.

## Key lookup

An application that keeps its keys in its own store passes a key lookup to
`xs_verify` or `xs_decrypt` instead of filling a key manager up front:

```c
xs_status lookup(void *store, const XsKeyQuery *query, XsKeys keys) {
    /* query->names: the KeyName values the document gives, null when it
       gives none; query->method: the signature, transport, wrap or content
       method URI the key serves. */
    for (size_t i = 0; i < query->name_count; i++) {
        XsBytes pem = my_store_find(store, query->names[i], query->method);
        if (pem.ptr != NULL) {
            xs_status status = xs_keys_add_public_pem(keys, query->names[i], pem,
                                                      XS_KEY_USAGE_VERIFY, NULL);
            if (status != XS_OK) {
                return status;
            }
        }
    }
    return XS_OK; /* finding nothing is not a failure */
}

XsKeyLookup key_lookup = {lookup, &my_store};
xs_verify(verifier, document, &request, &key_lookup, &evidence, &error);
```

- The callback is called only during the call that received it, once for each
  key the operation needs. It imports what it finds into `keys` with
  `xs_keys_add_*` and returns `XS_OK`, also when it found nothing.
- Keys it imports are resolved by the rules of any key manager: bounded by the
  operation's resource policy, the document's names select them, and they are
  trusted as keys the application supplied. `keys` belongs to the running
  call: keys imported into it serve the rest of that call, so the callback is
  asked only for names not yet imported, and once per method for a request
  without names. Its handle is destroyed when the callback returns.
- A verification whose signature names no key (no `KeyName`, or no
  `KeyInfo` at all) uses the one key the callback imported for that request,
  as a preset key the policy must admit, when the document's own sources give
  none.
- A decryption selects the key the `EncryptedKey` names, asked for with that
  key's own transport or wrap method, also when it is nested in another
  `EncryptedKey`; when the document names none, the one key the callback
  imported for that request. A key imported for a key wrap method (for
  example `kw-aes128`) only unwraps and is never taken for a content key. A
  decryptor created with the zero key manager decrypts only through a lookup.
- Any status other than `XS_OK` fails the call with that status, before a
  decryption changes the document; a value the header does not name becomes
  `XS_INTERNAL`.
- The callback may call the library. Destroying a handle the running call
  uses, or operating on its document, returns `XS_BUSY`.

## Tree documents

An application that works on its document as a tree links `xml-sec-libxml2`
instead. That library exports the whole C API above, the tree functions of
`crates/xml-sec-libxml2/include/xs_tree.h` (shaped like libxml2's tree
interface, under the `xs` prefix where libxml2 has `xml`) and one entry
point, declared in `crates/xml-sec-libxml2/include/xml_sec_libxml2.h`. It
links no XML library: the tree is the library's own, parsed by its core.

```c
xmlDocPtr doc = xsReadMemory(xml, len, NULL, NULL, 0);
XsDocument document;
xs_tree_document(policy, XS_OPERATION_SIGN, doc, &document, &error);
xs_sign(signer, document, &audit, &error);  /* fills the template in doc */
xs_document_destroy(document);              /* doc stays the caller's */
xsDocDumpMemory(doc, &bytes, &size);
xsFree(bytes);
xsFreeDoc(doc);
```

- The tree types (`xmlDoc`, `xmlNode`, `xmlNs`, `xmlAttr`, `xmlNodeSet`) are
  incomplete: a pointer is a handle the library validates on every call, and
  a handle that names nothing live is refused, never dereferenced. Node
  fields are read through accessors (`xsNodeGetChildren`, `xsNodeGetName`,
  ...); strings they return are copies released with `xsFree`.
- No function reads a file or a URL: the application reads its document and
  passes the bytes.
- The document handle reads the tree as it is when each operation starts,
  under that operation's compiled policy, so the application may change the
  tree through the tree functions between calls. While a call runs, nothing
  else uses the tree.
- Operations change the tree itself: signing writes the template's values,
  encryption replaces the element by `EncryptedData`, decryption restores it.
  Nodes an operation does not touch keep their handles; handles of nodes it
  removes are refused afterwards. A failed call leaves the tree as it was.
- `xs_document_serialize` refuses the handle with `XS_DOCUMENT`: the
  application serializes its tree with `xsDocDumpMemory`.

```sh
cargo build --release -p xml-sec-libxml2
# target/release/libxml_sec_libxml2.{so,dylib,a}
```

Nothing is loaded or resolved at run time, so the library is qualified
wherever the clean C API is. The crate's `SAFETY.md` records what it assumes
and guarantees.

## Qualification

`cargo run -p xml-sec-tools -- capi` builds the library, builds
`crates/xml-sec-capi/tests/c/roundtrip.c` (C99) and `tests/cpp/roundtrip.cpp`
(C++17) with the platform's compiler against the header and that library, runs
them, and checks that the library exports exactly the functions the header
declares. The C program signs, verifies a valid and a tampered document,
encrypts, decrypts, verifies and decrypts with keys from a lookup, replaces the
policy and exercises policy refusals, callback reentry and failure, and wrong,
destroyed and invalid arguments; the C++ program verifies through a lambda
lookup. It also builds the tree library, checks its exports against its
headers, and runs `crates/xml-sec-libxml2/tests/c/roundtrip.c`, which links
nothing else: it signs and verifies a tree document, sees a change the caller
makes between calls, encrypts and decrypts in place, and checks that untouched
nodes keep their handles and removed ones are refused. CI runs them on Linux, macOS
and Windows. `capi --sanitize` repeats them on Linux with the libraries and the
crates' own tests (handle table, concurrent destroy, argument validation,
callbacks, panic containment, redacted diagnostics, tree layout and edits)
under AddressSanitizer and the programs under AddressSanitizer, LeakSanitizer
and UndefinedBehaviorSanitizer. `SAFETY.md` in each crate records the
invariants of its one `unsafe` module.
