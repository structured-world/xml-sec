# Policy Schema Version 1 Reference

This is the application schema of `xml-sec-config`, not a TOML language version
or a new policy implementation. The [configuration guide](policy-configuration.md)
owns loading, inheritance and effective-output behavior; the
[deployment runbook](deployment.md) explains restrictive rollout. The checked
[sample](examples/policy-v1.toml) is compiled by the documentation gate.

## Document And Operation Tables

`schema_version = 1` and `profiles` are the only root fields. Each
`profiles.NAME` contains exactly one of `base` or `extends` and optional
`verification`, `signing`, `encryption`, `decryption` tables. `base` accepts
`Modern`, `SecureSaml`, `WsSecurity`, `Xades`, `XadesExtended`, `XadesConformant`,
`XmlSecCompatible`, `LegacyVerify`.
`extends` names another profile in the same document. Missing parents and
cycles fail. All profiles are validated, not only the selected one.

A profile may also carry a `deny` table, the permissions it withdraws from what
it inherits without restating the allowlists. Its arrays are `transforms`
(transform and canonicalization URIs), `signature_algorithms` and
`digest_algorithms` (algorithm URIs), `key_sources` (the key-source names below)
and `reference_uri_classes` (`empty`, `same_document`, `external`). Each value
must name something the build knows, so a misspelt denial fails loading. A
denial only withdraws: denying what the profile already refuses changes nothing,
and a child that extends the profile keeps it. A denied signature URI withdraws
the method it names in every parameterization: denying
`http://www.w3.org/2007/05/xmldsig-more#rsa-pss` withdraws every RSA-PSS tuple
(RFC 9231 2.3.10 carries the parameters in the element), whatever
`parameterized_rsa_pss` or an explicit descriptor grants. The effective
settings report the result as `denied_signature_algorithms`.

Each operation optionally accepts `enabled` (boolean). `false` must be the
only field in that operation table. Omission inherits; a child cannot re-enable
a disabled operation. Encryption tables require an encryption-enabled build.

| Field | Applicable operations | Value |
| --- | --- | --- |
| `signature_algorithms` | verify, sign | Algorithm URI array or `"default"`; parameterized RSA-PSS descriptors described below |
| `verify_only_signature_algorithms` | sign | Algorithm URI array: the verify-only methods (SHA-1 and weaker families) that `signature_algorithms` may list for signing; compilation refuses one listed there but not here. Empty by default; layers intersect |
| `denied_signature_algorithms` | verify, sign | Algorithm URI array withdrawn by denials, before any grant; layers unite |
| `digest_algorithms` | verify, sign | Digest URI array or `"default"` |
| `parameterized_rsa_pss` | verify, sign | `ExactOnly`, `SecureSupported`, `Sha1Supported` (also SHA-1, never MD5 or RIPEMD-160), `AllSupported` |
| `signature_constraints` | verify, sign | `General`, `Saml`, `WsSecurity`, `Xades` |
| `ecdsa_signature_value_encoding` | verify, sign | `XmlDsig`, `XmlSecAsn1Der` |
| `manifest_processing` | verify, sign | `Ignore`, `Process` |
| `request_selections` | verify, sign | Table of arrays a request may select in place of the policy's value: `same_document_id_semantics` (`Specification`, `XmlSecBarename`, `XmlSecVisa3d`), `ecdsa_signature_value_encodings` (`XmlDsig`, `XmlSecAsn1Der`), `manifest_processing` (`Ignore`, `Process`). Layers intersect; fewer values is restrictive |
| `detached_digest_attestation` | verify | `Forbidden`, `Accepted` |
| `timestamp_token_encoding` | verify | `Declared`, `Ber` |
| `hmac` | verify, sign | `minimum_key_bits`, `minimum_output_bits` (nonnegative integers) |
| `uris` | all | Nested table below |
| `transforms` | verify, sign, decrypt | Nested table below |
| `key_trust`, `key_sources` | verify | Nested tables below |
| `rsa_keys` | sign, encrypt, decrypt | `minimum_modulus_bits` (nonnegative integer) |
| `dsa_keys` | sign | `minimum_modulus_bits` (nonnegative integer) |
| `data_algorithms` | encrypt, decrypt | Content-algorithm URI array or `"default"` |
| `key_transport_algorithms` | encrypt, decrypt | Key-transport URI array or `"default"` |
| `key_wrap_algorithms` | encrypt, decrypt | Key-wrap URI array or `"default"` |
| `oaep_digests` | encrypt, decrypt | OAEP digest URI array or `"default"` |
| `key_establishment`, `xml`, `resources`, `validity` | all | Nested settings below |

Names and enum spellings are case-sensitive. URI arrays contain exact public
algorithm URIs from the [signature](xmldsig.md), [encryption](xmlenc.md) and
[provider](crypto-providers.md) contracts, not display names. Empty arrays deny
all selections. `"default"` maps to the typed field's `None` semantics, not
permission for every algorithm. Omission inherits rather than resetting a field.
Duplicate selections, unknown fields and fields in the wrong operation fail.
Numeric shape alone is insufficient: compilation also enforces hard ceilings,
minima, feature/provider availability and cross-field consistency.

## URI And Transform Tables

`uris` accepts `references`, `retrieval_methods`, `key_info_references`, each
an array containing any distinct subset of `"empty"`, `"same-document"`,
`"external"`. An empty array denies every URI class. External permission does
not create a resolver, resource map or network access. In the `encryption`
table, `references` bounds a resource an encryption reads by URI and the other
two bound the key references of its key.

| `transforms` field | Value |
| --- | --- |
| `allowed_algorithms` | Exact transform-URI array or `"default"` |
| `xpath_here_semantics` | `Specification`, `XmlSecLegacy` |
| `same_document_id_semantics` | `Specification`, `XmlSecBarename`, `XmlSecVisa3d` |
| `opc_relationship_edition` | `Ecma2012`, `Ecma2021` |
| `relationship_target_mode_semantics` | `Specification`, `Libxmlsec1` |
| `xslt_stylesheet_semantics` | `Specification`, `Libxmlsec1` |
| `empty_digest_input` | `Accept`, `Refuse` |
| `generated_canonicalization` | `ExplicitExclusiveC14n`, `Implicit` |

These interpretation choices are not ordered security levels. Restrictive
composition rejects incompatible modes rather than selecting the last value.
`generated_canonicalization` belongs to the `signing.transforms` table alone,
since only signing generates a transform; the other tables refuse it as a
schema error. `ExplicitExclusiveC14n`, which every named profile selects,
writes an Exclusive C14N `Transform` into a Reference whose chain ends in a
node set; `Implicit` writes nothing and leaves the node set to the Canonical
XML 1.0 conversion every verifier applies, as libxmlsec1 signs. A layer
restates its base's choice, so `Implicit` is reached only through a policy
built in code.
`empty_digest_input` is the exception: it is a restriction, so a layer that
refuses to digest a Reference whose transforms produce no octets keeps
refusing it whatever another layer says.

## Key Trust And Sources

`key_sources` accepts booleans `preset_key`, `key_name`, `key_value`,
`der_encoded_key_value`, `x509_data`, `key_info_reference`. A source permission
does not itself establish trust or supply a key.

| `key_trust` field | Value |
| --- | --- |
| `mode` | `RequireTrustedKey`, `CryptographicOnly` |
| `verify_x509_chains`, `check_crls` | Boolean |
| `max_x509_chain_depth`, `max_x509_candidate_paths` | Nonnegative integer |
| `rsa_keys`, `dsa_keys` | Tables with `minimum_modulus_bits` |
| `allowed_legacy_signature_algorithms` | Exact signature-URI/descriptor array |
| `parameterized_rsa_pss` | `ExactOnly`, `SecureSupported`, `Sha1Supported`, `AllSupported` |
| `certificate_signature_algorithms` | `"default"`, `"AllSupported"`, or descriptor array |
| `allowed_extended_key_usages` | Purpose array, described below |
| `verification_time` | `"system"` or explicit timestamp below |
| `unknown_x509_certificate` | `References`, `Libxmlsec1` |
| `trust_anchor_signer` | `Validated`, `Accepted` |

`trust_anchor_signer` decides a signing certificate that is itself a
configured trust anchor (ETSI EN 319 102-1 V1.4.1 5.2.6.4 step 1):
`Validated` checks it as the one-certificate path it forms, its validity
period included; `Accepted` passes it as trusted, as step 1(b) permits. It is
a permission, so a layer composes it restrictively: `Accepted` survives only
where every layer accepts. `XadesConformant` accepts; every other profile
validates.

`unknown_x509_certificate` is an interpretation, composed like the transform
semantics: it decides which `X509Data` children a lookup that stops on an
unknown certificate refuses. `References` refuses only a child naming a
certificate no store holds, as libxmlsec1 documents its flag; `Libxmlsec1`
refuses any child that yields no certificate, an `X509CRL` included, as its
implementation does. The libxmlsec1-compatible profiles select `Libxmlsec1`.

An extended purpose is `ServerAuth`, `ClientAuth`, `CodeSigning`,
`EmailProtection`, `TimeStamping`, `OcspSigning`, or an array of nonnegative
OID arcs. An arc may be an integer or a decimal string when needed to express
its full unsigned width. Core validation still checks the OID/purpose contract.

Certificate/CRL descriptors use `kind = "Dsa"`, `"RsaPkcs1v15"` or `"Ecdsa"`
with `digest` URI; `"RsaPss"` additionally requires `mgf_digest` and `salt_len`;
`"Ed25519"` and `"Ed448"` have no additional fields. `"PostQuantum"` requires
`uri` naming a supported pure PQ signature. Extraneous fields are rejected.
The certificate allowlist is independent of XML signature permissions.

A parameterized XML RSA-PSS selection is an inline table with exactly `uri`,
`digest`, `mgf_digest`, `salt_len`. `uri` must resolve to parameterized RSA-PSS;
the digests are exact URIs and salt length is a nonnegative integer. Fields
cannot override a fixed-method URI's semantics.

## Key Establishment

| Field | Value |
| --- | --- |
| `agreement_algorithms`, `derivation_algorithms`, `digest_algorithms` | Applicable URI array or `"default"` |
| `encapsulation_algorithms` | KEM URI array; no `"default"` shorthand |
| `kem_content_authentication` | `RequireAuthenticatedCipher`, `ExternalAuthenticated` |
| `kem_signature_trust` | `RequireCryptographicOnly`, `AcceptRecipientKey` |
| `max_encapsulation_operations`, `max_hash_blocks`, `max_owned_bytes` | Nonnegative integer |
| `max_dh_modulus_bits`, `minimum_dh_modulus_bits`, `minimum_dh_subgroup_bits`, `max_modular_work` | Nonnegative integer |

Every named profile states these sets explicitly, so the effective output
lists them and a layer narrows them element by element. Outbound operations
(signing, encryption) admit ECDH-ES, X25519 and X448 with `ConcatKDF`, HKDF or
PBKDF2 over SHA-2 in every profile. Inbound operations (verification,
decryption) admit the same, except `XmlSecCompatible`, whose ceiling adds what
libxmlsec1 agrees and derives with: DH-ES, and SHA-1 and SHA-3 KDF digests. A layer switches any of them off by listing the rest; none of the
profiles admits the XML Encryption 1.0 `xmlenc#dh` agreement.

`ExternalAuthenticated` asserts a caller-owned authenticity boundary; it does
not implement that authenticator or turn CBC padding into key confirmation.
The selected provider and immutable operation allowance still govern execution.
`AcceptRecipientKey` lets a verification that requires a trusted key take a
KEM/HMAC signature, the recipient key standing for that trust; the result still
establishes no sender identity. The inbound operations of `XmlSecCompatible`
(verification and decryption) and the verification of `LegacyVerify` admit the
ML-KEM parameter sets the provider supports with `ExternalAuthenticated` and
`AcceptRecipientKey`, as libxmlsec1 behaves; outbound operations and the other
profiles admit no KEM and keep both defaults. Composition keeps the stricter
value of each.

## XML And Resource Tables

`xml` accepts boolean `allow_internal_dtd`, which grants neither external DTD
loading nor network discovery, and `key_names`: `Specification` (the default)
reads `KeyName`, `CarriedKeyName`, `DerivedKeyName` and `MasterKeyName` with
significant white space, as XMLDSig 1.1 section 4.5.1 and XML Encryption 1.1
sections 3.5.1 and 3.5.2 require; `Libxmlsec1` first removes leading and
trailing white space, as libxmlsec1 does. Layers must agree on `key_names`.

Every `resources` value is a nonnegative integer. Field names and units follow
the public `ResourcePolicy`; they are maxima, not evidence that a deployment can
raise a hard safety ceiling. Their complete names are grouped here for lookup:

| Area | Fields |
| --- | --- |
| XML | `max_xml_nodes`, `max_xml_depth`, `max_xml_namespace_bindings`, `max_xml_document_bytes`, `max_xml_parse_work_bytes` |
| References | `max_references`, `max_signatures`, `max_transforms_per_reference`, `max_xml_base_components`, `max_xml_base_resolution_bytes`, `max_canonicalized_bytes` |
| External bytes | `max_external_resource_bytes`, `max_external_resource_total_bytes` |
| Streamed detached payloads | `max_detached_payload_bytes`, `max_detached_payload_total_bytes` |
| Encryption | `max_encryption_plaintext_bytes`, `max_encryption_recipients`, `max_encryption_metadata_bytes` |
| Keys and certificates | `max_key_candidates`, `max_x509_work`, `max_x509_workspace_bytes`, `max_key_import_kdf_work`, `max_key_import_kdf_memory_bytes`, `max_key_info_reference_depth`, `max_key_info_children` |
| Base64 | `max_base64_transform_input_bytes`, `max_base64_transform_output_bytes` |
| XPath | `max_xpath_expressions`, `max_xpath_expression_bytes`, `max_xpath_expression_complexity`, `max_xpath_context_evaluations`, `max_xpath_evaluation_work`, `max_xpath_mirror_string_bytes`, `max_xpath_string_work_bytes`, `max_xpath_namespace_bindings`, `max_xpath_namespace_bytes`, `max_xpath_filters` |
| Node sets | `max_node_set_filter_work`, `max_node_set_entries`, `max_node_set_owned_string_bytes`, `max_node_set_cumulative_owned_string_bytes` |
| OPC | `max_opc_parameter_bytes`, `max_opc_workspace_bytes` |
| XSLT | `max_xslt_work`, `max_xslt_workspace_bytes`, `max_xslt_output_bytes`, `max_xslt_recursion_depth` |

Use `policy show-effective` to inspect every inherited value under the actual
provider and feature build, rather than copying a default table that can drift.
Source-byte, workspace and work budgets are separate dimensions. They remain
cumulative through nested references, recipients and retries.

## Validity And Time

`validity = "none"` is valid only without an inherited authorization. Otherwise
`validity` is a table with `authorization_id`, `authority`, `reason`,
`not_before`, `expires_at`. Metadata must match the authenticated grant passed
by the application; config cannot create or change authority. Child intervals
can restrict but cannot extend the inherited half-open grant interval.

A timestamp is signed Unix seconds or `{ seconds = -1, nanoseconds = 500000000 }`.
`nanoseconds` is in `0..1000000000`; that example means half a second before
the epoch. Both fields are mandatory in table form. Effective output uses this
exact form; operating-system representability still applies. `"system"` is
supported only by `key_trust.verification_time`, not grant boundaries.
These timestamps are not a leap-second table or civil-time conversion service;
UTC evidence is separate [request context](key-management.md).

## Error And Rollout Contract

Unknown schema versions, syntax/type errors, unknown/inapplicable fields,
duplicate selections, contradictory semantics, unavailable capabilities and
unauthorized relaxations fail before XML execution. Loading is bounded by
explicit `LoadLimits`, not XML budgets. No config discovery, environment read,
watcher, key loading or implicit provider selection occurs.

`show-effective` emits complete deterministic policy, not keys or request bytes.
`diff` classifies effective changes; a successful command does not mean every
change is restrictive. Inspect the classifications and authenticate any approved
relaxation before applying a replacement. See the [deployment runbook](deployment.md).
