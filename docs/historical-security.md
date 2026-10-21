# Historical XML Security Regression Corpus

`tests/historical_security.rs` exercises public APIs with locally generated
synthetic inputs. The cases describe attack **classes**, not a claim that
every historical CVE has been reproduced or that an independent audit has
been completed. No production policy is relaxed to make a test pass.

## Sources And Invariants

| Class | Primary source | Executable case and required result |
| --- | --- | --- |
| Signature wrapping | [XMLDSig Best Practices §3.1.5](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/#modified-approval-example-wrapping-attack) and [XMLDSig 1.1 §8.1.1](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Secure) | `wrapping_cannot_authorize_an_unsigned_sibling_even_with_valid_crypto`: the relocated payload's real HMAC stays valid, but evidence cannot authorize the unsigned sibling. |
| SAML assertion substitution | Same signed-content invariant; SAML's expected assertion is supplied by the application | `secure_saml_requires_the_authenticated_assertion_not_the_first_assertion`: compiled SecureSaml accepts the authenticated assertion, never the first unsigned lookalike in a Response. This is XML signature coverage, not full SAML protocol validation. |
| Duplicate IDs | [XMLDSig 1.1 §4.4.3.3](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Same-Document) | `duplicate_ids_never_choose_an_attacker_controlled_first_or_last_match`: conflicting `ID`/`xml:id` values refuse resolution regardless of order or equal text. Ambiguous IDs are not first/last-match selections. |
| Attacker-selected HMAC truncation | [CERT VU#466161](https://www.kb.cert.org/vuls/id/466161/) and [XMLDSig 1.1 §6.3.1](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-HMAC) | `hmac_truncation_refuses_genuine_short_prefixes_not_only_random_forgeries`: genuine 80/120-bit prefixes refuse with the operation's 128-bit minimum; the original 128-bit MAC verifies. |
| RetrievalMethod loops | [Best Practices §2.1.5](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/#retrieval-method-loop) | `retrieval_method_self_reference_is_not_recursive_key_discovery`: an X509Data retrieval targeting its own RetrievalMethod fails the required target-kind check, without recursive processing. |
| External-resource abuse | [Best Practices §2.1.6](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/#problematic-external-references) | `external_reference_and_retrieval_uris_are_refused_before_acquisition`: both Reference and actively used RetrievalMethod refuse file, network and relative external URIs. No I/O resolver is installed. A preset trusted key deliberately does not resolve unused embedded KeyInfo. |
| Entity amplification / external entities | [Best Practices §4.2](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/#for-signers-and-verifiers-be-aware-of-schema-processing) | `entity_amplification_is_refused_at_the_public_xml_policy_boundary`: Modern's no-DTD contract refuses nested replacement definitions and external entities at the initial parser boundary; the DTD-free signed control verifies. |
| XSLT amplification | [Best Practices §2.1.1](https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/#xslt-denial) | `xslt_amplification_keeps_compatibility_but_cannot_escape_operation_limits`: a real four-level nested-loop transform verifies under explicit compatibility, refuses under Modern, and exhausts a tighter operation-wide work limit. Requires `xslt`. |
| RSA CPU abuse | [XMLDSig 1.1 §8.3](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyLength) | `rsa_oversized_modulus_and_exponent_refuse_before_big_integer_verification`: public key resolution refuses a modulus above the hard ceiling and an exponent above the supported range; a bounded key resolves. The component check precedes bigint construction. These bounds are implementation safety decisions, not RSA syntax rules. |
| Algorithm downgrade and padding probes | [XMLEnc 1.1 §§6.1, 6.1.3](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-backwards-compatibility-attacks) | `cbc_downgrade_and_padding_probes_have_one_pre_decryption_policy_refusal`: valid CBC, GCM relabelled as CBC and altered CBC tails all produce algorithm-policy refusal before even key resolution under Modern. GCM decrypts under Modern; explicit compatibility still decrypts valid CBC. Requires `xmlenc`. |

The W3C Best Practices document is an informative Working Group Note, not a
normative update. Secure-profile choices and concrete resource ceilings are
product policy. The normative specifications still decide wire semantics.

The XMLEnc test proves refusal before decryption, **not** timing equality of
parser or compatibility-mode errors. Applications exposing unauthenticated
CBC must provide their own authentication and public error-handling boundary;
compatibility permission does not make CBC authenticated encryption.

## Running The Corpus

```sh
cargo nextest run --test historical_security --features xslt,xml-backends-all
```

Every compiled XML backend runs the XML-path cases, including differential
parsing when enabled. Default builds exercise all non-XSLT cases; the existing
XSLT/all-feature CI configurations also execute the amplification case. All
inputs are small, fixed and offline; work exhaustion is deterministic rather
than inferred from a wall-clock timeout. Test allocations and fixture mutation
are confined to the harness, not introduced into production paths.

The upstream fuzzing donor is pinned with the ordinary libxmlsec1 corpus:
`apps/oss-fuzz/xmlsec_dsig_verify_target.c` limits both reference and KeyInfo
URI classes before verification. Unlike that crash-oriented harness, this
corpus asserts the processing outcome. Generic mutation/replay and retained
reproducers remain documented in [the fuzzing runbook](../fuzz/README.md).
