# OPC Relationship Transforms

The XMLDSig algorithm
`http://schemas.openxmlformats.org/package/2006/RelationshipTransform`
selects and normalizes relationships before canonicalization. It supports both
`RelationshipReference SourceId` and `RelationshipsGroupReference SourceType`,
including multiple relationships with the same Type. Selectors form a union.

## Trusted Edition Selection

The edition is an application decision, not a property inferred from XML:

```rust
use xml_sec::policy::{OpcRelationshipEdition, VerificationPolicy};

let mut policy = VerificationPolicy::default();
policy.transforms.opc_relationship_edition = OpcRelationshipEdition::Ecma2012;
```

Pass that policy to `VerifyContext::policy`; select the same edition in
`SigningPolicy` when signing. `DecryptionPolicy` uses the same typed field for
CipherReference transforms. Verification never retries another edition.

| Contract | Selection | Preparation |
| --- | --- | --- |
| ECMA-376 Part 2 (2012), §13.2.4.24 | Case-sensitive Unicode | Remove Relationship contents and container-edge characters; remove comments |
| ECMA-376 Part 2 (2021), §10.6, library default | ASCII case-insensitive | Remove text and comments; preserve processing instructions |

Both editions order Ids case-sensitively, reject duplicate identifiers, remove
namespace prefixes and unused namespace declarations, and insert an absent
`TargetMode="Internal"`. The CLI selects the 2012 compatibility contract.

## Building a Reference

```rust
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{DigestAlgorithm, ReferenceBuilder, RelationshipSelector, Transform};

let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
    .uri("_rels/.rels")
    .transform(Transform::Relationship(vec![
        RelationshipSelector::SourceId("rId1".into()),
        RelationshipSelector::SourceType("urn:example:relationships".into()),
    ]))
    .transform(Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)));
```

Provide external part bytes through the operation's caller-owned resource map and
explicitly permit the URI class in policy. The core performs no filesystem or
network discovery. A canonicalization transform must immediately follow the
Relationship Transform; both editions require inclusive C14N 1.0 with or without
comments (2012 §13.2.4.4; 2021 §10.5.8.2).

The CLI accepts detached reference bytes through explicit mappings:

```sh
xmlsec1 sign --privkey-pem key.pem --url-map:part.rels part.rels --output signed.xml template.xml
xmlsec1 verify --pubkey-pem public.pem --url-map:part.rels part.rels signed.xml
```

The mapping matches the resolved reference URI exactly. Duplicate mappings and
missing URL parameters are rejected. Unmapped references never open files or
fetch URLs; per-file and aggregate operation limits bound mapped bytes.

MCE processing follows ECMA-376 Part 3 §§7 and 9, with only the Relationships
application namespace understood. Ignorable and ProcessContent bindings retain
their declaring namespace scope, AlternateContent selects the first understood
Choice or its Fallback, and preservation attributes do not preserve discarded
content. Traversal is iterative and charged to operation limits.

`ResourcePolicy.max_opc_parameter_bytes` bounds cumulative parameter allocations;
`max_opc_workspace_bytes` bounds cumulative normalization workspace. Shared XML,
node-filter work, and canonical output limits also apply. Node-set input respects
its visibility mask; byte input uses the selected XML backend and shared decoder,
including UTF-16. This transform is not a complete OPC package validator: package
part existence, target resolution, and signature packaging rules remain separate.
Generic SignedInfo and CipherReference execution therefore remain available.
Successful XMLDSig verification is not OPC package conformance: the package
adapter must independently enforce Manifest placement and one Relationship
Transform per package part (2021 §10.5.8.2; 2012 §§13.2.4.7, 13.2.4.23).

The normative editions are available from [Ecma International](https://ecma-international.org/publications-and-standards/standards/ecma-376/).
