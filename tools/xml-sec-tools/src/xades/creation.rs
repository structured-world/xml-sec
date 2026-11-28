//! `xades creation [--results DIR]`: EU DSS's independent reading of the
//! signatures xml-sec creates and augments. The `create_probe` example signs
//! every packaging mode with the creation fixtures, `properties_probe` signs
//! with every optional qualifying property, `augment_probe` creates a
//! signature with content timestamps from the content fixtures and adds a
//! TSA token to a B-B signature with the augmentation fixtures, the CRLs and
//! OCSP response of the level fixtures to their B-T signature, from its own
//! B-T signature and CRLs, an archive timestamp and its renewal, and to the
//! level fixtures' B-LT `Manifest` signature an archive timestamp over a
//! `RenewedDigestsV2` of its detached object. DSS must
//! classify each signature at its expected level, find it cryptographically
//! intact with every reference found and intact, identify the signing
//! certificate and find every timestamp intact over its message imprint.
//! In the other direction DSS (`FormProbe`) makes the signature forms its own
//! tests make with the creation fixtures' signer, and `level_probe` must find
//! every signature of each valid at XAdES-BASELINE-B.

use super::{Corpus, absolute, line, xml};
use serde_json::{Map, Value, json};
use std::path::Path;

#[cfg(test)]
mod tests;

/// One created document and what DSS must report in it.
#[derive(Clone, Copy)]
pub(crate) struct Case {
    pub(crate) name: &'static str,
    /// Signatures, a countersignature counting as one of its own.
    pub(crate) signatures: usize,
    /// The format of every signature, or `|`-separated formats each found on
    /// some signature and covering all of them.
    pub(crate) format: &'static str,
    /// Timestamp tokens.
    pub(crate) timestamps: usize,
    /// The fixture directory the document was created with.
    pub(crate) fixtures: &'static str,
}

const fn created(name: &'static str, signatures: usize) -> Case {
    Case {
        name,
        signatures,
        format: "XAdES-BASELINE-B",
        timestamps: 0,
        fixtures: "creation",
    }
}

pub(crate) const CASES: [Case; 69] = [
    created("enveloped", 1),
    created("enveloping", 1),
    created("internally-detached", 1),
    created("detached", 1),
    created("parallel", 2),
    created("countersigned", 2),
    created("countersigned-nested", 3),
    created("detached-multiple", 1),
    created("inclusive", 1),
    created("prefixes", 1),
    created("empty-prefix", 1),
    created("placement-first-child", 1),
    created("placement-before", 1),
    created("placement-after", 1),
    created("placement-last-child", 1),
    created("reference-detached-xml", 1),
    created("signed-key-info", 1),
    created("manifest", 1),
    created("manifest-multiple", 1),
    created("manifest-transforms", 1),
    created("manifest-supplied", 1),
    // References the caller composes (`DataObject::Reference`).
    created("reference-filter2", 1),
    created("reference-xpath", 1),
    created("reference-by-id", 1),
    created("reference-comments", 1),
    created("object-base64", 1),
    created("reference-xslt", 1),
    // The optional qualifying properties (`properties_probe`).
    created("policy-explicit", 1),
    created("policy-transforms", 1),
    created("policy-implied", 1),
    created("policy-local-uri", 1),
    created("commitment", 1),
    created("signer-role", 1),
    created("production-place", 1),
    created("data-object-format", 1),
    created("countersigned-properties", 2),
    created("policy-store-added", 2),
    created("policy-supplied", 1),
    created("policy-asn1", 1),
    // Signatures in the historical vocabularies, which DSS also reports as
    // XAdES-BASELINE-B.
    created("historical-v111", 1),
    created("historical-v122", 1),
    created("historical-pre-en", 1),
    Case {
        name: "content-timestamps",
        signatures: 1,
        format: "XAdES-BASELINE-B",
        timestamps: 2,
        fixtures: "content",
    },
    // The TS 101 903 levels of a B-T signature, in the EN 319 132 names:
    // its complete references, then the X timestamp over them.
    Case {
        name: "c",
        signatures: 1,
        format: "XAdES-C",
        timestamps: 1,
        fixtures: "content",
    },
    Case {
        name: "x",
        signatures: 1,
        format: "XAdES-X",
        timestamps: 2,
        fixtures: "content",
    },
    // Then the values the references name, and an archive timestamp.
    Case {
        name: "xl",
        signatures: 1,
        format: "XAdES-XL",
        timestamps: 2,
        fixtures: "content",
    },
    Case {
        name: "a",
        signatures: 1,
        format: "XAdES-A",
        timestamps: 3,
        fixtures: "content",
    },
    Case {
        name: "a-renewed",
        signatures: 1,
        format: "XAdES-A",
        timestamps: 4,
        fixtures: "content",
    },
    // A signature in the pre-EN vocabulary with its signature timestamp.
    Case {
        name: "t-pre-en",
        signatures: 1,
        format: "XAdES-BASELINE-T",
        timestamps: 1,
        fixtures: "content",
    },
    // A B-LT signature sealed by an evidence record (ETSI TS 119 132-3),
    // then by a parallel one in the same property.
    Case {
        name: "e-ers",
        signatures: 1,
        format: "XAdES-ERS",
        timestamps: 2,
        fixtures: "content",
    },
    Case {
        name: "e-ers-parallel",
        signatures: 1,
        format: "XAdES-ERS",
        timestamps: 3,
        fixtures: "content",
    },
    // A new B-B signature beside the sealed one, both excluding every
    // signature from what they sign.
    Case {
        name: "e-ers-signed",
        signatures: 2,
        format: "XAdES-ERS|XAdES-BASELINE-B",
        timestamps: 3,
        fixtures: "content",
    },
    // Then with its validation values, which DSS reports as B-LT.
    Case {
        name: "lt-pre-en",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "content",
    },
    // The same in the ETSI TS 101 903 V1.1.1 and V1.2.2 vocabularies.
    Case {
        name: "lt-v111",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "content",
    },
    Case {
        name: "lt-v122",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "content",
    },
    // The pre-EN signature with its values and an archive timestamp, as
    // DSS's pre-EN B-LTA makes it.
    Case {
        name: "lta-pre-en",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 2,
        fixtures: "content",
    },
    // The TS 101 903 levels of the pre-EN signature, in the names of V1.3.2.
    Case {
        name: "c-pre-en",
        signatures: 1,
        format: "XAdES-C",
        timestamps: 1,
        fixtures: "content",
    },
    Case {
        name: "x-pre-en",
        signatures: 1,
        format: "XAdES-X",
        timestamps: 2,
        fixtures: "content",
    },
    Case {
        name: "xl-pre-en",
        signatures: 1,
        format: "XAdES-XL",
        timestamps: 2,
        fixtures: "content",
    },
    Case {
        name: "a-pre-en",
        signatures: 1,
        format: "XAdES-A",
        timestamps: 3,
        fixtures: "content",
    },
    // A B-LT signature that took the next generation of CRLs by a refresh.
    Case {
        name: "b-lt-refreshed",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "content",
    },
    Case {
        name: "content-repeated",
        signatures: 1,
        format: "XAdES-BASELINE-B",
        timestamps: 2,
        fixtures: "content",
    },
    // Content timestamps, an explicit policy and its store at B-T, then
    // extended through B-LT to B-LTA.
    Case {
        name: "content-t",
        signatures: 1,
        format: "XAdES-BASELINE-T",
        timestamps: 3,
        fixtures: "content",
    },
    Case {
        name: "content-lta",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 4,
        fixtures: "content",
    },
    Case {
        name: "b-t",
        signatures: 1,
        format: "XAdES-BASELINE-T",
        timestamps: 1,
        fixtures: "augmentation",
    },
    Case {
        name: "b-lt",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "levels",
    },
    Case {
        name: "b-lta",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 2,
        fixtures: "augmentation",
    },
    Case {
        name: "b-lta-renewed",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 3,
        fixtures: "augmentation",
    },
    // DSS does not process RenewedDigestsV2; the archive's imprint covers it.
    Case {
        name: "b-lta-manifest",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 2,
        fixtures: "levels",
    },
];

/// One signature form EU DSS makes as its signature tests make it, and the
/// signatures xml-sec must find in it, a countersignature counting as one of
/// its own.
#[derive(Clone, Copy)]
pub(crate) struct Form {
    pub(crate) name: &'static str,
    pub(crate) signatures: usize,
}

pub(crate) const FORMS: [Form; 6] = [
    Form {
        name: "parallel",
        signatures: 2,
    },
    Form {
        name: "countersigned",
        signatures: 2,
    },
    Form {
        name: "countersigned-nested",
        signatures: 3,
    },
    Form {
        name: "detached-multiple",
        signatures: 1,
    },
    Form {
        name: "inclusive",
        signatures: 1,
    },
    Form {
        name: "pretty-print",
        signatures: 1,
    },
];

/// The document every enveloped DSS form signs, and the detached files.
const FORM_DOCUMENT: &str = "<Document><Data Id=\"payload\">Form payload</Data></Document>";
const FORM_DETACHED: [(&str, &str); 2] = [
    ("detached.txt", "Detached payload\n"),
    ("detached-2.txt", "Second detached payload\n"),
];

/// The detached files a case's references name.
fn detached_files(name: &str) -> &'static [&'static str] {
    match name {
        "detached" | "commitment" => &["detached.txt"],
        "detached-multiple" | "manifest" | "manifest-multiple" => {
            &["detached.txt", "detached-2.txt"]
        }
        "reference-detached-xml" | "manifest-transforms" => &["detached-data.xml"],
        "manifest-supplied" => &["detached.txt", "detached-data.xml"],
        _ => &[],
    }
}

/// Why xml-sec's reading of a DSS form does not qualify: every signature
/// `level_probe` reports must be valid and meet XAdES-BASELINE-B.
pub(crate) fn assess_form(form: &Form, output: &str) -> Value {
    let reports: Vec<Value> = output
        .split("signature: ")
        .skip(1)
        .map(|chunk| super::lifecycle::xml_sec_outcome(&format!("signature: {chunk}")))
        .collect();
    let mut problems = Vec::new();
    if reports.len() != form.signatures {
        problems.push(format!(
            "{} signatures reported, {} expected",
            reports.len(),
            form.signatures
        ));
    }
    for (index, report) in reports.iter().enumerate() {
        if report["crypto"] != "Valid" || report["structure"] != "met" {
            problems.push(format!("signature {index}: {report}"));
        }
    }
    json!({ "name": form.name, "signatures": reports, "problems": problems })
}

/// The instant the probe assesses at, inside every creation certificate.
const TIME: &str = "1800000000";

/// Whether the diagnostic report has `expected` timestamps, each intact over
/// its message imprint (RFC 3161 §2.4.2).
fn tokens(diagnostic: xml::Node<'_, '_>, expected: usize, problems: &mut Vec<String>) {
    let mut found = 0;
    for timestamp in xml::below(diagnostic, "Timestamp", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
    {
        found += 1;
        let id = timestamp.attribute("Id").unwrap_or_default();
        if xml::text_at(timestamp, &["BasicSignature", "SignatureIntact"]).as_deref()
            != Some("true")
        {
            problems.push(format!("{id}: timestamp signature not intact"));
        }
        for matcher in xml::below(timestamp, "DigestMatcher", None) {
            let true_at = |field| xml::text_at(matcher, &[field]).as_deref() == Some("true");
            if !(true_at("DataFound") && true_at("DataIntact")) {
                problems.push(format!("{id}: message imprint not found or not intact"));
            }
        }
    }
    if found != expected {
        problems.push(format!("{found} timestamps, {expected} expected"));
    }
}

/// One fact DSS must report in a case's diagnostic report.
pub(crate) enum Expect {
    /// Some element matching the path holds the text: `element` names it by
    /// local name, `element@attribute` reads an attribute instead, and a
    /// `scope/` prefix limits the search to elements below one named `scope`.
    Text(&'static str, &'static str),
    /// Some `parent` element holds every one of these (element, text) facts
    /// below itself: values that belong together, such as a commitment's
    /// identifier and its scope.
    Together(&'static str, &'static [(&'static str, &'static str)]),
    /// Exactly `count` elements of local name `local` that carry a
    /// `BasicSignature` (validated objects such as revocation data).
    Validated(&'static str, usize),
    /// Exactly `count` elements of local name `local` whose `attribute` has
    /// this value.
    Counted(&'static str, &'static str, &'static str, usize),
    /// The fact holds within the diagnostic signature of the `ds:Signature`
    /// with this `Id` (its `DAIdentifier`).
    In(&'static str, &'static Expect),
    /// Exactly `count` elements of local name `local`, each holding every
    /// one of these (element, text) facts below itself.
    Each(&'static str, usize, &'static [(&'static str, &'static str)]),
}

const POLICY: &str = "1.3.6.1.4.1.13762.3.1";
const PROOF_OF_ORIGIN: &str = "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin";
const PROOF_OF_APPROVAL: &str = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";

/// What DSS reports of a well-formed evidence record over intact objects.
const EVIDENCE_RECORD: &[(&str, &str)] = &[
    ("StructuralValidation@valid", "true"),
    ("DataIntact", "true"),
];

/// The facts of the optional properties DSS must report for `name`.
fn expected_properties(name: &str) -> &'static [Expect] {
    use Expect::{Counted, Each, In, Text, Together};
    if name.starts_with("policy-") {
        return policy_properties(name);
    }
    match name {
        // Each commitment with its own scope.
        "commitment" => &[
            Together(
                "CommitmentTypeIndication",
                &[
                    ("Identifier", PROOF_OF_ORIGIN),
                    ("AllDataSignedObjects", "true"),
                ],
            ),
            Together(
                "CommitmentTypeIndication",
                &[
                    ("Identifier", PROOF_OF_APPROVAL),
                    ("ObjectReference", "sig-reference-1"),
                ],
            ),
        ],
        // Each role with its category: two claimed roles and one signed
        // assertion.
        "signer-role" => &[
            Together(
                "SignerRole",
                &[("Role", "Manager"), ("@Category", "claimed")],
            ),
            Together(
                "SignerRole",
                &[("Role", "Approver"), ("@Category", "claimed")],
            ),
            Counted("SignerRole", "Category", "claimed", 2),
            Counted("SignerRole", "Category", "signed", 1),
        ],
        "production-place" => &[
            Text("City", "Prague"),
            Text("StreetAddress", "Main Street 1"),
            Text("PostalCode", "11000"),
            Text("CountryName", "CZ"),
        ],
        // The countersignature's own place and claimed roles.
        "countersigned-properties" => &[
            In("counter", &Text("City", "Prague")),
            In("counter", &Text("StreetAddress", "Main Street 1")),
            In("counter", &Text("PostalCode", "11000")),
            In("counter", &Text("CountryName", "CZ")),
            In("counter", &Text("Role", "Manager")),
            In("counter", &Text("Role", "Approver")),
        ],
        // Both signed Manifests, each with its own entry.
        "manifest-multiple" => &[
            Counted("DigestMatcher", "type", "MANIFEST", 2),
            Counted("DigestMatcher", "type", "MANIFEST_ENTRY", 2),
        ],
        // DSS finds every Manifest entry, each after its own transforms.
        "manifest-transforms" => &[
            Counted("DigestMatcher", "type", "MANIFEST", 1),
            Counted("DigestMatcher", "type", "MANIFEST_ENTRY", 3),
        ],
        "manifest-supplied" => &[
            Counted("DigestMatcher", "type", "MANIFEST", 1),
            Counted("DigestMatcher", "type", "MANIFEST_ENTRY", 2),
        ],
        // DSS binds SigningCertificate, digest and issuer-serial, to the
        // signer's certificate; V1.1.1 carries the policy it requires.
        "historical-v111" => &[
            Text("CertificateRef/IssuerSerial@match", "true"),
            Text("CertificateRef/DigestAlgoAndValue@match", "true"),
            Text("Policy>Id", POLICY),
        ],
        "historical-v122" | "historical-pre-en" => &[
            Text("CertificateRef/IssuerSerial@match", "true"),
            Text("CertificateRef/DigestAlgoAndValue@match", "true"),
        ],
        // Each record is well formed and its data objects are the signature's
        // own: DSS finds the signature it seals intact. The parallel case
        // holds two records, each judged on its own.
        "e-ers" => &[Each("EvidenceRecord", 1, EVIDENCE_RECORD)],
        "e-ers-parallel" => &[Each("EvidenceRecord", 2, EVIDENCE_RECORD)],
        _ => timestamp_properties(name),
    }
}

/// The facts of the cases that carry timestamps or validation data beyond
/// the signature timestamp.
fn timestamp_properties(name: &str) -> &'static [Expect] {
    use Expect::{Counted, Text, Validated};
    match name {
        "content-timestamps" => &[
            Counted("Timestamp", "Type", "ALL_DATA_OBJECTS_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "INDIVIDUAL_DATA_OBJECTS_TIMESTAMP", 1),
        ],
        "content-repeated" => &[Counted(
            "Timestamp",
            "Type",
            "ALL_DATA_OBJECTS_TIMESTAMP",
            2,
        )],
        "content-t" => &[
            Counted("Timestamp", "Type", "ALL_DATA_OBJECTS_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "INDIVIDUAL_DATA_OBJECTS_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "SIGNATURE_TIMESTAMP", 1),
            Text("Id", POLICY),
            Text("Policy/DigestAlgoAndValue@match", "true"),
        ],
        // The content timestamps and the stored policy survive the levels.
        "content-lta" => &[
            Counted("Timestamp", "Type", "ALL_DATA_OBJECTS_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "INDIVIDUAL_DATA_OBJECTS_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "SIGNATURE_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "ARCHIVE_TIMESTAMP", 1),
            Text("Id", POLICY),
            Text("Policy/DigestAlgoAndValue@match", "true"),
        ],
        // Both generations of both CAs' CRLs are incorporated.
        "b-lt-refreshed" => &[Validated("Revocation", 4)],
        // The X timestamp covers the signature, its timestamp and its
        // references.
        "x" | "x-pre-en" | "xl-pre-en" => {
            &[Counted("Timestamp", "Type", "VALIDATION_DATA_TIMESTAMP", 1)]
        }
        // The pre-EN archive timestamps cover what came before them.
        "a-pre-en" => &[
            Counted("Timestamp", "Type", "VALIDATION_DATA_TIMESTAMP", 1),
            Counted("Timestamp", "Type", "ARCHIVE_TIMESTAMP", 1),
        ],
        "lta-pre-en" => &[Counted("Timestamp", "Type", "ARCHIVE_TIMESTAMP", 1)],
        _ => &[],
    }
}

/// The facts of the signature policy cases.
fn policy_properties(name: &str) -> &'static [Expect] {
    use Expect::{In, Text};
    match name {
        // The stored document's digest, after the transforms of the second,
        // matches the signed one.
        "policy-explicit" => &[
            Text("Id", POLICY),
            Text("Identified", "true"),
            Text("Policy/DigestAlgoAndValue@match", "true"),
            Text("Organization", "Example Organization"),
            Text("ExplicitText", "Signed under the example policy"),
        ],
        "policy-transforms" => &[
            Text("Id", POLICY),
            Text("Transformation", "Canonical XML 1.0 (omits comments)"),
            Text("Policy/DigestAlgoAndValue@match", "true"),
        ],
        "policy-implied" => &[Text("Id", "IMPLICIT_POLICY")],
        // DSS reads the identifier and its qualifiers; without the document
        // it cannot check the supplied digest.
        // The policy's own fields are its direct children, apart from the
        // same values its DocSpecification repeats.
        "policy-supplied" => &[
            Text("Policy>Id", "1.2.3.4.5.6"),
            Text("Policy/Url", "http://spuri.test"),
            Text("Policy>Description", "Test description"),
            Text(
                "Policy/DocumentationReference",
                "http://nowina.lu/signature-policy.pdf",
            ),
            Text("Policy/Organization", "Nowina Solutions"),
            Text("Policy/ExplicitText", "This is a test policy"),
            Text("DocSpecification/Id", "1.2.3.4.5.6"),
        ],
        // The stored DER policy digests, as TR 102 272 says, to the signed
        // value.
        "policy-asn1" => &[
            Text("Policy/Id", "1.2.3.4.5.6"),
            Text("Policy/Identified", "true"),
            Text("Policy/Asn1Processable", "true"),
            Text(
                "Policy/Transformation",
                "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification",
            ),
            Text("Policy/DigestAlgoAndValue@match", "true"),
        ],
        // The store added to the first signature authenticates its policy;
        // the second signature, under the same policy, has none.
        "policy-store-added" => &[
            In("sig", &Text("Id", POLICY)),
            In("sig", &Text("Identified", "true")),
            In("sig", &Text("Policy/DigestAlgoAndValue@match", "true")),
            In("second", &Text("Policy/DigestAlgoAndValue@match", "false")),
            In("second", &Text("Identified", "false")),
        ],
        // DSS has no local copy to compare; it reads the identifier.
        "policy-local-uri" => &[Text("Id", POLICY)],
        _ => &[],
    }
}

/// Whether some element at the `Text` path `element` below `root` holds
/// `expected`: `scope/element` searches below each `scope`, `scope>element`
/// reads only its direct children, and `@attribute` alone reads `root`'s own
/// attribute.
fn holds_text(root: xml::Node<'_, '_>, element: &str, expected: &str) -> bool {
    if let Some(attribute) = element.strip_prefix('@') {
        return root.attribute(attribute) == Some(expected);
    }
    let (scope, direct, named) = match element.split_once('>') {
        Some((scope, named)) => (Some(scope), true, named),
        None => element
            .split_once('/')
            .map_or((None, false, element), |(scope, named)| {
                (Some(scope), false, named)
            }),
    };
    let (local, attribute) = named
        .split_once('@')
        .map_or((named, None), |(local, attribute)| (local, Some(attribute)));
    let holds = |node: xml::Node<'_, '_>| match attribute {
        Some(attribute) => node.attribute(attribute) == Some(expected),
        None => xml::text_at(node, &[]).as_deref() == Some(expected),
    };
    match scope {
        Some(scope) if direct => xml::below(root, scope, None).any(|parent| {
            parent
                .children()
                .filter(|child| child.is_element() && child.tag_name().name() == local)
                .any(holds)
        }),
        Some(scope) => {
            xml::below(root, scope, None).any(|parent| xml::below(parent, local, None).any(holds))
        }
        None => xml::below(root, local, None).any(holds),
    }
}

/// Why `expect` does not hold below `root`, if it does not.
fn unmet(root: xml::Node<'_, '_>, expect: &Expect) -> Option<String> {
    match expect {
        Expect::Text(element, expected) => (!holds_text(root, element, expected))
            .then(|| format!("DSS did not read {element} {expected:?}")),
        Expect::Together(parent, facts) => (!xml::below(root, parent, None).any(|node| {
            facts
                .iter()
                .all(|(element, expected)| holds_text(node, element, expected))
        }))
        .then(|| format!("DSS did not read one {parent} with {facts:?}")),
        Expect::Validated(local, count) => {
            let found = xml::below(root, local, None)
                .filter(|node| xml::child(*node, "BasicSignature").is_some())
                .count();
            (found != *count).then(|| format!("DSS read {found} {local}, {count} expected"))
        }
        Expect::Counted(local, attribute, value, count) => {
            let found = xml::below(root, local, None)
                .filter(|node| node.attribute(*attribute) == Some(*value))
                .count();
            (found != *count).then(|| {
                format!("DSS read {found} {local} with {attribute}={value}, {count} expected")
            })
        }
        Expect::In(id, inner) => {
            let signature = xml::below(root, "Signature", None).find(|node| {
                xml::child(*node, "BasicSignature").is_some()
                    && xml::text_at(*node, &["DAIdentifier"]).as_deref() == Some(*id)
            });
            match signature {
                Some(signature) => unmet(signature, inner).map(|why| format!("{id}: {why}")),
                None => Some(format!("DSS reported no signature {id}")),
            }
        }
        Expect::Each(local, count, facts) => {
            let nodes: Vec<_> = xml::below(root, local, None).collect();
            if nodes.len() != *count {
                return Some(format!(
                    "DSS read {} {local}, {count} expected",
                    nodes.len()
                ));
            }
            let failing: Vec<String> = nodes
                .iter()
                .enumerate()
                .filter_map(|(index, node)| {
                    let missing: Vec<_> = facts
                        .iter()
                        .filter(|(element, expected)| !holds_text(*node, element, expected))
                        .collect();
                    (!missing.is_empty()).then(|| {
                        let name = node
                            .attribute("Id")
                            .map_or_else(|| format!("#{index}"), String::from);
                        format!("{local} {name} lacks {missing:?}")
                    })
                })
                .collect();
            (!failing.is_empty()).then(|| format!("DSS: {}", failing.join("; ")))
        }
    }
}

/// Each expected property of `name` the diagnostic report does not hold.
fn property_problems(name: &str, diagnostic: xml::Node<'_, '_>, problems: &mut Vec<String>) {
    problems.extend(
        expected_properties(name)
            .iter()
            .filter_map(|expect| unmet(diagnostic, expect)),
    );
}

/// The format details `data-object-format` writes, read in the created
/// document: DSS's report keeps only the MIME type of a `DataObjectFormat`.
fn document_problems(name: &str, document: &str, problems: &mut Vec<String>) {
    if name != "data-object-format" {
        return;
    }
    let parsed = match xml::parse(document, "created document") {
        Ok(parsed) => parsed,
        Err(error) => {
            problems.push(error);
            return;
        }
    };
    // The format the signature `sig` signed: only along the direct chain
    // ds:Object/QualifyingProperties/SignedProperties/SignedDataObjectProperties,
    // not an element of the same name elsewhere in or outside the signature.
    let format = xml::below(parsed.root_element(), "Signature", Some(super::DS))
        .filter(|node| node.attribute("Id") == Some("sig"))
        .flat_map(|signature| xml::children_named(signature, "Object", super::DS))
        .flat_map(|object| xml::children_named(object, "QualifyingProperties", super::SP))
        .flat_map(|qualifying| xml::children_named(qualifying, "SignedProperties", super::SP))
        .flat_map(|signed| xml::children_named(signed, "SignedDataObjectProperties", super::SP))
        .flat_map(|properties| xml::children_named(properties, "DataObjectFormat", super::SP))
        .find(|node| node.attribute("ObjectReference") == Some("#sig-reference-0"));
    for (local, expected) in [
        ("Description", "Base64 encoded text"),
        ("Identifier", "urn:oid:1.2.840.113549.1.7.1"),
        ("Encoding", "http://www.w3.org/2000/09/xmldsig#base64"),
    ] {
        let found = format.and_then(|format| {
            xml::below(format, local, Some(super::SP))
                .next()
                .and_then(|node| xml::text_at(node, &[]))
        });
        if found.as_deref().map(str::trim) != Some(expected) {
            problems.push(format!(
                "DataObjectFormat of #sig-reference-0: {local} {found:?}, {expected:?} expected"
            ));
        }
    }
}

/// Each reported signature whose format is none of `format`'s, and each of
/// them no signature has.
fn format_problems(lines: &[&str], format: &str, problems: &mut Vec<String>) {
    let formats: Vec<String> = format
        .split('|')
        .map(|format| format!(" format={format} "))
        .collect();
    for line in lines {
        if !formats.iter().any(|format| line.contains(format.as_str())) {
            problems.push(format!("not {format}: {line}"));
        }
    }
    for expected in &formats {
        if !lines.iter().any(|line| line.contains(expected.as_str())) {
            problems.push(format!("no signature reported{}", expected.trim_end()));
        }
    }
}

/// What DSS concluded on one created document, and why it does not qualify.
pub(crate) fn assess(
    case: &Case,
    output: &str,
    reports: &Path,
    document: &str,
) -> Result<Value, String> {
    let Case {
        name,
        signatures,
        format,
        timestamps,
        ..
    } = *case;
    let mut problems = Vec::new();
    // LevelProbe prints one line per signature it found.
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains(" format="))
        .collect();
    if lines.len() != signatures {
        problems.push(format!(
            "{} signatures reported, {signatures} expected",
            lines.len()
        ));
    }
    format_problems(&lines, format, &mut problems);
    let diagnostic_text = xml::read(&reports.join("diagnostic.xml"))?;
    let diagnostic = xml::parse(&diagnostic_text, "diagnostic report")?;
    tokens(diagnostic.root_element(), timestamps, &mut problems);
    property_problems(name, diagnostic.root_element(), &mut problems);
    document_problems(name, document, &mut problems);
    let mut intact = Vec::new();
    for signature in xml::below(diagnostic.root_element(), "Signature", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
    {
        let id = signature.attribute("Id").unwrap_or_default();
        let signature_intact = xml::text_at(signature, &["BasicSignature", "SignatureIntact"])
            .as_deref()
            == Some("true");
        let matchers: Vec<(String, bool)> = xml::below(signature, "DigestMatcher", None)
            .map(|matcher| {
                let true_at = |field| xml::text_at(matcher, &[field]).as_deref() == Some("true");
                (
                    matcher.attribute("uri").unwrap_or_default().to_owned(),
                    true_at("DataFound") && true_at("DataIntact"),
                )
            })
            .collect();
        if !signature_intact {
            problems.push(format!("{id}: signature value not intact"));
        }
        for (uri, ok) in &matchers {
            if !ok {
                problems.push(format!("{id}: reference {uri:?} not found or not intact"));
            }
        }
        intact.push(
            json!({ "id": id, "signature_intact": signature_intact, "references": matchers.len() }),
        );
    }
    let detailed_text = xml::read(&reports.join("detailed.xml"))?;
    let detailed = xml::parse(&detailed_text, "detailed report")?;
    let mut blocks = Vec::new();
    // DSS validates a countersignature in a block of its own type.
    for block in xml::below(detailed.root_element(), "BasicBuildingBlocks", None).filter(|block| {
        matches!(
            block.attribute("Type"),
            Some("SIGNATURE" | "COUNTER_SIGNATURE")
        )
    }) {
        let conclusions = xml::conclusions(block, "Indication");
        // EN 319 102-1 V1.4.1 §5.2.3: identification of the signing
        // certificate; §5.2.7: cryptographic verification.
        for (name, required) in [("ISC", "PASSED"), ("CV", "PASSED")] {
            if conclusions.get(name).and_then(Value::as_str) != Some(required) {
                problems.push(format!(
                    "{}: {name} is {:?}",
                    block.attribute("Id").unwrap_or_default(),
                    conclusions.get(name)
                ));
            }
        }
        blocks.push(Value::Object(conclusions));
    }
    if blocks.len() != signatures {
        problems.push(format!(
            "{} signature blocks, {signatures} expected",
            blocks.len()
        ));
    }
    let mut row = Map::new();
    row.insert("name".into(), name.into());
    row.insert(
        "reported".into(),
        lines.iter().map(|line| Value::from(*line)).collect(),
    );
    row.insert("signatures".into(), Value::Array(intact));
    row.insert("conclusions".into(), Value::Array(blocks));
    row.insert(
        "problems".into(),
        problems
            .iter()
            .map(|problem| Value::from(problem.as_str()))
            .collect(),
    );
    Ok(Value::Object(row))
}

/// Creates every case, validates it with DSS and keeps the reports.
pub(crate) fn execute(corpus: &Corpus, results: &Path) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let fixtures = corpus.root.join("crates/xml-sec-xades/tests/fixtures");
    let signed = results.join("signed");
    for (example, action, directory) in [
        ("create_probe", None, "creation"),
        ("properties_probe", None, "creation"),
        ("augment_probe", Some("content"), "content"),
        ("augment_probe", Some("content-lta"), "content"),
        ("augment_probe", Some("refresh"), "content"),
        ("augment_probe", Some("extended"), "content"),
        ("augment_probe", Some("historical-lt"), "content"),
        ("augment_probe", Some("historical-lt-v111"), "content"),
        ("augment_probe", Some("historical-lt-v122"), "content"),
        ("augment_probe", Some("pre-en-levels"), "content"),
        ("augment_probe", Some("parallel"), "content"),
        ("augment_probe", Some("complete"), "augmentation"),
        ("augment_probe", Some("extend"), "levels"),
        ("augment_probe", Some("archive"), "augmentation"),
        ("augment_probe", Some("renew"), "levels"),
    ] {
        let mut probe = line(&[
            &"cargo",
            &"run",
            &"-q",
            &"-p",
            &"xml-sec-xades",
            &"--features",
            &"produce,xslt",
            &"--example",
            &example,
            &"--",
        ]);
        probe.extend(action.map(Into::into));
        probe.extend(line(&[&fixtures.join(directory), &signed]));
        // One log per action, so a later run of the same example keeps it.
        let log = match action {
            Some(action) => format!("{example}-{action}"),
            None => example.to_owned(),
        };
        corpus.require(&probe, &results.join(log))?;
    }
    let classpath = super::dss::build(corpus, results)?.classpath;
    let mut summary = Vec::new();
    for case in &CASES {
        let reports = results.join(case.name);
        let mut probe = super::dss::java(
            &classpath,
            "LevelProbe",
            &[
                &signed.join(format!("{}.xml", case.name)),
                &fixtures.join(case.fixtures).join("root.der"),
                &TIME,
                &reports,
            ],
        );
        for file in detached_files(case.name) {
            probe.push(signed.join(file).into());
        }
        // The object its signed Manifest names.
        if case.name == "b-lta-manifest" {
            probe.push(fixtures.join("levels/detached.txt").into());
        }
        let run = corpus.require(&probe, &results.join(format!("{}-run", case.name)))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        let document = xml::read(&signed.join(format!("{}.xml", case.name)))?;
        summary.push(assess(case, &output, &reports, &document)?);
    }
    summary.extend(forms(
        corpus,
        results,
        &classpath,
        &fixtures.join("creation"),
    )?);
    super::write_json(
        &results.join("summary.json"),
        &Value::Array(summary.clone()),
    )?;
    let failed: Vec<&Value> = summary
        .iter()
        .filter(|row| {
            row["problems"]
                .as_array()
                .is_some_and(|problems| !problems.is_empty())
        })
        .collect();
    if !failed.is_empty() {
        return Err(format!(
            "the other implementation does not accept a created document (DSS for xml-sec's, xml-sec for DSS's forms under dss-forms): {}",
            Value::Array(failed.into_iter().cloned().collect())
        ));
    }
    println!(
        "EU DSS: {} created documents validated, xml-sec: {} DSS forms validated, reports saved to {}",
        CASES.len(),
        FORMS.len(),
        results.display()
    );
    Ok(())
}

/// DSS makes every form with the creation fixtures' signer, and xml-sec
/// validates each signature at B-B against the fixtures' root.
fn forms(
    corpus: &Corpus,
    results: &Path,
    classpath: &str,
    fixtures: &Path,
) -> Result<Vec<Value>, String> {
    let work = results.join("dss-forms");
    std::fs::create_dir_all(&work).map_err(|error| error.to_string())?;
    let write = |name: &str, content: &[u8]| {
        std::fs::write(work.join(name), content).map_err(|error| format!("write {name}: {error}"))
    };
    write("document.xml", FORM_DOCUMENT.as_bytes())?;
    for (name, content) in FORM_DETACHED {
        write(name, content.as_bytes())?;
    }
    // DSS takes the signer as a PKCS#12 store with its chain.
    for certificate in ["signer", "intermediate"] {
        corpus.require(
            &line(&[
                &corpus.openssl,
                &"x509",
                &"-inform",
                &"DER",
                &"-in",
                &fixtures.join(format!("{certificate}.der")),
                &"-out",
                &work.join(format!("{certificate}.pem")),
            ]),
            &work.join(format!("{certificate}-pem")),
        )?;
    }
    let store = work.join("signer.p12");
    corpus.require(
        &line(&[
            &corpus.openssl,
            &"pkcs12",
            &"-export",
            &"-inkey",
            &fixtures.join("signer.key"),
            &"-in",
            &work.join("signer.pem"),
            &"-certfile",
            &work.join("intermediate.pem"),
            &"-name",
            &"signer",
            &"-passout",
            &"pass:dss",
            &"-out",
            &store,
        ]),
        &work.join("signer-p12"),
    )?;
    let level_probe = line(&[
        &"cargo",
        &"run",
        &"-q",
        &"-p",
        &"xml-sec-xades",
        &"--features",
        &"produce",
        &"--example",
        &"level_probe",
        &"--",
    ]);
    let mut rows = Vec::new();
    for form in &FORMS {
        let document = work.join(format!("{}.xml", form.name));
        let probe = super::dss::java(
            classpath,
            "FormProbe",
            &[&store, &form.name, &work, &TIME, &document],
        );
        corpus.require(&probe, &work.join(format!("{}-dss", form.name)))?;
        let mut validate = level_probe.clone();
        validate.extend(line(&[&document, &fixtures.join("root.der"), &TIME, &"b"]));
        for file in detached_files(form.name) {
            validate.extend(line(&[&"--detached", &work.join(file)]));
        }
        let run = corpus.require(&validate, &work.join(format!("{}-xml-sec", form.name)))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        rows.push(assess_form(form, &output));
    }
    Ok(rows)
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut results = corpus.root.join("target/xades-creation-results");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => results = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades creation [--results DIR]".into()),
        }
    }
    Ok(execute(corpus, &results)?)
}
