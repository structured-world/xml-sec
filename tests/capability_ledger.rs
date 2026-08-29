use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[path = "../tools/xmlsec1/src/args.rs"]
mod cli_args;

const LEDGER_JSON: &str = include_str!("../compatibility/libxmlsec1-1.3.13.json");
const DONOR_COMMIT: &str = include_str!("../compatibility/libxmlsec1-1.3.13-donor-commit.txt");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: u32,
    upstream: Upstream,
    generated_by: String,
    evidence: BTreeMap<String, Evidence>,
    classifications: BTreeMap<String, Classification>,
    availability: Vec<AvailabilitySpan>,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Upstream {
    project: String,
    version: String,
    commit: String,
    repository: String,
}

#[derive(Debug, Deserialize)]
struct Evidence {
    test: String,
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    kind: String,
    name: String,
    source: String,
    line: usize,
    detail: String,
    exit_code: Option<i32>,
    classification: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Classification {
    outcome: String,
    rationale: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailabilitySpan {
    source: String,
    start_line: usize,
    end_line: usize,
    conditions: Vec<String>,
}

fn ledger() -> Ledger {
    serde_json::from_str(LEDGER_JSON).expect("committed capability ledger must be valid JSON")
}

fn item_id(item: &Item) -> String {
    format!("{}:{}:{}:{}", item.kind, item.source, item.line, item.name)
}

fn classification<'a>(ledger: &'a Ledger, item: &Item) -> &'a Classification {
    ledger
        .classifications
        .get(&item.classification)
        .unwrap_or_else(|| panic!("{} references unknown classification", item_id(item)))
}

fn conditions_for<'a>(ledger: &'a Ledger, item: &Item) -> &'a [String] {
    let mut matching = ledger.availability.iter().filter(|span| {
        span.source == item.source && span.start_line <= item.line && item.line <= span.end_line
    });
    let conditions = matching
        .next()
        .map_or(&[][..], |span| span.conditions.as_slice());
    assert!(
        matching.next().is_none(),
        "{} has overlapping availability spans",
        item_id(item)
    );
    conditions
}

fn declared_tests() -> BTreeSet<&'static str> {
    let mut names = BTreeSet::new();
    let mut test_attribute = false;
    for line in include_str!("capability_ledger.rs").lines() {
        let line = line.trim();
        if line == "#[test]" {
            test_attribute = true;
        } else if test_attribute {
            if let Some(declaration) = line.strip_prefix("fn ") {
                let name = declaration
                    .split_once('(')
                    .expect("test function declaration must have parameters")
                    .0;
                names.insert(name);
                test_attribute = false;
            } else if !line.starts_with("#[") {
                test_attribute = false;
            }
        }
    }
    names
}

fn validate_evidence(ledger: &Ledger) -> Result<(), String> {
    let referenced_classifications: BTreeSet<_> = ledger
        .items
        .iter()
        .map(|item| item.classification.as_str())
        .collect();
    for key in ledger.classifications.keys() {
        if !referenced_classifications.contains(key.as_str()) {
            return Err(format!(
                "classification {key} is not referenced by any item"
            ));
        }
    }
    let referenced: BTreeSet<_> = ledger
        .classifications
        .values()
        .map(|classification| classification.evidence.as_str())
        .collect();
    let tests = declared_tests();
    for (key, evidence) in &ledger.evidence {
        if !referenced.contains(key.as_str()) {
            return Err(format!("evidence {key} is not referenced by any item"));
        }
        let name = evidence
            .test
            .strip_prefix("capability_ledger::")
            .ok_or_else(|| format!("evidence test {} has no suite prefix", evidence.test))?;
        if !tests.contains(name) {
            return Err(format!("evidence test {name} does not exist in this suite"));
        }
        if evidence.description.is_empty() {
            return Err(format!("evidence {key} has no description"));
        }
    }
    Ok(())
}

#[test]
fn complete_surface_categories_are_stable() {
    // Exact category counts make an upstream or extractor drift visible in review.
    let ledger = ledger();
    assert_eq!(ledger.schema_version, 2);
    assert_eq!(ledger.upstream.project, "libxmlsec1");
    assert_eq!(ledger.upstream.version, "1.3.13");
    assert_eq!(ledger.upstream.commit, DONOR_COMMIT.trim());
    assert_eq!(
        ledger.upstream.repository,
        "https://github.com/lsh123/xmlsec"
    );
    assert_eq!(ledger.generated_by, "xml-sec-capability-ledger/2");
    assert_eq!(ledger.classifications.len(), 20);
    assert_eq!(ledger.availability.len(), 427);

    let counts = ledger
        .items
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.kind.as_str()).or_insert(0_usize) += 1;
            counts
        });
    assert_eq!(
        counts,
        BTreeMap::from([
            ("algorithm-uri", 141),
            ("backend-api", 847),
            ("build-define", 50),
            ("callback", 64),
            ("class-id", 1_078),
            ("cli-command", 24),
            ("cli-exit-status", 3),
            ("cli-option", 74),
            ("deprecated-api", 13),
            ("enum", 15),
            ("export-function", 609),
            ("export-variable", 435),
            ("header", 59),
            ("key-format", 11),
            ("macro", 1_499),
            ("registry", 15),
            ("struct-layout", 25),
            ("test-family", 20),
            ("typedef", 70),
        ])
    );
}

#[test]
fn every_entry_is_unique_sorted_and_evidenced() {
    // Deterministic ordering and complete evidence keep regeneration reviewable.
    let ledger = ledger();
    let ids: Vec<_> = ledger.items.iter().map(item_id).collect();
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), ids.len());

    let sort_keys: Vec<_> = ledger
        .items
        .iter()
        .map(|item| (&item.kind, &item.name, &item.source, item.line))
        .collect();
    let mut sorted = sort_keys.clone();
    sorted.sort();
    assert_eq!(sort_keys, sorted);

    for pair in ledger.availability.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        assert!(
            (left.source.as_str(), left.start_line) < (right.source.as_str(), right.start_line),
            "availability spans must remain uniquely sorted"
        );
        assert!(
            left.source != right.source || left.end_line < right.start_line,
            "availability spans must not overlap in {}",
            left.source
        );
    }

    for item in &ledger.items {
        let id = item_id(item);
        let classification = classification(&ledger, item);
        assert!(!item.name.is_empty(), "{id} has no name");
        assert!(!item.source.is_empty(), "{id} has no source");
        assert!(item.line > 0, "{id} has no source line");
        assert!(!item.detail.is_empty(), "{id} has no extracted detail");
        assert!(
            !classification.rationale.is_empty(),
            "{id} has no rationale"
        );
        assert!(
            ledger.evidence.contains_key(&classification.evidence),
            "{id} references unknown evidence {}",
            classification.evidence
        );
        assert!(!item.classification.is_empty());
        assert!(
            conditions_for(&ledger, item)
                .iter()
                .all(|condition| condition.starts_with('#'))
        );
        assert!(
            [
                "exact",
                "source-compatible",
                "behavior-compatible",
                "compatibility-profile-only",
                "provider-limited",
                "intentionally-unsupported",
                "binary-abi-incompatible",
                "planned",
            ]
            .contains(&classification.outcome.as_str()),
            "{id} has undocumented outcome {}",
            classification.outcome
        );
    }
    validate_evidence(&ledger).expect("all evidence must be referenced and executable");
}

#[test]
fn orphaned_or_stale_evidence_is_rejected() {
    // Evidence must remain both reachable from an item and executable by this suite.
    let mut orphaned = ledger();
    orphaned.evidence.insert(
        "orphaned".into(),
        Evidence {
            test: "capability_ledger::complete_surface_categories_are_stable".into(),
            description: "unused evidence".into(),
        },
    );
    assert!(
        validate_evidence(&orphaned)
            .expect_err("orphaned evidence must fail")
            .contains("not referenced")
    );

    let mut stale = ledger();
    stale
        .evidence
        .values_mut()
        .next()
        .expect("ledger must contain evidence")
        .test = "capability_ledger::renamed_or_deleted_test".into();
    assert!(
        validate_evidence(&stale)
            .expect_err("stale test reference must fail")
            .contains("does not exist")
    );
}

#[test]
fn c_surface_is_explicitly_incompatible() {
    // A native Rust API must not be reported as drop-in C ABI compatibility.
    let ledger = ledger();
    let c_kinds = [
        "header",
        "export-function",
        "export-variable",
        "macro",
        "build-define",
        "enum",
        "struct-layout",
        "callback",
        "typedef",
        "class-id",
    ];
    for item in ledger
        .items
        .iter()
        .filter(|item| c_kinds.contains(&item.kind.as_str()))
    {
        assert_eq!(
            classification(&ledger, item).outcome,
            "binary-abi-incompatible",
            "{}",
            item_id(item)
        );
    }
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
#[test]
fn native_algorithm_claims_match_the_rust_api() {
    // Every positive claim must pass through the corresponding production parser or type.
    let ledger = ledger();
    let claims: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| {
            item.kind == "algorithm-uri"
                && matches!(
                    classification(&ledger, item).outcome.as_str(),
                    "behavior-compatible" | "compatibility-profile-only"
                )
        })
        .collect();
    assert_eq!(claims.len(), 51);
    for item in claims {
        assert_native_uri_support(item);
    }
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
fn assert_native_uri_support(item: &Item) {
    use xml_sec::c14n::C14nAlgorithm;
    use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
    };

    let uri = item.detail.as_str();
    match item.name.as_str() {
        "xmlSecHrefAes128Cbc"
        | "xmlSecHrefAes128Gcm"
        | "xmlSecHrefAes256Cbc"
        | "xmlSecHrefAes256Gcm" => {
            assert_eq!(DataEncryptionAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefC14N"
        | "xmlSecHrefC14N11"
        | "xmlSecHrefC14N11WithComments"
        | "xmlSecHrefC14NWithComments"
        | "xmlSecHrefExcC14N"
        | "xmlSecHrefExcC14NWithComments" => {
            assert!(C14nAlgorithm::from_uri(uri).is_some(), "{}", item_id(item));
        }
        "xmlSecHrefDsaSha1"
        | "xmlSecHrefDsaSha256"
        | "xmlSecHrefEcdsaSha1"
        | "xmlSecHrefEcdsaSha224"
        | "xmlSecHrefEcdsaSha256"
        | "xmlSecHrefEcdsaSha384"
        | "xmlSecHrefEcdsaSha512"
        | "xmlSecHrefHmacSha1"
        | "xmlSecHrefHmacSha224"
        | "xmlSecHrefHmacSha256"
        | "xmlSecHrefHmacSha384"
        | "xmlSecHrefHmacSha512"
        | "xmlSecHrefRsaSha1"
        | "xmlSecHrefRsaSha224"
        | "xmlSecHrefRsaSha256"
        | "xmlSecHrefRsaSha384"
        | "xmlSecHrefRsaSha512" => {
            assert_eq!(SignatureAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefSha1" | "xmlSecHrefSha224" | "xmlSecHrefSha256" | "xmlSecHrefSha384"
        | "xmlSecHrefSha512" => {
            assert_eq!(DigestAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefKWAes128" | "xmlSecHrefKWAes256" => {
            assert_eq!(KeyWrapAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefRsaOaep" | "xmlSecHrefRsaOaepEnc11" => {
            assert_eq!(KeyTransportAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefMgf1Sha1"
        | "xmlSecHrefMgf1Sha256"
        | "xmlSecHrefMgf1Sha384"
        | "xmlSecHrefMgf1Sha512" => {
            let implemented = [
                OaepDigestAlgorithm::Sha1,
                OaepDigestAlgorithm::Sha256,
                OaepDigestAlgorithm::Sha384,
                OaepDigestAlgorithm::Sha512,
            ];
            assert!(
                implemented
                    .into_iter()
                    .any(|algorithm| algorithm.mgf_uri() == uri)
            );
        }
        "xmlSecHrefBase64" | "xmlSecHrefEnveloped" | "xmlSecXPath2Ns" | "xmlSecXPathNs" => {
            assert_transform_uri_parses(uri)
        }
        "xmlSecHrefDEREncodedKeyValue"
        | "xmlSecHrefDSAKeyValue"
        | "xmlSecHrefECKeyValue"
        | "xmlSecHrefRSAKeyValue"
        | "xmlSecHrefRawX509Cert"
        | "xmlSecHrefX509Data" => assert_key_info_uri_parses(item.name.as_str(), uri),
        "xmlSecHrefEncryptedKey" => assert_encrypted_key_uri_parses(uri),
        name => panic!("positive ledger claim {name} has no executable Rust evidence"),
    }
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
fn assert_transform_uri_parses(uri: &str) {
    let parameter = match uri {
        "http://www.w3.org/TR/1999/REC-xpath-19991116" => {
            "<XPath xmlns=\"http://www.w3.org/2000/09/xmldsig#\">true()</XPath>"
        }
        "http://www.w3.org/2002/06/xmldsig-filter2" => {
            "<XPath xmlns=\"http://www.w3.org/2002/06/xmldsig-filter2\" Filter=\"intersect\">true()</XPath>"
        }
        _ => "",
    };
    let xml = format!(
        "<Transforms xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Transform Algorithm=\"{uri}\">{parameter}</Transform></Transforms>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(
        xml_sec::xmldsig::transforms::parse_transforms(document.root_element())
            .unwrap()
            .len(),
        1
    );
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
fn assert_key_info_uri_parses(name: &str, uri: &str) {
    const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    const DS11: &str = "http://www.w3.org/2009/xmldsig11#";
    let child = match name {
        "xmlSecHrefDEREncodedKeyValue" => {
            assert_eq!(uri, format!("{DS11}DEREncodedKeyValue"));
            "<dsig11:DEREncodedKeyValue>AQIDBA==</dsig11:DEREncodedKeyValue>"
        }
        "xmlSecHrefDSAKeyValue" => {
            assert_eq!(uri, format!("{DS}DSAKeyValue"));
            "<KeyValue><DSAKeyValue><Y>AQ==</Y></DSAKeyValue></KeyValue>"
        }
        "xmlSecHrefECKeyValue" => {
            assert_eq!(uri, format!("{DS11}ECKeyValue"));
            "<KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey></dsig11:ECKeyValue></KeyValue>"
        }
        "xmlSecHrefRSAKeyValue" => {
            assert_eq!(uri, format!("{DS}RSAKeyValue"));
            "<KeyValue><RSAKeyValue><Modulus>AQAB</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>"
        }
        "xmlSecHrefRawX509Cert" => {
            assert_eq!(uri, format!("{DS}rawX509Certificate"));
            return assert_retrieval_method_type_parses(uri);
        }
        "xmlSecHrefX509Data" => {
            assert_eq!(uri, format!("{DS}X509Data"));
            "<X509Data/>"
        }
        _ => unreachable!(),
    };
    let xml = format!("<KeyInfo xmlns=\"{DS}\" xmlns:dsig11=\"{DS11}\">{child}</KeyInfo>");
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(
        xml_sec::xmldsig::parse_key_info(document.root_element())
            .unwrap()
            .sources
            .len(),
        1
    );
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
fn assert_retrieval_method_type_parses(uri: &str) {
    let xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RetrievalMethod URI=\"#key\" Type=\"{uri}\"/></KeyInfo>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    xml_sec::xmldsig::parse_key_info(document.root_element()).unwrap();
}

#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
fn assert_encrypted_key_uri_parses(uri: &str) {
    assert_eq!(uri, "http://www.w3.org/2001/04/xmlenc#EncryptedKey");
    let xml = r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><CipherData><CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</CipherValue></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</CipherValue></CipherData></EncryptedData>"#;
    assert_eq!(
        xml_sec::xmlenc::parse_encrypted_data(xml)
            .unwrap()
            .encrypted_keys
            .len(),
        1
    );
}

#[cfg(feature = "xmldsig")]
#[test]
fn legacy_algorithm_claims_are_policy_gated() {
    // Only algorithms independently gated by compiled policy belong here.
    let ledger = ledger();
    let actual: BTreeSet<_> = ledger
        .items
        .iter()
        .filter(|item| classification(&ledger, item).outcome == "compatibility-profile-only")
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([
            "xmlSecHrefDsaSha1",
            "xmlSecHrefEcdsaSha1",
            "xmlSecHrefHmacSha1",
            "xmlSecHrefRsaSha1",
        ])
    );

    let sha1 = ledger
        .items
        .iter()
        .find(|item| item.name == "xmlSecHrefSha1")
        .expect("SHA-1 digest URI must remain inventoried");
    let sha1_classification = classification(&ledger, sha1);
    assert_eq!(sha1_classification.outcome, "behavior-compatible");
    assert!(
        sha1_classification
            .rationale
            .contains("secure signing defaults")
    );
    assert!(
        xml_sec::policy::VerificationPolicy::default()
            .digest_algorithms
            .is_none()
    );
    assert!(!xml_sec::xmldsig::DigestAlgorithm::Sha1.signing_allowed());

    let fixture = std::fs::read_to_string(
        "tests/fixtures/xmldsig/xmldsig11-interop-2012/signature-enveloping-p256_sha1.xml",
    )
    .expect("SHA-1 interoperability fixture must be readable");
    let mut verification_policy = xml_sec::policy::VerificationPolicy::default();
    verification_policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(xml_sec::xmldsig::SignatureAlgorithm::EcdsaSha1);
    let resolver = xml_sec::xmldsig::DefaultKeyResolver::default();
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&resolver)
        .policy(verification_policy)
        .verify(&fixture)
        .expect("explicit compatibility policy must execute SHA-1 verification");
    assert_eq!(result.status, xml_sec::xmldsig::DsigStatus::Valid);

    let builder = xml_sec::xmldsig::SignatureBuilder::new(
        xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
        xml_sec::xmldsig::SignatureAlgorithm::RsaSha1,
    )
    .add_reference(
        xml_sec::xmldsig::ReferenceBuilder::new(xml_sec::xmldsig::DigestAlgorithm::Sha1).uri(""),
    );
    assert!(builder.build_template().is_err());
    let signing_policy = xml_sec::policy::SigningPolicy {
        signature_algorithms: Some(std::collections::HashSet::from([
            xml_sec::xmldsig::SignatureAlgorithm::RsaSha1,
        ])),
        digest_algorithms: Some(std::collections::HashSet::from([
            xml_sec::xmldsig::DigestAlgorithm::Sha1,
        ])),
        ..xml_sec::policy::SigningPolicy::default()
    };
    builder
        .build_template_with_policy(&signing_policy)
        .expect("explicit compatibility policy must enable SHA-1 template construction");
}

#[cfg(feature = "xmldsig")]
#[test]
fn xpath_claims_record_libxmlsec_here_compatibility() {
    // URI support is native, but the donor's non-standard here() binding is explicit opt-in.
    let ledger = ledger();
    for name in ["xmlSecXPathNs", "xmlSecXPath2Ns"] {
        let item = ledger
            .items
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("{name} must remain inventoried"));
        let classification = classification(&ledger, item);
        assert_eq!(item.classification, "native-xpath-uri");
        assert_eq!(classification.outcome, "behavior-compatible");
        assert!(classification.rationale.contains("XmlSecLegacy"));
    }
    assert_eq!(
        xml_sec::xmldsig::XPathHereSemantics::default(),
        xml_sec::xmldsig::XPathHereSemantics::Specification
    );
}

#[test]
fn backend_surface_distinguishes_provider_capabilities_from_unimplemented_apis() {
    // Donor backend symbols are supported only when the native provider has that capability.
    let ledger = ledger();
    let provider_limited: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| {
            item.kind == "backend-api"
                && classification(&ledger, item).outcome == "provider-limited"
        })
        .collect();
    assert!(!provider_limited.is_empty());
    assert!(
        provider_limited
            .iter()
            .all(|item| item.name.contains("Transform"))
    );

    for unsupported in ["Des3", "Gost"] {
        assert!(ledger.items.iter().any(|item| {
            item.kind == "backend-api"
                && item.name.contains(unsupported)
                && classification(&ledger, item).outcome == "planned"
        }));
    }
}

#[test]
fn donor_declarations_are_extracted_without_truncation() {
    // Representative aliases, enums, macros, and defines guard each lexical extractor.
    let ledger = ledger();
    for alias in ["xmlSecSize", "xmlSecByte", "xmlSecKey", "xmlSecKeyPtr"] {
        assert!(
            ledger
                .items
                .iter()
                .any(|item| item.kind == "typedef" && item.name == alias)
        );
    }
    for enum_name in ["xmlSecDSigReferenceOrigin", "xmlEncCtxMode"] {
        assert!(
            ledger
                .items
                .iter()
                .any(|item| item.kind == "enum" && item.name == enum_name)
        );
    }
    let assertion = ledger
        .items
        .iter()
        .find(|item| item.kind == "macro" && item.name == "xmlSecAssert")
        .expect("xmlSecAssert macro must be inventoried");
    assert!(assertion.detail.contains("xmlSecError"));
    assert!(
        !ledger
            .items
            .iter()
            .any(|item| item.kind == "build-define" && item.name == "XMLSEC_CRYPTO_CFLAGS")
    );

    for define in [
        "XMLSEC_CUSTOM_CRYPT32",
        "XMLSEC_DL_LIBLTDL",
        "XMLSEC_OPENSSL3_ENGINES",
        "XMLSEC_STATIC",
    ] {
        assert!(
            ledger
                .items
                .iter()
                .any(|item| { item.kind == "build-define" && item.name == define }),
            "missing compiler define {define}"
        );
    }
    for option in ["--output", "--privkey-pem", "--pubkey-pem"] {
        let item = ledger
            .items
            .iter()
            .find(|item| item.kind == "cli-option" && item.name == option)
            .unwrap_or_else(|| panic!("missing CLI option {option}"));
        assert!(item.detail.contains("xmlSecAppCmdLineParamType"));
        assert!(item.detail.contains("xmlSecAppCmdLineParamFlag"));
    }

    let guarded_x509 = ledger
        .items
        .iter()
        .find(|item| item.name == "xmlSecGCryptAppKeyCertLoad")
        .expect("guarded X.509 API must be inventoried");
    assert!(
        conditions_for(&ledger, guarded_x509)
            .iter()
            .any(|condition| condition == "#ifndef XMLSEC_NO_X509")
    );
}

#[test]
fn conditional_macro_variants_and_class_ids_are_complete() {
    // Conditional definitions and multiline class aliases must all remain drift-visible.
    let ledger = ledger();
    let export_variants: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "macro" && item.name == "XMLSEC_EXPORT")
        .collect();
    assert_eq!(export_variants.len(), 5);
    assert!(
        export_variants
            .iter()
            .any(|item| item.detail.contains("dllexport"))
    );
    assert!(
        export_variants
            .iter()
            .any(|item| item.detail.contains("dllimport"))
    );

    for macro_item in ledger.items.iter().filter(|item| {
        item.kind == "macro"
            && item.name.ends_with("Id")
            && !item.detail.contains(&format!("{}(", item.name))
    }) {
        assert!(
            ledger.items.iter().any(|item| {
                item.kind == "class-id"
                    && item.name == macro_item.name
                    && item.source == macro_item.source
                    && item.line == macro_item.line
            }),
            "{}",
            item_id(macro_item)
        );
    }
}

#[test]
fn registry_inventory_covers_complete_id_families() {
    // Lookup and lifecycle functions are registry surface just like registration functions.
    let ledger = ledger();
    for name in [
        "xmlSecKeyDataIdsGet",
        "xmlSecKeyDataIdsGetEnabled",
        "xmlSecKeyDataIdsInit",
        "xmlSecKeyDataIdsShutdown",
        "xmlSecKeyDataIdsRegisterDefault",
        "xmlSecKeyDataIdsRegister",
        "xmlSecKeyDataIdsRegisterDisabled",
        "xmlSecTransformIdsGet",
        "xmlSecTransformIdsInit",
        "xmlSecTransformIdsShutdown",
        "xmlSecTransformIdsRegisterDefault",
        "xmlSecTransformIdsRegister",
    ] {
        assert!(
            ledger
                .items
                .iter()
                .any(|item| item.kind == "registry" && item.name == name),
            "{name}"
        );
    }
}

#[test]
fn configured_header_contains_installed_version_values() {
    // The ledger represents configured version.h values rather than Autoconf placeholders.
    let ledger = ledger();
    let macros: BTreeMap<_, _> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "macro" && item.source == "include/xmlsec/version.h.in")
        .map(|item| (item.name.as_str(), item.detail.as_str()))
        .collect();
    assert!(macros["XMLSEC_VERSION"].contains("\"1.3.13\""));
    assert!(macros["XMLSEC_VERSION_MAJOR"].ends_with('1'));
    assert!(macros["XMLSEC_VERSION_MINOR"].ends_with('3'));
    assert!(macros["XMLSEC_VERSION_SUBMINOR"].ends_with("13"));
    assert!(macros["XMLSEC_VERSION_INFO"].contains("\"10313:0:0\""));
    assert!(macros.values().all(|detail| !detail.contains('@')));
}

#[test]
fn planned_surface_is_never_reported_as_supported() {
    // All unimplemented parity targets must remain explicit, not silently omitted.
    let ledger = ledger();
    let planned: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| classification(&ledger, item).outcome == "planned")
        .collect();
    assert!(!planned.is_empty());
    assert!(planned.iter().any(|item| item.kind == "cli-option"));
    assert!(planned.iter().any(|item| item.kind == "algorithm-uri"));
    assert!(planned.iter().any(|item| item.kind == "test-family"));
    assert!(planned.iter().any(|item| item.kind == "registry"));
}

#[test]
fn phaos_xmldsig_family_is_exhaustively_classified() {
    // The family claim remains honest while the dedicated integration suite
    // accounts for every vector and exposes unsupported dependencies exactly.
    let ledger = ledger();
    let families: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "test-family" && item.name == "phaos-xmldsig-three")
        .collect();
    assert_eq!(
        families.len(),
        1,
        "Phaos XMLDSig family must appear exactly once in the upstream inventory"
    );
    let family = families[0];
    let classification = classification(&ledger, family);
    assert_eq!(family.classification, "phaos-xmldsig-exhaustive");
    assert_eq!(classification.outcome, "planned");
    assert_eq!(classification.evidence, "phaos-xmldsig-tests");

    let suite = include_str!("phaos_interop.rs");
    assert!(suite.contains("every_phaos_signature_is_classified_once"));
    assert!(suite.contains("executes_every_phaos_signature_through_the_public_pipeline"));
}

#[test]
fn xmldsig_second_edition_family_is_exhaustively_classified() {
    // The family inventory is backed by exact positive and unsupported
    // outcomes for every signed vector and generation template.
    let ledger = ledger();
    let families: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "test-family" && item.name == "xmldsig2ed-tests")
        .collect();
    assert_eq!(families.len(), 1);
    let family = families[0];
    let classification = classification(&ledger, family);
    assert_eq!(family.classification, "xmldsig2ed-exhaustive");
    assert_eq!(classification.outcome, "planned");
    assert_eq!(classification.evidence, "xmldsig2ed-tests");

    let suite = include_str!("donor_interop_suite.rs");
    assert!(
        suite.contains("complete_second_edition_verification_corpus_is_classified_and_executed")
    );
    assert!(suite.contains("second_edition_template_materializes_c14n11_and_signs_detached_xml"));
}

#[test]
fn native_cli_claims_match_process_and_upstream_runner_tests() {
    // Commands are complete dispatch entries; individual options remain explicit
    // when their format or policy mapping has not been implemented yet.
    let ledger = ledger();
    let runtime_commands: BTreeSet<_> = cli_args::Command::ALL
        .iter()
        .map(|command| command.canonical_name())
        .collect();
    let ledger_commands: BTreeSet<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "cli-command" && !item.name.starts_with("--"))
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(runtime_commands, ledger_commands);

    for item in ledger
        .items
        .iter()
        .filter(|item| item.kind == "cli-command" && !item.name.starts_with("--"))
    {
        assert!(
            runtime_commands.contains(item.name.as_str()),
            "missing runtime command {}",
            item.name
        );
        assert_eq!(classification(&ledger, item).outcome, "behavior-compatible");
    }
    let behavior_compatible = BTreeSet::from([
        "add-id-attr",
        "binary-data",
        "enable-asn1-signatures-hack",
        "enable-visa3d-hack",
        "help",
        "id-attr",
        "ignore-manifests",
        "insecure",
        "lax-key-search",
        "node-id",
        "output",
        "print-debug",
        "print-xml-debug",
        "verify-crls",
        "xml-data",
    ]);
    let provider_limited = BTreeSet::from([
        "X509-skip-strict-checks",
        "aes-key",
        "crypto",
        "crypto-config",
        "gen-key",
        "hmac-key",
        "pkcs8-der",
        "pkcs8-pem",
        "print-crypto-library-errors",
        "privkey-der",
        "privkey-pem",
        "pubkey-cert-der",
        "pubkey-cert-pem",
        "pubkey-der",
        "pubkey-pem",
        "trusted-der",
        "trusted-pem",
        "untrusted-der",
        "untrusted-pem",
    ]);
    let verbose = ledger
        .items
        .iter()
        .find(|item| item.kind == "cli-option" && item.name == "--verbose")
        .expect("donor ledger must inventory --verbose");
    assert_eq!(classification(&ledger, verbose).outcome, "planned");
    let runtime_options: BTreeSet<_> = cli_args::OPTION_SPECS
        .iter()
        .map(|spec| spec.canonical)
        .collect();
    // Native extensions are intentionally absent from the donor inventory.
    // Keep the list explicit so adding an option cannot silently weaken the
    // libxmlsec1 compatibility classification below.
    let native_extension_options = BTreeSet::from(["xml-backend"]);
    assert!(native_extension_options.is_subset(&runtime_options));
    assert!(native_extension_options.iter().all(|option| {
        !ledger
            .items
            .iter()
            .any(|item| item.kind == "cli-option" && item.name == format!("--{option}"))
    }));
    let runtime_supported_options: BTreeSet<_> = runtime_options
        .iter()
        .copied()
        .filter(|option| behavior_compatible.contains(option) || provider_limited.contains(option))
        .collect();
    let ledger_supported_options: BTreeSet<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "cli-option")
        .filter(|item| {
            matches!(
                classification(&ledger, item).outcome.as_str(),
                "behavior-compatible" | "provider-limited"
            )
        })
        .map(|item| item.name.trim_start_matches("--"))
        .collect();
    assert_eq!(runtime_supported_options, ledger_supported_options);

    for spec in cli_args::OPTION_SPECS {
        if native_extension_options.contains(spec.canonical) {
            continue;
        }
        let option = format!("--{}", spec.canonical);
        let item = ledger
            .items
            .iter()
            .find(|item| item.kind == "cli-option" && item.name == option)
            .unwrap_or_else(|| panic!("missing CLI option {option}"));
        let expected = if behavior_compatible.contains(spec.canonical) {
            "behavior-compatible"
        } else if provider_limited.contains(spec.canonical) {
            "provider-limited"
        } else {
            "planned"
        };
        assert_eq!(
            classification(&ledger, item).outcome,
            expected,
            "CLI option {option} has the wrong compatibility classification"
        );
    }
    let ledger_statuses: BTreeSet<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "cli-exit-status")
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(
        ledger_statuses,
        BTreeSet::from(["failure", "success", "unknown-command"])
    );

    for (status, outcome, code) in [
        ("success", "behavior-compatible", 0),
        ("failure", "behavior-compatible", 1),
        ("unknown-command", "planned", 0),
    ] {
        let item = ledger
            .items
            .iter()
            .find(|item| item.kind == "cli-exit-status" && item.name == status)
            .unwrap_or_else(|| panic!("missing CLI status {status}"));
        assert_eq!(classification(&ledger, item).outcome, outcome);
        assert_eq!(item.exit_code, Some(code), "wrong exit code for {status}");
    }
}

#[test]
fn deprecated_surface_is_explicitly_unsupported() {
    // Deprecated aliases stay visible without adding compatibility shims prematurely.
    let ledger = ledger();
    let deprecated: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "deprecated-api")
        .collect();
    assert!(!deprecated.is_empty());
    assert!(
        deprecated
            .iter()
            .all(|item| classification(&ledger, item).outcome == "intentionally-unsupported")
    );
}
use xml_sec as roxmltree;
