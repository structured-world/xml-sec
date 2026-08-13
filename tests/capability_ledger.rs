use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const LEDGER_JSON: &str = include_str!("../compatibility/libxmlsec1-1.3.13.json");
const DONOR_COMMIT: &str = include_str!("../compatibility/libxmlsec1-1.3.13-donor-commit.txt");

#[derive(Debug, Deserialize)]
struct Ledger {
    schema_version: u32,
    upstream: Upstream,
    generated_by: String,
    evidence: BTreeMap<String, Evidence>,
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
struct Item {
    id: String,
    kind: String,
    name: String,
    source: String,
    line: usize,
    detail: String,
    outcome: String,
    rationale: String,
    evidence: String,
    classification_rule: String,
}

fn ledger() -> Ledger {
    serde_json::from_str(LEDGER_JSON).expect("committed capability ledger must be valid JSON")
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
    let referenced: BTreeSet<_> = ledger
        .items
        .iter()
        .map(|item| item.evidence.as_str())
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
    assert_eq!(ledger.schema_version, 1);
    assert_eq!(ledger.upstream.project, "libxmlsec1");
    assert_eq!(ledger.upstream.version, "1.3.13");
    assert_eq!(ledger.upstream.commit, DONOR_COMMIT.trim());
    assert_eq!(
        ledger.upstream.repository,
        "https://github.com/lsh123/xmlsec"
    );
    assert_eq!(ledger.generated_by, "xml-sec-capability-ledger/1");

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
    let ids: Vec<_> = ledger.items.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(
        ids.iter().copied().collect::<BTreeSet<_>>().len(),
        ids.len()
    );

    let sort_keys: Vec<_> = ledger
        .items
        .iter()
        .map(|item| (&item.kind, &item.name, &item.source, item.line))
        .collect();
    let mut sorted = sort_keys.clone();
    sorted.sort();
    assert_eq!(sort_keys, sorted);

    for item in &ledger.items {
        assert!(!item.name.is_empty(), "{} has no name", item.id);
        assert!(!item.source.is_empty(), "{} has no source", item.id);
        assert!(item.line > 0, "{} has no source line", item.id);
        assert!(
            !item.detail.is_empty(),
            "{} has no extracted detail",
            item.id
        );
        assert!(!item.rationale.is_empty(), "{} has no rationale", item.id);
        assert!(
            ledger.evidence.contains_key(&item.evidence),
            "{} references unknown evidence {}",
            item.id,
            item.evidence
        );
        assert!(!item.classification_rule.is_empty());
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
            .contains(&item.outcome.as_str()),
            "{} has undocumented outcome {}",
            item.id,
            item.outcome
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
        assert_eq!(item.outcome, "binary-abi-incompatible", "{}", item.id);
    }
}

#[test]
fn native_algorithm_claims_match_the_rust_api() {
    // Every positive claim must pass through the corresponding production parser or type.
    let ledger = ledger();
    let claims: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| {
            matches!(
                item.outcome.as_str(),
                "behavior-compatible" | "compatibility-profile-only"
            )
        })
        .collect();
    assert_eq!(claims.len(), 41);
    for item in claims {
        assert_native_uri_support(item);
    }
}

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
            assert!(C14nAlgorithm::from_uri(uri).is_some(), "{}", item.id);
        }
        "xmlSecHrefDsaSha1"
        | "xmlSecHrefEcdsaSha256"
        | "xmlSecHrefEcdsaSha384"
        | "xmlSecHrefHmacSha1"
        | "xmlSecHrefRsaSha1"
        | "xmlSecHrefRsaSha256"
        | "xmlSecHrefRsaSha384"
        | "xmlSecHrefRsaSha512" => {
            assert_eq!(SignatureAlgorithm::from_uri(uri).unwrap().uri(), uri);
        }
        "xmlSecHrefSha1" | "xmlSecHrefSha256" | "xmlSecHrefSha384" | "xmlSecHrefSha512" => {
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

fn assert_retrieval_method_type_parses(uri: &str) {
    let xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RetrievalMethod URI=\"#key\" Type=\"{uri}\"/></KeyInfo>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    xml_sec::xmldsig::parse_key_info(document.root_element()).unwrap();
}

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

#[test]
fn legacy_algorithm_claims_are_policy_gated() {
    // Only algorithms independently gated by compiled policy belong here.
    let ledger = ledger();
    let actual: BTreeSet<_> = ledger
        .items
        .iter()
        .filter(|item| item.outcome == "compatibility-profile-only")
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([
            "xmlSecHrefDsaSha1",
            "xmlSecHrefHmacSha1",
            "xmlSecHrefRsaSha1",
            "xmlSecHrefSha1",
        ])
    );
}

#[test]
fn backend_surface_distinguishes_provider_capabilities_from_unimplemented_apis() {
    // Donor backend symbols are supported only when the native provider has that capability.
    let ledger = ledger();
    let provider_limited: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "backend-api" && item.outcome == "provider-limited")
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
                && item.outcome == "planned"
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
            macro_item.id
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
        .filter(|item| item.outcome == "planned")
        .collect();
    assert!(!planned.is_empty());
    assert!(planned.iter().any(|item| item.kind == "cli-command"));
    assert!(planned.iter().any(|item| item.kind == "cli-option"));
    assert!(planned.iter().any(|item| item.kind == "algorithm-uri"));
    assert!(planned.iter().any(|item| item.kind == "test-family"));
    assert!(planned.iter().any(|item| item.kind == "registry"));
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
            .all(|item| item.outcome == "intentionally-unsupported")
    );
}
