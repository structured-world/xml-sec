use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

// Loading `args.rs` through a directory module keeps it a non-`mod.rs` file, so
// its `mod tests;` resolves to `args/tests.rs` exactly as in the CLI crate.
#[path = "../tools/xmlsec1/src"]
#[cfg(all(feature = "xmldsig", feature = "xmlenc", feature = "c14n"))]
mod cli_src {
    pub mod args;
}
#[cfg(all(feature = "xmldsig", feature = "xmlenc", feature = "c14n"))]
use cli_src::args as cli_args;

const LEDGER_JSON: &str = include_str!("../compatibility/libxmlsec1.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: u32,
    upstream: Upstream,
    generated_by: String,
    evidence: BTreeMap<String, Evidence>,
    classifications: BTreeMap<String, Classification>,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    project: String,
    version: String,
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
    detail: String,
    #[serde(default)]
    conditions: Vec<String>,
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

fn ledger() -> Ledger {
    serde_json::from_str(LEDGER_JSON).expect("committed capability ledger must be valid JSON")
}

fn item_id(item: &Item) -> String {
    format!(
        "{}:{}:{}:{}",
        item.kind,
        item.source,
        item.name,
        item.conditions.join(" ")
    )
}

fn classification<'a>(ledger: &'a Ledger, item: &Item) -> &'a Classification {
    ledger
        .classifications
        .get(&item.classification)
        .unwrap_or_else(|| panic!("{} references unknown classification", item_id(item)))
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
    assert_eq!(ledger.schema_version, 3);
    assert_eq!(ledger.upstream.project, "libxmlsec1");
    assert_eq!(
        ledger.upstream.repository,
        "https://github.com/lsh123/xmlsec"
    );
    assert_eq!(ledger.generated_by, "xml-sec-capability-ledger/3");
    assert_eq!(ledger.classifications.len(), 27);

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
            ("algorithm-uri", 136),
            ("backend-api", 856),
            ("build-define", 50),
            ("callback", 65),
            ("class-id", 1_128),
            ("cli-command", 24),
            ("cli-exit-status", 3),
            ("cli-option", 77),
            ("deprecated-api", 15),
            ("enum", 15),
            ("export-function", 625),
            ("export-variable", 431),
            ("header", 59),
            ("internal-export", 70),
            ("key-format", 11),
            ("macro", 1_670),
            ("registry", 15),
            ("struct-layout", 25),
            ("test-family", 29),
            ("typedef", 66),
        ])
    );
}

#[test]
fn every_entry_is_unique_sorted_and_evidenced() {
    // Deterministic ordering and complete evidence keep regeneration reviewable.
    // Identity is the declaration and its branch, never a donor line number.
    let ledger = ledger();
    let sort_keys: Vec<_> = ledger
        .items
        .iter()
        .map(|item| {
            (
                &item.kind,
                &item.name,
                &item.source,
                &item.detail,
                &item.conditions,
            )
        })
        .collect();
    assert_eq!(
        sort_keys.iter().collect::<BTreeSet<_>>().len(),
        sort_keys.len()
    );
    let mut sorted = sort_keys.clone();
    sorted.sort();
    assert_eq!(sort_keys, sorted);

    for item in &ledger.items {
        let id = item_id(item);
        let classification = classification(&ledger, item);
        assert!(!item.name.is_empty(), "{id} has no name");
        assert!(!item.source.is_empty(), "{id} has no source");
        assert!(!item.detail.is_empty(), "{id} has no extracted detail");
        assert_eq!(
            item.exit_code.is_some(),
            item.kind == "cli-exit-status",
            "{id} has inconsistent exit-status metadata"
        );
        assert!(
            !classification.rationale.is_empty(),
            "{id} has no rationale"
        );
        assert!(
            ledger.evidence.contains_key(&classification.evidence),
            "{id} references unknown evidence {}",
            classification.evidence
        );
        assert_ne!(item.classification, "");
        assert!(
            item.conditions
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

/// Where libxmlsec1 keeps the headers of its crypto backends.
const BACKEND_HEADERS: [&str; 6] = ["gcrypt", "gnutls", "mscng", "mscrypto", "nss", "openssl"];

fn from_backend_header(item: &Item) -> bool {
    BACKEND_HEADERS.iter().any(|backend| {
        item.source
            .starts_with(&format!("include/xmlsec/{backend}/"))
    })
}

/// The libxmlsec1-compatible headers, as `(file name, text)`.
fn compatible_headers() -> Vec<(String, String)> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/xml-sec-xmlsec1/include/xmlsec");
    let mut headers: Vec<_> = std::fs::read_dir(&directory)
        .expect("the libxmlsec1-compatible include directory")
        .map(|entry| entry.expect("an include directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "h"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a readable header");
            let name = path
                .file_name()
                .expect("a header file name")
                .to_string_lossy()
                .into_owned();
            (name, text)
        })
        .collect();
    headers.sort();
    headers
}

/// Every identifier of the exported declarations of `text`, each read from
/// the line starting with the export marker through its terminating `;`, so
/// a name on a later line of the declaration is included.
fn exported_words(text: &str) -> BTreeSet<&str> {
    let mut words = BTreeSet::new();
    let mut inside = false;
    for line in text.lines() {
        inside = inside || line.starts_with("XMLSEC_EXPORT");
        if !inside {
            continue;
        }
        words.extend(
            line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| !word.is_empty()),
        );
        inside = !line.contains(';');
    }
    words
}

/// Whether `text` declares the exported function `name`.
fn declares(text: &str, name: &str) -> bool {
    exported_words(text).contains(name)
}

#[test]
fn a_declaration_split_across_lines_is_seen() {
    // The exclusion checks must not miss a declaration whose name follows the
    // export marker on a later line.
    let header = "XMLSEC_EXPORT int\n    xmlSecBufferReadFile(xmlSecBufferPtr buf,\n        const char* filename);\nint xmlSecOther(void);\n";
    assert!(declares(header, "xmlSecBufferReadFile"));
    assert!(declares(header, "xmlSecBufferPtr"));
    assert!(!declares(header, "xmlSecOther"));
}

#[test]
fn c_surface_is_explicitly_incompatible() {
    // No C tier is claimed, so no generic C item may be reported as source or
    // binary compatible; only the functions the library does not offer are
    // excluded outright.
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
    for item in ledger.items.iter().filter(|item| {
        c_kinds.contains(&item.kind.as_str())
            && !from_backend_header(item)
            && item.classification != "not-offered-c-surface"
    }) {
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
    assert_eq!(claims.len(), 75);
    for item in claims {
        if item.classification == "feature-gated-xslt-uri" {
            // Its parameter is a stylesheet; xslt_transform_contract_executes runs it.
            continue;
        }
        if item.classification == "feature-gated-legacy-uri" {
            // The ledger records the build requirement, not unconditional API
            // availability. Thin/default builds must reject every optional URI.
            let uri = item.detail.as_str();
            let available = xml_sec::xmldsig::SignatureAlgorithm::from_uri(uri).is_some()
                || xml_sec::xmldsig::DigestAlgorithm::from_uri(uri).is_some()
                || xml_sec::xmlenc::DataEncryptionAlgorithm::from_uri(uri).is_ok()
                || xml_sec::xmlenc::KeyTransportAlgorithm::from_uri(uri).is_ok()
                || xml_sec::xmlenc::KeyWrapAlgorithm::from_uri(uri).is_ok();
            assert_eq!(
                available,
                cfg!(feature = "legacy-algorithms"),
                "{}",
                item_id(item)
            );
            continue;
        }
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
        | "xmlSecHrefRsaSha512"
        | "xmlSecHrefRsaPssSha1"
        | "xmlSecHrefRsaPssSha224"
        | "xmlSecHrefRsaPssSha256"
        | "xmlSecHrefRsaPssSha384"
        | "xmlSecHrefRsaPssSha512"
        | "xmlSecHrefRsaPssSha3_224"
        | "xmlSecHrefRsaPssSha3_256"
        | "xmlSecHrefRsaPssSha3_384"
        | "xmlSecHrefRsaPssSha3_512" => {
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
                    .any(|algorithm| algorithm.mgf_uri() == Some(uri))
            );
        }
        "xmlSecHrefBase64" | "xmlSecHrefEnveloped" | "xmlSecXPath2Ns" | "xmlSecXPathNs" => {
            assert_transform_uri_parses(uri);
        }
        "xmlSecHrefRelationship" => {
            let xml = format!(
                "<Transforms xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Transform Algorithm=\"{uri}\"><RelationshipReference xmlns=\"http://schemas.openxmlformats.org/package/2006/digital-signature\" SourceId=\"rId1\"/></Transform><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms>"
            );
            let document = roxmltree::Document::parse(&xml).unwrap();
            let transforms = xml_sec::xmldsig::parse_transforms(document.root_element()).unwrap();
            assert!(
                matches!(&transforms[0], xml_sec::xmldsig::Transform::Relationship(selectors) if selectors == &[xml_sec::xmldsig::RelationshipSelector::SourceId("rId1".into())])
            );
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
fn opc_relationship_contract_executes() {
    // The ledger's OPC claim proves actual transform execution, not URI
    // recognition alone; full edition/signature interoperability lives in its
    // dedicated integration suite.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        NodeSet, RelationshipSelector, Transform, TransformData, execute_transforms,
    };
    assert_eq!(
        xml_sec::policy::VerificationPolicy::default()
            .transforms
            .opc_relationship_edition,
        xml_sec::policy::OpcRelationshipEdition::Ecma2021
    );
    let xml = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"RID\" Type=\"urn:t\" Target=\"a\"/></Relationships>";
    let document = xml_sec::Document::parse(xml).unwrap();
    let chain = [
        Transform::Relationship(vec![RelationshipSelector::SourceType("URN:T".into())]),
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];
    let output = execute_transforms(
        document.root_element(),
        TransformData::NodeSet(NodeSet::entire_document_with_comments(&document).unwrap()),
        &chain,
    )
    .unwrap();
    assert_eq!(output, b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"RID\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>");
}

#[cfg(feature = "xmldsig")]
#[test]
fn xslt_transform_contract_executes() {
    // The XSLT claim is the executed transform of an xslt build, refused by URI otherwise.
    let ledger = ledger();
    let item = ledger
        .items
        .iter()
        .find(|item| item.name == "xmlSecHrefXslt")
        .expect("XSLT URI must remain inventoried");
    assert_eq!(item.classification, "feature-gated-xslt-uri");
    let document = xml_sec::Document::parse(concat!(
        r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">"#,
        r#"<Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">"#,
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">"#,
        r#"<xsl:output method="text"/><xsl:template match="/">"#,
        r#"<xsl:value-of select="count(//item)"/></xsl:template></xsl:stylesheet>"#,
        r#"</Transform></Transforms>"#
    ))
    .unwrap();
    let chain = xml_sec::xmldsig::parse_transforms(document.root_element());
    #[cfg(feature = "xslt")]
    {
        let input = xml_sec::Document::parse("<root><item/><item/></root>").unwrap();
        let output = xml_sec::xmldsig::execute_transforms(
            input.root_element(),
            xml_sec::xmldsig::TransformData::NodeSet(
                xml_sec::xmldsig::NodeSet::entire_document_without_comments(&input).unwrap(),
            ),
            &chain.expect("an xslt build parses the transform"),
        )
        .unwrap();
        assert_eq!(output, b"2");
    }
    #[cfg(not(feature = "xslt"))]
    assert!(matches!(
        chain,
        Err(xml_sec::xmldsig::TransformError::UnsupportedTransform(uri))
            if uri == "http://www.w3.org/TR/1999/REC-xslt-19991116"
    ));
}

#[cfg(feature = "xmldsig")]
#[test]
fn legacy_algorithm_claims_are_policy_gated() {
    // Legacy algorithms and the OPC edition contract are independently selected
    // by compiled policy; OPC compatibility is not a cryptographic downgrade.
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
            "xmlSecHrefRelationship",
            "xmlSecHrefDsaSha1",
            "xmlSecHrefEcdsaSha1",
            "xmlSecHrefHmacSha1",
            "xmlSecHrefRsaSha1",
            "xmlSecHrefRsaPssSha1",
            "xmlSecHrefAes192Cbc",
            "xmlSecHrefAes192Gcm",
            "xmlSecHrefKWAes192",
            "xmlSecHrefDes3Cbc",
            "xmlSecHrefKWDes3",
            "xmlSecHrefRsaPkcs1",
            "xmlSecHrefMd5",
            "xmlSecHrefRipemd160",
            "xmlSecHrefRsaMd5",
            "xmlSecHrefRsaRipemd160",
            "xmlSecHrefHmacMd5",
            "xmlSecHrefHmacRipemd160",
            "xmlSecHrefEcdsaRipemd160",
            "xmlSecHrefXslt",
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
    verification_policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
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

    // Template construction exists only where signing is compiled.
    #[cfg(feature = "xmldsig-sign")]
    {
        let builder = xml_sec::xmldsig::SignatureBuilder::new(
            xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
            xml_sec::xmldsig::SignatureAlgorithm::RsaSha1,
        )
        .add_reference(
            xml_sec::xmldsig::ReferenceBuilder::new(xml_sec::xmldsig::DigestAlgorithm::Sha1)
                .uri(""),
        );
        assert!(builder.build_template().is_err());
        let signing_policy = xml_sec::policy::SigningPolicy {
            signature_algorithms: Some(std::collections::BTreeSet::from([
                xml_sec::xmldsig::SignatureAlgorithm::RsaSha1,
            ])),
            digest_algorithms: Some(std::collections::BTreeSet::from([
                xml_sec::xmldsig::DigestAlgorithm::Sha1,
            ])),
            ..xml_sec::policy::SigningPolicy::default()
        };
        builder
            .build_template_with_policy(&signing_policy)
            .expect("explicit compatibility policy must enable SHA-1 template construction");
    }
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

    // A backend transform getter is provider-limited exactly when the
    // algorithm URI of the same name is claimed for the native API, so the
    // two classifications cannot drift apart.
    let claimed: BTreeSet<&str> = ledger
        .items
        .iter()
        .filter(|item| {
            item.kind == "algorithm-uri"
                && matches!(
                    classification(&ledger, item).outcome.as_str(),
                    "behavior-compatible" | "compatibility-profile-only"
                )
        })
        .map(|item| item.name.as_str())
        .collect();
    let algorithm = |name: &str| -> Option<String> {
        let rest = name.strip_prefix("xmlSec")?.strip_suffix("GetKlass")?;
        ["GCrypt", "GnuTLS", "MSCng", "MSCrypto", "Nss", "OpenSSL"]
            .iter()
            .find_map(|backend| rest.strip_prefix(backend)?.strip_prefix("Transform"))
            .filter(|algorithm| !algorithm.is_empty())
            .map(str::to_owned)
    };
    let mut getters = 0;
    for item in ledger
        .items
        .iter()
        .filter(|item| item.kind == "backend-api")
    {
        let Some(algorithm) = algorithm(&item.name) else {
            continue;
        };
        getters += 1;
        let href = format!("xmlSecHref{algorithm}");
        let expected = if claimed.contains(href.as_str()) {
            "provider-limited"
        } else {
            "intentionally-unsupported"
        };
        assert_eq!(
            classification(&ledger, item).outcome,
            expected,
            "{} ({href})",
            item.name
        );
    }
    assert!(getters > provider_limited.len());

    assert!(ledger.items.iter().any(|item| {
        item.kind == "backend-api"
            && item.name.contains("Gost")
            && classification(&ledger, item).outcome == "intentionally-unsupported"
    }));
}

#[test]
fn backend_source_tier_is_not_claimed() {
    // The backend-specific source tier is decided as not claimed: no backend
    // header ships, so a backend call fails to compile rather than reaching an
    // alias, and the ledger states that for every item of a backend header
    // instead of leaving it a planned target.
    let ledger = ledger();
    let include = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/xml-sec-xmlsec1/include/xmlsec");
    for backend in BACKEND_HEADERS {
        assert!(
            !include.join(backend).exists(),
            "the {backend} backend header directory must not ship"
        );
    }
    let backend_items: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| from_backend_header(item))
        .collect();
    assert_eq!(backend_items.len(), 3_104);
    for item in &backend_items {
        let expected = if item.classification == "backend-provider-transform-surface" {
            "provider-limited"
        } else {
            assert_eq!(
                item.classification,
                "backend-specific-surface",
                "{}",
                item_id(item)
            );
            "intentionally-unsupported"
        };
        assert_eq!(
            classification(&ledger, item).outcome,
            expected,
            "{}",
            item_id(item)
        );
    }
    // A backend function never reaches the library's headers under its name.
    let headers = compatible_headers();
    let declared: BTreeSet<_> = headers
        .iter()
        .flat_map(|(_, text)| exported_words(text))
        .collect();
    for item in backend_items
        .iter()
        .filter(|item| item.kind == "backend-api")
    {
        assert!(
            !declared.contains(item.name.as_str()),
            "{} is declared by a libxmlsec1-compatible header",
            item.name
        );
    }
}

#[test]
fn c_layer_exclusions_are_explicit() {
    // Functions the library does not offer are replaced by a note in its
    // headers, so a program using one fails to compile under its name; the
    // internal exports of libxmlsec1's crypto libraries are declared nowhere.
    let ledger = ledger();
    let headers = compatible_headers();
    let not_offered: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.classification == "not-offered-c-surface")
        .collect();
    assert_eq!(not_offered.len(), 8);
    for item in not_offered {
        assert_eq!(
            classification(&ledger, item).outcome,
            "intentionally-unsupported"
        );
        let header = item
            .source
            .strip_prefix("include/xmlsec/")
            .expect("a generic libxmlsec1 header");
        let (_, text) = headers
            .iter()
            .find(|(name, _)| name == header)
            .unwrap_or_else(|| panic!("{header} is shipped"));
        assert!(!declares(text, &item.name), "{} is declared", item.name);
        assert!(
            text.contains(&format!("/* {} is not offered: ", item.name)),
            "{header} has no note for {}",
            item.name
        );
    }
    let internal: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "internal-export")
        .collect();
    assert_eq!(internal.len(), 70);
    let declared: BTreeSet<_> = headers
        .iter()
        .flat_map(|(_, text)| exported_words(text))
        .collect();
    for item in internal {
        assert_eq!(item.classification, "internal-crypto-export");
        assert_eq!(
            classification(&ledger, item).outcome,
            "intentionally-unsupported"
        );
        assert!(
            !declared.contains(item.name.as_str()),
            "internal export {} is declared",
            item.name
        );
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
    for enum_name in ["xmlSecDSigReferenceOrigin", "xmlSecEncCtxMode"] {
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
        "XMLSEC_CRYPTO_DYNAMIC_LOADING",
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
        guarded_x509
            .conditions
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
    assert_eq!(export_variants.len(), 6);
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
                    && item.conditions == macro_item.conditions
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
    // The ledger represents configured version.h values rather than Autoconf
    // placeholders, and they are the version the ledger was generated from.
    let ledger = ledger();
    let macros: BTreeMap<_, _> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "macro" && item.source == "include/xmlsec/version.h.in")
        .map(|item| (item.name.as_str(), item.detail.as_str()))
        .collect();
    let version = ledger.upstream.version.as_str();
    let parts: Vec<u32> = version
        .split('.')
        .map(|part| part.parse().expect("numeric version part"))
        .collect();
    let [major, minor, subminor] = parts[..] else {
        panic!("three-part version {version}");
    };
    assert!(macros["XMLSEC_VERSION"].ends_with(&format!(" \"{version}\"")));
    assert!(macros["XMLSEC_VERSION_MAJOR"].ends_with(&format!(" {major}")));
    assert!(macros["XMLSEC_VERSION_MINOR"].ends_with(&format!(" {minor}")));
    assert!(macros["XMLSEC_VERSION_SUBMINOR"].ends_with(&format!(" {subminor}")));
    let info = major * 10_000 + minor * 100 + subminor;
    assert!(macros["XMLSEC_VERSION_INFO"].ends_with(&format!(" \"{info}:0:0\"")));
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
    assert!(suite.contains(
        "second_edition_template_materializes_its_canonicalization_and_signs_detached_xml"
    ));
}

/// Every runtime command is a complete, behavior-compatible donor entry.
#[cfg(all(feature = "xmldsig", feature = "xmlenc", feature = "c14n"))]
fn assert_cli_commands_match(ledger: &Ledger) {
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
        assert_eq!(classification(ledger, item).outcome, "behavior-compatible");
    }
}

/// Donor exit statuses keep their classification and numeric code.
#[cfg(all(feature = "xmldsig", feature = "xmlenc", feature = "c14n"))]
fn assert_cli_exit_statuses_match(ledger: &Ledger) {
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
        ("unknown-command", "planned", 1),
    ] {
        let item = ledger
            .items
            .iter()
            .find(|item| item.kind == "cli-exit-status" && item.name == status)
            .unwrap_or_else(|| panic!("missing CLI status {status}"));
        assert_eq!(classification(ledger, item).outcome, outcome);
        assert_eq!(item.exit_code, Some(code), "wrong exit code for {status}");
    }
}

#[test]
#[cfg(all(feature = "xmldsig", feature = "xmlenc", feature = "c14n"))]
fn native_cli_claims_match_process_and_upstream_runner_tests() {
    // Commands are complete dispatch entries; individual options remain explicit
    // when their format or policy mapping has not been implemented yet.
    let ledger = ledger();
    assert_cli_commands_match(&ledger);
    assert_cli_exit_statuses_match(&ledger);
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
    let native_extension_options = BTreeSet::from(["xml-backend", "utc-facts"]);
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
}

#[test]
fn deprecated_surface_is_explicitly_classified() {
    // Deprecated generic functions are declared like the rest of the generic
    // surface, which claims no C tier; deprecated backend functions share the
    // backend's classification.
    let ledger = ledger();
    let headers = compatible_headers();
    let deprecated: Vec<_> = ledger
        .items
        .iter()
        .filter(|item| item.kind == "deprecated-api")
        .collect();
    assert_eq!(deprecated.len(), 15);
    for item in deprecated {
        if from_backend_header(item) {
            assert_eq!(item.classification, "backend-specific-surface");
            assert_eq!(
                classification(&ledger, item).outcome,
                "intentionally-unsupported"
            );
        } else {
            assert_eq!(item.classification, "deprecated-generic-surface");
            assert_eq!(
                classification(&ledger, item).outcome,
                "binary-abi-incompatible"
            );
            assert!(
                headers.iter().any(|(_, text)| declares(text, &item.name)),
                "{} is not declared",
                item.name
            );
        }
    }
}
#[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
use xml_sec as roxmltree;
