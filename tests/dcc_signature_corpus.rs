//! PTB Digital Calibration Certificate (DCC 3.3.0) signature corpus.
//!
//! The certificate follows the current DCC schema (namespace `https://ptb.de/dcc`)
//! and the signature form of the PTB DCC wiki (<https://wiki.dcc.ptb.de/en/dsSignature>):
//! inclusive C14N 1.0, an enveloped-signature transform over `URI=""` and RSA
//! with the SHA family, including the wiki example's RSA-SHA1 with a SHA-1
//! digest. Every case is signed by this library and by xmlsec1 and verified by
//! both. The schema gives `administrativeData` and `measurementResults` no ID,
//! so narrower references and wrapping use the IDs it does declare, on
//! `measurementResult`. No case reads a schema, DTD or other resource.
#![cfg(all(feature = "xmldsig", feature = "xmldsig-sign"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, date_time_ymd,
};
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{
    Instant, PolicyViolation, SigningPolicy, VerificationPolicy, XmlInputPolicy,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, FailureReason, KeyResolverConfig,
    ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder,
    SignatureRequirement, Transform, VerificationRequest, VerifyContext, VerifyEvidence,
    X509CertificateKeyInfoWriter,
};
use xml_sec::{NodeIdentity, XmlDocument};

const DCC: &str = "https://ptb.de/dcc";
const CERTIFICATE: &str = include_str!("fixtures/xmldsig/dcc/calibration-certificate.xml");
const ROOT_CLOSE: &str = "</dcc:digitalCalibrationCertificate>";
/// 2026-03-20T00:00:00Z: inside the signer's validity, after the revocation.
const VERIFICATION_TIME: i64 = 1_773_964_800;
const XMLSEC1_VERIFICATION_TIME: &str = "2026-03-20 00:00:00";
/// 2025-06-01T00:00:00Z: inside the expired signer's validity.
const EXPIRED_VALIDITY_TIME: i64 = 1_748_736_000;
const XMLSEC1_EXPIRED_VALIDITY_TIME: &str = "2025-06-01 00:00:00";
const RESULT_ID_ATTRIBUTE: &str = "https://ptb.de/dcc:measurementResult";

/// The signature algorithms of the corpus: the wiki example and its SHA-2 form.
#[derive(Clone, Copy, Debug)]
enum Profile {
    RsaSha1,
    RsaSha256,
}

impl Profile {
    const ALL: [Self; 2] = [Self::RsaSha1, Self::RsaSha256];

    fn signature(self) -> SignatureAlgorithm {
        match self {
            Self::RsaSha1 => SignatureAlgorithm::RsaSha1,
            Self::RsaSha256 => SignatureAlgorithm::RsaSha256,
        }
    }

    fn digest(self) -> DigestAlgorithm {
        match self {
            Self::RsaSha1 => DigestAlgorithm::Sha1,
            Self::RsaSha256 => DigestAlgorithm::Sha256,
        }
    }
}

/// What a Reference covers.
#[derive(Clone, Copy, Debug)]
enum Coverage {
    /// The PTB form: the whole certificate minus the enveloped Signature.
    Whole,
    /// One `measurementResult` by its schema ID.
    Result(&'static str),
}

/// Who produces a signature.
#[derive(Clone, Copy, Debug)]
enum Producer {
    Library,
    Xmlsec1,
}

fn producers() -> Vec<Producer> {
    if xmlsec1::is_available() {
        vec![Producer::Library, Producer::Xmlsec1]
    } else {
        eprintln!("{}", xmlsec1::skip_reason());
        vec![Producer::Library]
    }
}

struct Credential {
    key_pem: String,
    certificate_pem: String,
}

/// A laboratory PKI: one trusted root, its CRL and the signing certificates.
struct Pki {
    root_pem: String,
    root_der: Vec<u8>,
    crl_pem: String,
    crl_der: Vec<u8>,
    signer: Credential,
    expired: Credential,
    revoked: Credential,
    outsider: Credential,
}

fn key_pem(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn leaf_params(
    name: &str,
    serial: u64,
    from: (i32, u8, u8),
    to: (i32, u8, u8),
) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(SerialNumber::from(serial));
    params.not_before = date_time_ymd(from.0, from.1, from.2);
    params.not_after = date_time_ymd(to.0, to.1, to.2);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    params
}

fn pki() -> Pki {
    let mut root_params = CertificateParams::new(Vec::new()).unwrap();
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "DCC Test Calibration Root");
    root_params.serial_number = Some(SerialNumber::from(1_u64));
    root_params.not_before = date_time_ymd(2025, 1, 1);
    root_params.not_after = date_time_ymd(2031, 1, 1);
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = KeyPair::from_pem(&key_pem("tests/fixtures/keys/rsa/rsa-4096-key.pem")).unwrap();
    let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();

    let issue = |key_path: &str, params: CertificateParams| {
        let key_pem = key_pem(key_path);
        let key = KeyPair::from_pem(&key_pem).unwrap();
        let certificate = params.signed_by(&key, &root).unwrap();
        Credential {
            key_pem,
            certificate_pem: certificate.pem(),
        }
    };
    let signer = issue(
        "tests/fixtures/keys/rsa/rsa-2048-key.pem",
        leaf_params("DCC Signer", 2, (2026, 1, 1), (2027, 1, 1)),
    );
    let revoked = issue(
        "tests/fixtures/keys/ca2key.pem",
        leaf_params("DCC Revoked Signer", 3, (2026, 1, 1), (2027, 1, 1)),
    );
    let expired = issue(
        "tests/fixtures/keys/rsa/rsa-expired-key.pem",
        leaf_params("DCC Expired Signer", 4, (2025, 1, 1), (2025, 12, 31)),
    );
    let outsider_key_pem = key_pem("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let outsider_key = KeyPair::from_pem(&outsider_key_pem).unwrap();
    let outsider = leaf_params("DCC Untrusted Signer", 5, (2026, 1, 1), (2027, 1, 1))
        .self_signed(&outsider_key)
        .unwrap();

    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 3, 15),
        next_update: date_time_ymd(2026, 4, 15),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(3_u64),
            revocation_time: date_time_ymd(2026, 3, 16),
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&root)
    .unwrap();

    Pki {
        root_pem: root.pem(),
        root_der: root.der().to_vec(),
        crl_pem: crl.pem().unwrap(),
        crl_der: crl.der().to_vec(),
        signer,
        expired,
        revoked,
        outsider: Credential {
            key_pem: outsider_key_pem,
            certificate_pem: outsider.pem(),
        },
    }
}

/// Files the xmlsec1 command line reads, removed with the directory.
struct Scratch {
    directory: PathBuf,
}

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Scratch {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "xml-sec-dcc-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        Self { directory }
    }

    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn inclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Inclusive1_0, false)
}

fn reference_uri(coverage: Coverage) -> String {
    match coverage {
        Coverage::Whole => String::new(),
        Coverage::Result(id) => format!("#{id}"),
    }
}

/// The Signature template xmlsec1 fills in, in the form of the PTB wiki.
fn template(profile: Profile, coverage: Coverage) -> String {
    let transform = match coverage {
        Coverage::Whole => "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        Coverage::Result(_) => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    };
    format!(
        concat!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#,
            r#"<ds:SignatureMethod Algorithm="{method}"/><ds:Reference URI="{uri}"><ds:Transforms>"#,
            r#"<ds:Transform Algorithm="{transform}"/></ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="{digest}"/><ds:DigestValue></ds:DigestValue>"#,
            r#"</ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue>"#,
            r#"<ds:KeyInfo><ds:X509Data></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        ),
        method = profile.signature().uri(),
        uri = reference_uri(coverage),
        transform = transform,
        digest = profile.digest().uri(),
    )
}

fn append_before_root_end(xml: &str, fragment: &str) -> String {
    let end = xml.rfind(ROOT_CLOSE).expect("certificate root end tag");
    format!("{}{fragment}{}", &xml[..end], &xml[end..])
}

fn run_xmlsec1(arguments: &[&str]) -> Output {
    xmlsec1::command()
        .args(arguments)
        .output()
        .expect("xmlsec1 must start")
}

/// Sign `xml` by appending one more Signature as the root's last child, as the
/// DCC schema places it.
fn sign(
    producer: Producer,
    xml: &str,
    credential: &Credential,
    profile: Profile,
    coverage: Coverage,
) -> String {
    sign_under(
        producer,
        xml,
        credential,
        profile,
        coverage,
        XmlInputPolicy::default(),
    )
}

fn sign_under(
    producer: Producer,
    xml: &str,
    credential: &Credential,
    profile: Profile,
    coverage: Coverage,
    xml_input: XmlInputPolicy,
) -> String {
    match producer {
        Producer::Library => {
            let key = RsaSigningKey::from_pkcs8_pem(&credential.key_pem).unwrap();
            let writer =
                X509CertificateKeyInfoWriter::from_pem(&credential.certificate_pem).unwrap();
            let mut reference =
                ReferenceBuilder::new(profile.digest()).uri(reference_uri(coverage));
            reference = match coverage {
                Coverage::Whole => reference.transform(Transform::Enveloped),
                Coverage::Result(_) => reference.transform(Transform::C14n(inclusive_c14n())),
            };
            let builder = SignatureBuilder::new(inclusive_c14n(), profile.signature())
                .ns_prefix("ds")
                .add_reference(reference)
                .key_info(true);
            let policy = SigningPolicy {
                signature_algorithms: Some([profile.signature()].into_iter().collect()),
                digest_algorithms: Some([profile.digest()].into_iter().collect()),
                xml: xml_input,
                ..SigningPolicy::default()
            };
            SignContext::new(&key)
                .key_info_writer(&writer)
                .policy(policy)
                .sign_with_builder(xml, &builder)
                .unwrap_or_else(|error| panic!("{profile:?} {coverage:?} signing: {error}"))
                .output
        }
        Producer::Xmlsec1 => {
            let scratch = Scratch::new();
            let key = scratch.file("key.pem", &credential.key_pem);
            let certificate = scratch.file("cert.pem", &credential.certificate_pem);
            let input = scratch.file(
                "template.xml",
                &append_before_root_end(xml, &template(profile, coverage)),
            );
            let output = scratch.directory.join("signed.xml");
            let credentials = format!("{},{}", key.display(), certificate.display());
            // xmlsec1 signs the first Signature it finds unless told otherwise.
            let last = "(//*[local-name()='Signature'])[last()]";
            // The template carries an empty X509Data, not a KeyName that would
            // name the loaded key, so the key is selected without a name.
            let result = run_xmlsec1(&[
                "--sign",
                "--lax-key-search",
                "--privkey-pem",
                &credentials,
                "--id-attr:id",
                RESULT_ID_ATTRIBUTE,
                "--node-xpath",
                last,
                "--output",
                output.to_str().unwrap(),
                input.to_str().unwrap(),
            ]);
            assert!(
                result.status.success(),
                "xmlsec1 {profile:?} {coverage:?} signing failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            fs::read_to_string(output).unwrap()
        }
    }
}

/// How xmlsec1 should judge a signed certificate.
#[derive(Clone, Copy)]
struct Xmlsec1Request<'a> {
    pki: &'a Pki,
    with_crl: bool,
    /// One-based Signature position; xmlsec1 verifies one Signature per run.
    signature: usize,
}

fn xmlsec1_verifies(xml: &str, request: Xmlsec1Request<'_>) -> Output {
    xmlsec1_verifies_at(xml, request, XMLSEC1_VERIFICATION_TIME)
}

fn xmlsec1_verifies_at(xml: &str, request: Xmlsec1Request<'_>, time: &str) -> Output {
    let scratch = Scratch::new();
    let input = scratch.file("signed.xml", xml);
    let root = scratch.file("root.pem", &request.pki.root_pem);
    let crl = scratch.file("crl.pem", &request.pki.crl_pem);
    let node = format!("(//*[local-name()='Signature'])[{}]", request.signature);
    let mut arguments = vec![
        "--verify".to_owned(),
        "--trusted-pem".to_owned(),
        root.display().to_string(),
        "--verification-gmt-time".to_owned(),
        time.to_owned(),
        "--id-attr:id".to_owned(),
        RESULT_ID_ATTRIBUTE.to_owned(),
        "--node-xpath".to_owned(),
        node,
    ];
    if request.with_crl {
        // Authenticate the CRL against the trusted root, as this library does.
        arguments.push("--verify-crls".to_owned());
        arguments.push("--crl-pem".to_owned());
        arguments.push(crl.display().to_string());
    }
    arguments.push(input.display().to_string());
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run_xmlsec1(&arguments)
}

fn assert_xmlsec1_accepts(xml: &str, request: Xmlsec1Request<'_>, case: &str) {
    if !xmlsec1::is_available() {
        return;
    }
    let output = xmlsec1_verifies(xml, request);
    assert!(
        output.status.success(),
        "{case}: xmlsec1 must verify: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// xmlsec1 must refuse with its `Failure reason: {reason}` status line.
fn assert_xmlsec1_refuses(xml: &str, request: Xmlsec1Request<'_>, case: &str, reason: &str) {
    if !xmlsec1::is_available() {
        return;
    }
    let output = xmlsec1_verifies(xml, request);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{case}: xmlsec1 must refuse");
    assert!(
        stderr.contains(&format!("Failure reason: {reason}\n")),
        "{case}: xmlsec1 must refuse with {reason}: {stderr}"
    );
}

fn utc_facts() -> structured_pkix::temporal::LeapTable<'static> {
    // Synthetic UTC coverage of the test's validity window, supplied by the
    // request as every application supplies its own.
    structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).unwrap()
}

/// X.509 trust at the fixed verification time, with or without SHA-1.
fn policy(profile: Profile) -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.check_crls = true;
    policy.key_trust.verification_time = Some(Instant::new(VERIFICATION_TIME, 0).unwrap());
    if let Profile::RsaSha1 = profile {
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(SignatureAlgorithm::RsaSha1);
    }
    policy
}

fn resolver(pki: &Pki, with_crl: bool) -> DefaultKeyResolver {
    DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![pki.root_der.clone()],
        crls: if with_crl {
            vec![pki.crl_der.clone()]
        } else {
            Vec::new()
        },
        ..KeyResolverConfig::default()
    })
}

/// The DCC child element `local` of the certificate root, located by name.
fn ring(document: &XmlDocument, local: &str) -> NodeIdentity {
    document.with_view(|view| {
        let node = view
            .document()
            .root_element()
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == local
                    && node.tag_name().namespace() == Some(DCC)
            })
            .unwrap_or_else(|| panic!("certificate has no {local}"));
        view.identity_of(node).unwrap()
    })
}

fn result_element(document: &XmlDocument, id: &str) -> NodeIdentity {
    document
        .with_view(|view| view.node_for_id(id, &[]))
        .unwrap_or_else(|| panic!("certificate has no unique {id}"))
}

struct Verified {
    document: XmlDocument,
    evidence: VerifyEvidence,
}

fn verify(
    xml: &str,
    profile: Profile,
    pki: &Pki,
    with_crl: bool,
    expected: &dyn Fn(&XmlDocument) -> Vec<NodeIdentity>,
    signatures: SignatureRequirement,
) -> Verified {
    verify_under(xml, policy(profile), pki, with_crl, expected, signatures)
}

fn verify_under(
    xml: &str,
    policy: VerificationPolicy,
    pki: &Pki,
    with_crl: bool,
    expected: &dyn Fn(&XmlDocument) -> Vec<NodeIdentity>,
    signatures: SignatureRequirement,
) -> Verified {
    let document =
        XmlDocument::parse_with_policy(xml.to_owned(), &policy).expect("signed certificate parses");
    let resolver = resolver(pki, with_crl);
    let targets = expected(&document);
    let request = VerificationRequest {
        expected_targets: &targets,
        signatures,
        ..VerificationRequest::default()
    };
    let evidence = VerifyContext::new()
        .key_resolver(&resolver)
        .utc_facts(utc_facts())
        .policy(policy)
        .verify_request(&document, &request)
        .expect("verification produces a report");
    Verified { document, evidence }
}

fn both_rings(document: &XmlDocument) -> Vec<NodeIdentity> {
    vec![
        ring(document, "administrativeData"),
        ring(document, "measurementResults"),
    ]
}

fn no_targets(_: &XmlDocument) -> Vec<NodeIdentity> {
    Vec::new()
}

#[test]
fn corpus_certificate_is_the_ptb_layout() {
    // The base document is a DCC 3.3.0 certificate: the corpus proves nothing
    // about real certificates if it drifts from the published layout.
    let document = XmlDocument::parse(CERTIFICATE.to_owned()).unwrap();
    document.with_view(|view| {
        let root = view.document().root_element();
        assert_eq!(root.tag_name().namespace(), Some(DCC));
        assert_eq!(root.tag_name().name(), "digitalCalibrationCertificate");
        assert_eq!(root.attribute("schemaVersion"), Some("3.3.0"));
        let rings = root
            .children()
            .filter(xml_sec::Node::is_element)
            .map(|node| node.tag_name().name())
            .collect::<Vec<_>>();
        assert_eq!(rings, ["administrativeData", "measurementResults"]);
    });
}

#[test]
fn a_signed_certificate_verifies_with_both_rings_covered() {
    // The PTB form covers every ring. Each signer's output must verify in both
    // implementations, and the request's expected rings must be proven covered.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let case = format!("{producer:?} {profile:?}");
            let signed = sign(producer, CERTIFICATE, &pki.signer, profile, Coverage::Whole);
            let verified = verify(
                &signed,
                profile,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            for target in both_rings(&verified.document) {
                assert!(
                    verified
                        .evidence
                        .covers_element(&verified.document, target)
                        .unwrap(),
                    "{case}: ring not covered"
                );
            }
            assert_xmlsec1_accepts(
                &signed,
                Xmlsec1Request {
                    pki: &pki,
                    with_crl: true,
                    signature: 1,
                },
                &case,
            );
        }
    }
}

#[test]
fn the_default_policy_refuses_the_wiki_rsa_sha1_signature() {
    // RSA-SHA1 verifies only under a policy that admits it; the default policy
    // refuses the method itself, before any key or digest work.
    let pki = pki();
    for producer in producers() {
        let signed = sign(
            producer,
            CERTIFICATE,
            &pki.signer,
            Profile::RsaSha1,
            Coverage::Whole,
        );
        let document = XmlDocument::parse(signed).unwrap();
        let resolver = resolver(&pki, true);
        // The corpus trust settings without the SHA-1 permission.
        let default = VerificationPolicy {
            key_trust: policy(Profile::RsaSha256).key_trust,
            ..VerificationPolicy::default()
        };
        let evidence = VerifyContext::new()
            .key_resolver(&resolver)
            .utc_facts(utc_facts())
            .policy(default)
            .verify_all(&document)
            .unwrap();
        assert!(!evidence.accepted(&document).unwrap(), "{producer:?}");
        let [signature] = evidence.signatures() else {
            panic!("{producer:?}: one signature expected");
        };
        assert!(
            matches!(
                signature.result(),
                Err(DsigError::Policy(PolicyViolation::Algorithm { algorithm, .. }))
                    if algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            ),
            "{producer:?}: {:?}",
            signature.result()
        );
    }
}

#[test]
fn an_unsigned_certificate_reports_no_signature() {
    // An unsigned DCC is a valid certificate without evidence: verification
    // must report the missing Signature, never an empty success.
    let pki = pki();
    let error = VerifyContext::new()
        .key_resolver(&resolver(&pki, true))
        .utc_facts(utc_facts())
        .policy(policy(Profile::RsaSha256))
        .verify(CERTIFICATE)
        .unwrap_err();
    assert!(
        matches!(
            error,
            DsigError::MissingElement {
                element: "Signature"
            }
        ),
        "{error:?}"
    );
    let document = XmlDocument::parse(CERTIFICATE.to_owned()).unwrap();
    let evidence = VerifyContext::new()
        .key_resolver(&resolver(&pki, true))
        .policy(policy(Profile::RsaSha256))
        .verify_all(&document)
        .unwrap();
    assert!(evidence.signatures().is_empty());
    assert!(!evidence.accepted(&document).unwrap());
    if xmlsec1::is_available() {
        let output = xmlsec1_verifies(
            CERTIFICATE,
            Xmlsec1Request {
                pki: &pki,
                with_crl: true,
                signature: 1,
            },
        );
        assert!(
            !output.status.success(),
            "xmlsec1 must refuse an unsigned certificate"
        );
    }
}

#[test]
fn changed_measurement_results_break_the_digest() {
    // A measured value edited after signing must fail the Reference digest
    // while the signature over SignedInfo itself stays valid.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let case = format!("{producer:?} {profile:?}");
            let signed = sign(producer, CERTIFICATE, &pki.signer, profile, Coverage::Whole);
            assert_eq!(signed.matches("<si:value>273.16</si:value>").count(), 1);
            let changed =
                signed.replace("<si:value>273.16</si:value>", "<si:value>273.17</si:value>");
            let verified = verify(
                &changed,
                profile,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                !verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            let [signature] = verified.evidence.signatures() else {
                panic!("{case}: one signature expected");
            };
            let result = signature.result().as_ref().unwrap();
            assert_eq!(
                result.status,
                DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 }),
                "{case}"
            );
            assert_xmlsec1_refuses(
                &changed,
                Xmlsec1Request {
                    pki: &pki,
                    with_crl: true,
                    signature: 1,
                },
                &case,
                "REFERENCE",
            );
        }
    }
}

#[test]
fn a_signature_over_one_result_does_not_cover_the_others() {
    // A valid signature over result-1 alone proves nothing about result-2 or
    // the measurementResults ring; only the expected-target request sees it.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let case = format!("{producer:?} {profile:?}");
            let signed = sign(
                producer,
                CERTIFICATE,
                &pki.signer,
                profile,
                Coverage::Result("result-1"),
            );
            let verified = verify(
                &signed,
                profile,
                &pki,
                true,
                &no_targets,
                SignatureRequirement::All,
            );
            let document = &verified.document;
            assert!(verified.evidence.accepted(document).unwrap(), "{case}");
            let evidence = &verified.evidence;
            assert!(
                evidence
                    .covers_element(document, result_element(document, "result-1"))
                    .unwrap()
            );
            assert!(
                !evidence
                    .covers_element(document, result_element(document, "result-2"))
                    .unwrap()
            );
            assert!(
                !evidence
                    .covers_element(document, ring(document, "measurementResults"))
                    .unwrap()
            );
            assert!(
                !evidence
                    .covers_element(document, ring(document, "administrativeData"))
                    .unwrap()
            );

            let expecting_rings = verify(
                &signed,
                profile,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                !expecting_rings
                    .evidence
                    .accepted(&expecting_rings.document)
                    .unwrap(),
                "{case}: rings are not covered"
            );
            let expecting_other = verify(
                &signed,
                profile,
                &pki,
                true,
                &|document| vec![result_element(document, "result-2")],
                SignatureRequirement::All,
            );
            assert!(
                !expecting_other
                    .evidence
                    .accepted(&expecting_other.document)
                    .unwrap(),
                "{case}: result-2 is not covered"
            );
            // xmlsec1 has no notion of expected targets: it reports the
            // signature valid, which is why the request must carry them.
            assert_xmlsec1_accepts(
                &signed,
                Xmlsec1Request {
                    pki: &pki,
                    with_crl: true,
                    signature: 1,
                },
                &case,
            );
        }
    }
}

/// Move the signed result into `dcc:comment`, whose content the schema
/// admits unvalidated, and put a changed copy with the same ID in its place.
fn wrap(signed: &str, id: &str) -> String {
    let start_tag = format!("<dcc:measurementResult id=\"{id}\">");
    let start = signed.find(&start_tag).expect("signed result");
    let end = start
        + signed[start..].find("</dcc:measurementResult>").unwrap()
        + "</dcc:measurementResult>".len();
    let original = &signed[start..end];
    let forged = original.replace("<si:value>273.16</si:value>", "<si:value>300.00</si:value>");
    assert_ne!(forged, original);
    let rings_end = "</dcc:measurementResults>";
    let wrapped = format!("{}{forged}{}", &signed[..start], &signed[end..]);
    let at = wrapped.find(rings_end).unwrap() + rings_end.len();
    format!(
        "{}<dcc:comment>{original}</dcc:comment>{}",
        &wrapped[..at],
        &wrapped[at..]
    )
}

#[test]
fn a_wrapped_duplicate_id_result_is_refused() {
    // Signature wrapping: the signed result moves under dcc:comment and a forged
    // copy with the same ID takes its place. The reference must not resolve to
    // either copy, and the forged result must never be reported covered.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let case = format!("{producer:?} {profile:?}");
            let signed = sign(
                producer,
                CERTIFICATE,
                &pki.signer,
                profile,
                Coverage::Result("result-1"),
            );
            let wrapped = wrap(&signed, "result-1");
            let verified = verify(
                &wrapped,
                profile,
                &pki,
                true,
                &no_targets,
                SignatureRequirement::All,
            );
            assert!(
                !verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            let [signature] = verified.evidence.signatures() else {
                panic!("{case}: one signature expected");
            };
            assert_eq!(
                signature.result().as_ref().unwrap().status,
                DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 }),
                "{case}"
            );
            let forged = verified.document.with_view(|view| {
                let node = view
                    .document()
                    .descendants()
                    .find(|node| node.attribute("id") == Some("result-1"))
                    .unwrap();
                view.identity_of(node).unwrap()
            });
            assert!(
                !verified
                    .evidence
                    .covers_element(&verified.document, forged)
                    .unwrap()
            );
            if xmlsec1::is_available() {
                let output = xmlsec1_verifies(
                    &wrapped,
                    Xmlsec1Request {
                        pki: &pki,
                        with_crl: true,
                        signature: 1,
                    },
                );
                assert!(
                    !output.status.success(),
                    "{case}: xmlsec1 must refuse the wrapped result"
                );
            }
        }
    }
}

#[test]
fn two_signatures_of_different_coverage_verify_together() {
    // A laboratory signature over result-2 and a final signature over the whole
    // certificate. verify_all reports both; the rings are covered by the second.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let case = format!("{producer:?} {profile:?}");
            let first = sign(
                producer,
                CERTIFICATE,
                &pki.signer,
                profile,
                Coverage::Result("result-2"),
            );
            let both = sign(producer, &first, &pki.signer, profile, Coverage::Whole);
            let verified = verify(
                &both,
                profile,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::Exactly(2),
            );
            assert!(
                verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            assert_eq!(verified.evidence.signatures().len(), 2, "{case}");
            for signature in verified.evidence.signatures() {
                assert_eq!(
                    signature.result().as_ref().unwrap().status,
                    DsigStatus::Valid,
                    "{case}"
                );
            }
            for position in [1, 2] {
                assert_xmlsec1_accepts(
                    &both,
                    Xmlsec1Request {
                        pki: &pki,
                        with_crl: true,
                        signature: position,
                    },
                    &format!("{case} signature {position}"),
                );
            }
            // Requiring one signature refuses a document that carries two.
            let one = verify(
                &both,
                profile,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::Exactly(1),
            );
            assert!(!one.evidence.accepted(&one.document).unwrap(), "{case}");
        }
    }
}

/// The single Signature's outcome, which must be a refusal to trust its key.
fn assert_untrusted(xml: &str, profile: Profile, pki: &Pki, with_crl: bool, case: &str) {
    let verified = verify(
        xml,
        profile,
        pki,
        with_crl,
        &both_rings,
        SignatureRequirement::All,
    );
    assert!(
        !verified.evidence.accepted(&verified.document).unwrap(),
        "{case}"
    );
    let [signature] = verified.evidence.signatures() else {
        panic!("{case}: one signature expected");
    };
    assert!(
        matches!(signature.result(), Err(DsigError::KeyResolution(_))),
        "{case}: {:?}",
        signature.result()
    );
}

#[test]
fn signers_outside_the_trusted_path_are_refused() {
    // A self-signed outsider, an expired and a revoked laboratory certificate:
    // the signatures are mathematically valid, the signers are not trusted.
    let pki = pki();
    for producer in producers() {
        for profile in Profile::ALL {
            let cases = [
                ("outsider", &pki.outsider),
                ("expired", &pki.expired),
                ("revoked", &pki.revoked),
            ];
            for (name, credential) in cases {
                let case = format!("{producer:?} {profile:?} {name}");
                let signed = sign(producer, CERTIFICATE, credential, profile, Coverage::Whole);
                assert_untrusted(&signed, profile, &pki, true, &case);
                assert_xmlsec1_refuses(
                    &signed,
                    Xmlsec1Request {
                        pki: &pki,
                        with_crl: true,
                        signature: 1,
                    },
                    &case,
                    "KEY-NOT-FOUND",
                );
            }
            // Inside its validity period the expired certificate's path is
            // otherwise valid: the refusal above is the expiry.
            let case = format!("{producer:?} {profile:?} expired, verified in its validity");
            let expired = sign(
                producer,
                CERTIFICATE,
                &pki.expired,
                profile,
                Coverage::Whole,
            );
            let mut in_validity = policy(profile);
            in_validity.key_trust.verification_time =
                Some(Instant::new(EXPIRED_VALIDITY_TIME, 0).unwrap());
            // The CRL is issued after that time, so it is not yet usable there.
            let verified = verify_under(
                &expired,
                in_validity,
                &pki,
                false,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            if xmlsec1::is_available() {
                let output = xmlsec1_verifies_at(
                    &expired,
                    Xmlsec1Request {
                        pki: &pki,
                        with_crl: false,
                        signature: 1,
                    },
                    XMLSEC1_EXPIRED_VALIDITY_TIME,
                );
                assert!(
                    output.status.success(),
                    "{case}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            // Without the CRL the revoked certificate's path is otherwise valid:
            // the refusal above is the revocation, not another path defect.
            let case = format!("{producer:?} {profile:?} revoked without CRL");
            let revoked = sign(
                producer,
                CERTIFICATE,
                &pki.revoked,
                profile,
                Coverage::Whole,
            );
            let verified = verify(
                &revoked,
                profile,
                &pki,
                false,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            assert_xmlsec1_accepts(
                &revoked,
                Xmlsec1Request {
                    pki: &pki,
                    with_crl: false,
                    signature: 1,
                },
                &case,
            );
        }
    }
}

/// The W3C XML Signature DTD, as a document type declaration may name it. The
/// DCC never needs it, and neither implementation may fetch it.
const W3C_DOCTYPE: &str = concat!(
    r#"<!DOCTYPE dcc:digitalCalibrationCertificate PUBLIC "-//W3C//DTD XML-Signature 20010315//EN" "#,
    r#""http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.dtd">"#,
);

#[test]
fn schema_references_and_the_w3c_dtd_fetch_nothing() {
    // The certificate names its schema (which imports the PTB copy of the
    // xmldsig schema without the DTD) and, in one variant, the W3C DTD. The
    // signature verifies from the document bytes alone. A document type
    // declaration is refused unless the XML policy admits one, and even then
    // its external subset is never read. xmlsec1 runs with every HTTP request
    // routed to a closed port, so any fetch would fail it.
    let pki = pki();
    assert!(CERTIFICATE.contains("https://www.ptb.de/dcc/d-sig/xmldsig-core-schema.xsd"));
    let declaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    let with_doctype =
        CERTIFICATE.replacen(declaration, &format!("{declaration}{W3C_DOCTYPE}\n"), 1);
    assert_ne!(with_doctype, CERTIFICATE);
    let Err(refused) =
        XmlDocument::parse_with_policy(with_doctype.clone(), &policy(Profile::RsaSha256))
    else {
        panic!("the default XML policy must refuse a document type declaration");
    };
    assert!(refused.to_string().contains("DTD"), "{refused}");
    let dtd = XmlInputPolicy {
        allow_internal_dtd: true,
    };
    for producer in producers() {
        for (name, certificate, xml_input) in [
            ("schema", CERTIFICATE, XmlInputPolicy::default()),
            ("W3C DTD", with_doctype.as_str(), dtd),
        ] {
            let case = format!("{producer:?} {name}");
            let signed = sign_under(
                producer,
                certificate,
                &pki.signer,
                Profile::RsaSha256,
                Coverage::Whole,
                xml_input,
            );
            let mut verification = policy(Profile::RsaSha256);
            verification.xml = xml_input;
            let verified = verify_under(
                &signed,
                verification,
                &pki,
                true,
                &both_rings,
                SignatureRequirement::All,
            );
            assert!(
                verified.evidence.accepted(&verified.document).unwrap(),
                "{case}"
            );
            if xmlsec1::is_available() {
                let scratch = Scratch::new();
                let input = scratch.file("signed.xml", &signed);
                let root = scratch.file("root.pem", &pki.root_pem);
                let output = xmlsec1::command()
                    .env("http_proxy", "http://127.0.0.1:9")
                    .env("HTTP_PROXY", "http://127.0.0.1:9")
                    .env("https_proxy", "http://127.0.0.1:9")
                    .env("HTTPS_PROXY", "http://127.0.0.1:9")
                    .env_remove("no_proxy")
                    .env_remove("NO_PROXY")
                    .args([
                        "--verify",
                        "--trusted-pem",
                        root.to_str().unwrap(),
                        "--verification-gmt-time",
                        XMLSEC1_VERIFICATION_TIME,
                        input.to_str().unwrap(),
                    ])
                    .output()
                    .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(output.status.success(), "{case}: {stderr}");
                assert!(!stderr.contains("failed to load"), "{case}: {stderr}");
            }
        }
    }
}
