//! B-LT augmentation through the public entry points.
//!
//! The signatures come from `xml-sec-tools xades fixtures --levels`: xmlsec1
//! signs, OpenSSL issues the PKI, its CRLs, the OCSP response and the token.
//! `b-t.xml` and `b-lt.xml` carry the same signature, so the material the
//! B-LT fixture incorporates is exactly what the caller supplies here. Every
//! extended document is checked again by an independent verification.

#![cfg(feature = "produce")]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::Certificate;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, SignatureAlgorithm, VerificationKey,
    VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    Assessment, AugmentError, ConfiguredResponder, DataAdded, Inputs, Outcome, PathFailure,
    Requirements, StatusFailure, ValidationData, ValidationError, add_validation_data, validate,
};

const ROOT: &[u8] = include_bytes!("fixtures/levels/root.der");
const ISSUER: &[u8] = include_bytes!("fixtures/levels/issuer.der");
const OUTSIDER: &[u8] = include_bytes!("fixtures/levels/outsider.der");
const B_T: &str = include_str!("fixtures/levels/b-t.xml");
const B_LT: &str = include_str!("fixtures/levels/b-lt.xml");
/// Every status comes from a responder only local configuration authorizes,
/// and no response carries that responder's certificate.
const B_LT_UNCERTIFIED_RESPONDER: &str =
    include_str!("fixtures/levels/b-lt-uncertified-responder.xml");
/// B-LTA with an archive and its renewal over the B-LT material.
const B_LTA_RENEWED: &str = include_str!("fixtures/levels/b-lta-renewed.xml");
/// Unix time `1_800_000_000`, inside every fixture certificate and CRL window.
const AT: i64 = 500_000 * 3600;
const CRL: &str = "EncapsulatedCRLValue";
const OCSP: &str = "EncapsulatedOCSPValue";
const OCSP_TAG: &str = "xades:EncapsulatedOCSPValue";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 31)))
}

fn utc() -> LeapTable<'static> {
    LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage")
}

/// The distinct DER values of every `xades:{local}` element of `xml`.
fn encapsulated(xml: &str, local: &str) -> Vec<Vec<u8>> {
    let (open, close) = (format!("<xades:{local}>"), format!("</xades:{local}>"));
    let mut values: Vec<Vec<u8>> = Vec::new();
    for (start, _) in xml.match_indices(&open) {
        let start = start + open.len();
        let end = start + xml[start..].find(&close).expect("closed value");
        let value = STANDARD.decode(&xml[start..end]).expect("base64 value");
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

/// The CRLs and OCSP responses OpenSSL issued for the levels PKI.
struct Material {
    crls: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
}

impl Material {
    fn issued() -> Self {
        Self {
            crls: encapsulated(B_LT, CRL),
            responses: encapsulated(B_LT, OCSP),
        }
    }

    fn none() -> Self {
        Self {
            crls: Vec::new(),
            responses: Vec::new(),
        }
    }
}

/// The signer's own public key, from the first `KeyInfo` certificate, as a
/// caller would configure it directly.
fn signer_key() -> VerificationKey {
    let open = "<ds:X509Certificate>";
    let start = B_T.find(open).expect("signer certificate") + open.len();
    let end = start + B_T[start..].find('<').expect("certificate end");
    let der: String = B_T[start..end].split_whitespace().collect();
    let der = STANDARD.decode(der).expect("base64 certificate");
    let parser = Parser::der(account());
    let certificate = Certificate::read(&parser, &der, 0).expect("signer certificate");
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: certificate.tbs().public_key().as_bytes().to_vec(),
        certificate_der: None,
        name: None,
    }
}

/// The verification every operation and every independent check uses.
struct Fixture {
    resolver: DefaultKeyResolver,
    policy: VerificationPolicy,
    /// A caller-supplied key that verifies signatures without any path.
    explicit: Option<VerificationKey>,
    /// OCSP responders the caller configures, for the addition and every check.
    responders: &'static [ConfiguredResponder<'static>],
}

impl Fixture {
    fn new() -> Self {
        let mut policy = VerificationPolicy::default();
        policy.key_trust.verify_x509_chains = true;
        policy.key_trust.verification_time = Instant::new(AT, 0);
        Self {
            resolver: DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![ROOT.to_vec()],
                ..KeyResolverConfig::default()
            }),
            policy,
            explicit: None,
            responders: &[],
        }
    }

    /// [`Self::new`] with the outside responder configured for the issuer.
    fn configured() -> Self {
        Self {
            responders: &[ConfiguredResponder {
                responder: OUTSIDER,
                issuer: ISSUER,
            }],
            ..Self::new()
        }
    }

    /// Add `material` to the signature of `document` and require `requirements`.
    fn add(
        &self,
        document: &mut XmlDocument,
        material: &Material,
        requirements: Requirements,
    ) -> Result<DataAdded, AugmentError> {
        let context = VerifyContext::new().policy(self.policy.clone());
        let context = match &self.explicit {
            Some(key) => context.key(key),
            None => context.key_resolver(&self.resolver),
        };
        let request = VerificationRequest::default();
        let crls: Vec<&[u8]> = material.crls.iter().map(Vec::as_slice).collect();
        let responses: Vec<&[u8]> = material.responses.iter().map(Vec::as_slice).collect();
        let utc = utc();
        add_validation_data(
            document,
            &ValidationData {
                signature: "sig",
                assessment: &Assessment {
                    context: &context,
                    request: &request,
                    certificates: &[],
                },
                inputs: &Inputs {
                    requirements,
                    anchors: &[ROOT],
                    certificates: &[],
                    utc: &utc,
                    accuracies: &[],
                    responders: self.responders,
                    crls: &crls,
                    responses: &responses,
                },
                id_attributes: &[],
            },
            &account(),
        )
    }

    /// The level `xml` meets on its own material, checked from scratch.
    fn level(&self, xml: &str, requirements: Requirements) -> Outcome<bool> {
        let context = VerifyContext::new()
            .policy(self.policy.clone())
            .key_resolver(&self.resolver);
        let document = XmlDocument::parse(xml).expect("document parses");
        let utc = utc();
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let signature = session.evidence().signatures()[0].identity();
                let inputs = Inputs {
                    requirements,
                    anchors: &[ROOT],
                    certificates: &[],
                    utc: &utc,
                    accuracies: &[],
                    responders: self.responders,
                    crls: &[],
                    responses: &[],
                };
                Ok(validate(&session, signature, &inputs, |level| {
                    level.all_requirements_met()
                }))
            },
        )
        .expect("document verifies")
        .expect("level validation completes")
    }
}

fn parsed(xml: &str) -> XmlDocument {
    XmlDocument::parse(xml).expect("fixture parses")
}

#[test]
fn issued_crls_and_ocsp_take_b_t_to_b_lt() {
    // The fixture meets B-T and not B-LT; the caller holds the CRLs and the
    // delegated OCSP response the PKI issued for its signer and TSA paths.
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.level(B_T, Requirements::LongTerm),
        Outcome::Status(StatusFailure::NoSource)
    ));
    let mut document = parsed(B_T);
    let added = fixture.add(&mut document, &Material::issued(), Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::Published)), "{added:?}");
    let extended = document.as_xml().to_owned();
    // One general container, after the timestamp it does not alter.
    assert_eq!(extended.matches("</xades141:AnyValidationData>").count(), 1);
    assert!(
        extended.find("SignatureTimeStamp>").expect("timestamp")
            < extended.find("AnyValidationData").expect("material")
    );
    let level = fixture.level(&extended, Requirements::LongTerm);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}

#[test]
fn every_value_is_the_original_artifact() {
    // OCSP values are whole OCSPResponse envelopes, CRLs their own DER, as the
    // issuer produced them; nothing is re-encoded or reduced to its body.
    let fixture = Fixture::new();
    let material = Material::issued();
    let mut document = parsed(B_T);
    fixture
        .add(&mut document, &material, Requirements::LongTerm)
        .expect("material added");
    let extended = document.as_xml();
    let crls = encapsulated(extended, CRL);
    let responses = encapsulated(extended, OCSP);
    assert_eq!(responses, material.responses);
    for crl in &material.crls {
        assert!(crls.contains(crl), "issued CRL missing");
    }
}

#[test]
fn a_complete_document_is_left_unchanged() {
    // The B-LT fixture already incorporates everything: nothing is written and
    // the generation stays the one the caller holds.
    let fixture = Fixture::new();
    let mut document = parsed(B_LT);
    let snapshot =
        |document: &XmlDocument| document.with_view(|view| (view.identity(), view.generation()));
    let before = snapshot(&document);
    let added = fixture.add(&mut document, &Material::issued(), Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::AlreadyPresent)), "{added:?}");
    assert_eq!(document.as_xml(), B_LT);
    assert_eq!(snapshot(&document), before);
}

#[test]
fn a_second_addition_adds_nothing() {
    // After one addition the census finds every artifact in the document.
    let fixture = Fixture::new();
    let mut document = parsed(B_T);
    fixture
        .add(&mut document, &Material::issued(), Requirements::LongTerm)
        .expect("material added");
    let first = document.as_xml().to_owned();
    let again = fixture.add(&mut document, &Material::issued(), Requirements::LongTerm);
    assert!(matches!(again, Ok(DataAdded::AlreadyPresent)), "{again:?}");
    assert_eq!(document.as_xml(), first);
}

#[test]
fn only_values_without_an_eligible_copy_are_added() {
    // The signature's CertificateValues stay while its revocation values and
    // the timestamp's validation data are removed. The OCSP responder's
    // certificate serves only the signer's status, for which that container
    // is eligible, so it is not repeated. The CAs the TSA shares with the
    // signer are, because EN 319 132-1 §6.3(x) does not accept the signer's
    // ordinary values for a timestamp's material.
    let start = B_LT.find("<xades:RevocationValues>").expect("values");
    let close = "</xadesv141:TimeStampValidationData>";
    let end = B_LT.find(close).expect("validation data") + close.len();
    let stripped = format!("{}{}", &B_LT[..start], &B_LT[end..]);
    let fixture = Fixture::new();
    let mut document = parsed(&stripped);
    let material = Material::issued();
    let added = fixture.add(&mut document, &material, Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::Published)), "{added:?}");
    let extended = document.as_xml().to_owned();
    let certificates = encapsulated(&stripped, "EncapsulatedX509Certificate");
    // OpenSSL embeds the responder's certificate in its response.
    let embedded = |certificate: &Vec<u8>| {
        material.responses[0]
            .windows(certificate.len())
            .any(|window| window == certificate.as_slice())
    };
    let responder = certificates
        .iter()
        .find(|certificate| embedded(certificate))
        .expect("responder certificate");
    assert_eq!(extended.matches(&STANDARD.encode(responder)).count(), 1);
    for shared in certificates
        .iter()
        .filter(|certificate| !embedded(certificate))
    {
        assert_eq!(extended.matches(&STANDARD.encode(shared)).count(), 2);
    }
    let level = fixture.level(&extended, Requirements::LongTerm);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}

#[test]
fn without_a_status_source_nothing_is_added() {
    // A member with no status anywhere is a missing input; the document keeps
    // its generation rather than gaining an incomplete container.
    let fixture = Fixture::new();
    let mut document = parsed(B_T);
    let added = fixture.add(&mut document, &Material::none(), Requirements::LongTerm);
    assert!(
        matches!(
            added,
            Err(AugmentError::Unmet(Outcome::Status(
                StatusFailure::NoSource
            )))
        ),
        "{added:?}"
    );
    assert_eq!(document.as_xml(), B_T);
}

#[test]
fn a_signature_below_b_t_is_refused() {
    // Without its timestamp the signature is B-B: validation data alone cannot
    // make it B-LT. The level's preparation already finds the property missing,
    // so nothing is added.
    let start = B_T.find("<xades:UnsignedProperties").expect("unsigned");
    let close = "</xades:UnsignedProperties>";
    let end = B_T.find(close).expect("unsigned end") + close.len();
    let basic = format!("{}{}", &B_T[..start], &B_T[end..]);
    let fixture = Fixture::new();
    let mut document = parsed(&basic);
    let added = fixture.add(&mut document, &Material::issued(), Requirements::LongTerm);
    assert!(
        matches!(
            added,
            Err(AugmentError::Validation(ValidationError::Prepare(_)))
        ),
        "{added:?}"
    );
    assert_eq!(document.as_xml(), basic);
}

#[test]
fn a_signature_without_its_path_gains_nothing() {
    // Verified by the caller's own key, the signature has no validated path,
    // so there is no signer path whose statuses could be incorporated.
    let mut fixture = Fixture::new();
    fixture.explicit = Some(signer_key());
    let mut document = parsed(B_T);
    let added = fixture.add(&mut document, &Material::issued(), Requirements::LongTerm);
    assert!(
        matches!(
            added,
            Err(AugmentError::Unmet(Outcome::Path {
                failure: PathFailure::NotValidated,
                ..
            }))
        ),
        "{added:?}"
    );
    assert_eq!(document.as_xml(), B_T);
}

#[test]
fn a_level_below_b_lt_is_refused() {
    // Validation data is what B-LT adds; a request for less has nothing to check.
    let fixture = Fixture::new();
    let mut document = parsed(B_T);
    let added = fixture.add(
        &mut document,
        &Material::issued(),
        Requirements::Timestamped,
    );
    assert!(
        matches!(
            added,
            Err(AugmentError::BelowLongTerm(Requirements::Timestamped))
        ),
        "{added:?}"
    );
    assert_eq!(document.as_xml(), B_T);
}

#[test]
fn a_level_the_addition_cannot_reach_is_rolled_back() {
    // B-LTA needs an archive timestamp, which validation data does not add: the
    // staged generation is checked, found short and discarded.
    let fixture = Fixture::new();
    let mut document = parsed(B_T);
    let added = fixture.add(&mut document, &Material::issued(), Requirements::Archival);
    assert!(
        matches!(
            added,
            Err(AugmentError::Validation(ValidationError::Prepare(_)))
        ),
        "{added:?}"
    );
    assert_eq!(document.as_xml(), B_T);
}

#[test]
fn a_configured_responder_is_incorporated() {
    // RFC 6960 §4.2.2.2: the caller's configuration authorizes the outside
    // responder, yet EN 319 132-1 §6.3 also wants its certificate in the
    // document, and no response carries it. The configuration supplies it.
    let fixture = Fixture::configured();
    assert!(matches!(
        fixture.level(B_LT_UNCERTIFIED_RESPONDER, Requirements::LongTerm),
        Outcome::Assessed(false)
    ));
    let mut document = parsed(B_LT_UNCERTIFIED_RESPONDER);
    let added = fixture.add(&mut document, &Material::none(), Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::Published)), "{added:?}");
    let extended = document.as_xml().to_owned();
    // The signer and the TSA both need it; one general copy serves both.
    assert_eq!(extended.matches(&STANDARD.encode(OUTSIDER)).count(), 1);
    let level = fixture.level(&extended, Requirements::LongTerm);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}

#[test]
fn a_timestamp_status_held_only_by_the_signature_is_copied_whole() {
    // The TSA's OCSP response is moved into the signature's own
    // RevocationValues, which EN 319 132-1 §6.3(x) does not accept for a
    // timestamp. The caller supplies no response: the document's whole
    // OCSPResponse is copied into the general container.
    let responses = encapsulated(B_LT_UNCERTIFIED_RESPONDER, OCSP);
    let element = |der: &Vec<u8>| format!("<{OCSP_TAG}>{}</{OCSP_TAG}>", STANDARD.encode(der));
    let (signer, tsa) = (element(&responses[0]), element(&responses[1]));
    let moved = B_LT_UNCERTIFIED_RESPONDER
        .replacen(
            &format!("<xades:OCSPValues>{tsa}</xades:OCSPValues>"),
            "",
            1,
        )
        .replacen(&signer, &format!("{signer}{tsa}"), 1);
    assert_eq!(moved.matches(&tsa).count(), 1);
    assert!(moved.find(&tsa) < moved.find("TimeStampValidationData"));
    let fixture = Fixture::configured();
    let mut document = parsed(&moved);
    let added = fixture.add(&mut document, &Material::none(), Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::Published)), "{added:?}");
    let extended = document.as_xml().to_owned();
    assert_eq!(extended.matches(&tsa).count(), 2);
    let level = fixture.level(&extended, Requirements::LongTerm);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}

/// `(header length, content length)` of the DER element starting `der`.
fn header(der: &[u8]) -> (usize, usize) {
    let first = usize::from(der[1]);
    if first < 0x80 {
        return (2, first);
    }
    let count = first & 0x7f;
    let length = der[2..2 + count]
        .iter()
        .fold(0, |length, byte| length << 8 | usize::from(*byte));
    (2 + count, length)
}

/// The whole elements in `content`, in order.
fn children(mut content: &[u8]) -> Vec<&[u8]> {
    let mut elements = Vec::new();
    while !content.is_empty() {
        let (head, length) = header(content);
        elements.push(&content[..head + length]);
        content = &content[head + length..];
    }
    elements
}

/// The content of the DER element `der`.
fn content(der: &[u8]) -> &[u8] {
    let (head, length) = header(der);
    &der[head..head + length]
}

/// A DER element with this tag and content.
fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut der = vec![tag];
    // X.690 §8.1.3: the short form below 128, else the minimal long form.
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => der.push(short),
        _ => {
            let length = content.len().to_be_bytes();
            let bytes: Vec<u8> = length
                .iter()
                .skip_while(|byte| **byte == 0)
                .copied()
                .collect();
            der.push(0x80 | u8::try_from(bytes.len()).expect("a usize has at most 8 octets"));
            der.extend(bytes);
        }
    }
    der.extend(content);
    der
}

/// `token` with `response` added to its unsigned `SignedData.crls` as an
/// `id-ri-ocsp-response` choice (RFC 5940 §2.2). The field is outside every
/// signed attribute (RFC 5652 §5.1), so the token's signature still holds.
fn carrying(token: &[u8], response: &[u8]) -> Vec<u8> {
    /// `1.3.6.1.5.5.7.16.2`, id-ri-ocsp-response.
    const OCSP_RESPONSE: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x02];
    let info = children(content(token));
    let fields = children(content(content(info[1])));
    let (signer_infos, middle) = fields[1..].split_last().expect("signerInfos");
    // RFC 5652 §5.1: version 5 when another revocation format is present.
    let mut signed = element(0x02, &[5]);
    for field in middle {
        assert_ne!(
            field[0], 0xa1,
            "the fixture token carries no revocation data"
        );
        signed.extend(*field);
    }
    let choice = element(0xa1, &[OCSP_RESPONSE, response].concat());
    signed.extend(element(0xa1, &choice));
    signed.extend(*signer_infos);
    let wrapped = element(0xa0, &element(0x30, &signed));
    element(0x30, &[info[0], wrapped.as_slice()].concat())
}

#[test]
fn a_status_carried_only_by_another_token_is_copied_whole() {
    // The TSA's OCSP response travels only in the last archive token's CMS
    // revocation data. That token carries it for itself, but EN 319 132-1
    // §6.3(x) does not accept one token's material for another, so the
    // earlier tokens need a copy, which is that token's whole OCSPResponse.
    let responses = encapsulated(B_LT_UNCERTIFIED_RESPONDER, OCSP);
    let tsa_status = &responses[1];
    let open = "<xades:EncapsulatedTimeStamp>";
    let start = B_LTA_RENEWED.rfind(open).expect("last token") + open.len();
    let end = start + B_LTA_RENEWED[start..].find('<').expect("token end");
    let token = STANDARD
        .decode(&B_LTA_RENEWED[start..end])
        .expect("base64 token");
    let carried = STANDARD.encode(carrying(&token, tsa_status));
    let document_xml = format!(
        "{}{carried}{}",
        &B_LTA_RENEWED[..start],
        &B_LTA_RENEWED[end..]
    );
    let fixture = Fixture::configured();
    let mut document = parsed(&document_xml);
    let added = fixture.add(&mut document, &Material::none(), Requirements::LongTerm);
    assert!(matches!(added, Ok(DataAdded::Published)), "{added:?}");
    let extended = document.as_xml().to_owned();
    assert_eq!(
        encapsulated(&extended, OCSP)
            .iter()
            .filter(|value| *value == tsa_status)
            .count(),
        1
    );
    let level = fixture.level(&extended, Requirements::LongTerm);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}
