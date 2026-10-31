//! Executable qualification of the alloc-only WASM product paths.
//! This separate consumer excludes native-only development dependencies.

use std::sync::Arc;

use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::provider::SignatureAnswer;
use structured_cms::timestamp::{CheckContext, ImprintAgreement, Token, TokenSignature};
use structured_pkix::Certificate;
use structured_pkix::path::WorkingKey;
use structured_pkix::temporal::{Instant, LeapTable};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
use xml_sec::policy::{CertificateSignatureAlgorithms, VerificationPolicy};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::cms::CmsProvider;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigStatus, FailureReason, KeyResolverConfig, VerificationRequest,
    VerifyContext, verify_signature_with_pem_key, with_verified_request,
};
use xml_sec_xades::{Inputs, Outcome, Requirements, validate};

/// A donor SAML 2.0 response signed by its identity provider.
const SIGNED_RESPONSE: &str = include_str!("../../fixtures/saml/response_signed_by_idp_ecdsa.xml");
const SIGNER_KEY: &str = include_str!("../../fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");
/// An RFC 3161 token from an independent authority, with its certificate.
const TOKEN: &[u8] = include_bytes!("../../fixtures/cms/timestamp/ed25519.tst");
const TOKEN_CERTIFICATE: &[u8] = include_bytes!("../../fixtures/cms/timestamp/ed25519.der");
const TOKEN_PAYLOAD: &[u8] = include_bytes!("../../fixtures/cms/timestamp/payload.txt");
/// A B-LTA signature whose tokens and status OpenSSL produced.
const LEVELS_ARCHIVAL: &str =
    include_str!("../../../crates/xml-sec-xades/tests/fixtures/levels/b-lta.xml");
const LEVELS_ROOT: &[u8] =
    include_bytes!("../../../crates/xml-sec-xades/tests/fixtures/levels/root.der");

/// Called in the compiled WASM module, not a native substitute.
#[unsafe(no_mangle)]
pub extern "C" fn xml_sec_wasm_smoke() -> u32 {
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    match canonicalize_xml(b"<root b=\"2\" a=\"1\"><empty/></root>", &algorithm) {
        Ok(bytes) if bytes == b"<root a=\"1\" b=\"2\"><empty></empty></root>" => 1,
        _ => 0,
    }
}

/// Full `XMLDSig` verification in the compiled WASM module: the signed
/// response verifies, and the same response with altered signed content is
/// rejected at its reference digest.
#[unsafe(no_mangle)]
pub extern "C" fn xml_sec_wasm_verify() -> u32 {
    let valid = matches!(
        verify_signature_with_pem_key(SIGNED_RESPONSE, SIGNER_KEY, false),
        Ok(result) if result.status == DsigStatus::Valid
    );
    let tampered = SIGNED_RESPONSE.replacen("test@example.com", "tampered@example.com", 1);
    let rejected = matches!(
        verify_signature_with_pem_key(&tampered, SIGNER_KEY, false),
        Ok(result) if result.status
            == DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
    u32::from(valid && rejected)
}

/// Whether the archival level of `xml`'s first signature is met, in this module.
fn archival_level(xml: &str) -> Option<bool> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![LEVELS_ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Some(Instant::new(1_800_000_000, 0)?);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).ok()?;
    let request = VerificationRequest::default();
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 25, 1 << 31)));
    let utc = LeapTable::new(0, 2_000_000_000, &[]).ok()?;
    let anchors: &[&[u8]] = &[LEVELS_ROOT];
    with_verified_request(&document, &context, &request, &account, |session| {
        let inputs = Inputs {
            requirements: Requirements::Archival,
            anchors,
            certificates: &[],
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        let signature = session.evidence().signatures()[0].identity();
        Ok(validate(&session, signature, &inputs, |level| {
            level.all_requirements_met()
        }))
    })
    .ok()?
    .ok()
    .and_then(|outcome| match outcome {
        Outcome::Assessed(met) => Some(met),
        _ => None,
    })
}

/// B-LTA validation in the compiled WASM module: real tokens, CRLs and OCSP
/// meet the level, and a changed archive token does not.
#[unsafe(no_mangle)]
pub extern "C" fn xml_sec_wasm_xades() -> u32 {
    let open = "<xades:EncapsulatedTimeStamp>";
    let Some((start, _)) = LEVELS_ARCHIVAL.rmatch_indices(open).next() else {
        return 0;
    };
    let at = start + open.len() + 400;
    let replacement = if &LEVELS_ARCHIVAL[at..=at] == "A" {
        "B"
    } else {
        "A"
    };
    let tampered = format!(
        "{}{replacement}{}",
        &LEVELS_ARCHIVAL[..at],
        &LEVELS_ARCHIVAL[at + 1..]
    );
    u32::from(archival_level(LEVELS_ARCHIVAL) == Some(true) && archival_level(&tampered).is_none())
}

/// The signature answer for `token`, if its check completed with a matching
/// imprint and, for a valid signature, retained evidence.
fn check_token(token: &[u8]) -> Option<SignatureAnswer> {
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::ber(memory.clone());
    let certificate_parser = Parser::der(memory);
    let token = Token::read(&parser, token, 0).ok()?;
    let parent = parser.read(&[], 0).ok()?;
    let certificate = Certificate::read(&certificate_parser, TOKEN_CERTIFICATE, 0).ok()?;
    let certificate_parent = certificate_parser.read(&[], 0).ok()?;
    let utc = LeapTable::new(0, 2_000_000_000, &[]).ok()?;
    let mut policy = VerificationPolicy::default();
    policy.key_trust.certificate_signature_algorithms =
        Some(CertificateSignatureAlgorithms::AllSupported);
    let provider = RustCryptoProvider;
    let cms = CmsProvider::new(&provider, &policy);
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0)?),
        window: None,
        policy_accuracy: None,
    };
    let checked = token
        .check(&cms, &parent, &context, &mut [TOKEN_PAYLOAD], |_, _| {
            Ok::<_, ()>(false)
        })
        .ok()?;
    let TokenSignature::Checked(signature) = &checked.signature else {
        return None;
    };
    let answer = signature.signature()?;
    let consistent = checked.imprint == ImprintAgreement::Matches
        && checked.evidence().is_some() == (answer == SignatureAnswer::Valid);
    consistent.then_some(answer)
}

/// RFC 3161 timestamp verification through the selected provider in the
/// compiled WASM module: the token verifies, and the same token with an
/// altered signature value is an invalid signature rather than an error.
#[unsafe(no_mangle)]
pub extern "C" fn xml_sec_wasm_cms() -> u32 {
    let mut tampered = TOKEN.to_vec();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0x01;
    }
    u32::from(
        check_token(TOKEN) == Some(SignatureAnswer::Valid)
            && check_token(&tampered) == Some(SignatureAnswer::Invalid),
    )
}
