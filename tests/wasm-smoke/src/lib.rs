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
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
use xml_sec::policy::{CertificateSignatureAlgorithms, VerificationPolicy};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::cms::CmsProvider;
use xml_sec::xmldsig::{DsigStatus, FailureReason, verify_signature_with_pem_key};

/// A donor SAML 2.0 response signed by its identity provider.
const SIGNED_RESPONSE: &str = include_str!("../../fixtures/saml/response_signed_by_idp_ecdsa.xml");
const SIGNER_KEY: &str = include_str!("../../fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");
/// An RFC 3161 token from an independent authority, with its certificate.
const TOKEN: &[u8] = include_bytes!("../../fixtures/cms/timestamp/ed25519.tst");
const TOKEN_CERTIFICATE: &[u8] = include_bytes!("../../fixtures/cms/timestamp/ed25519.der");
const TOKEN_PAYLOAD: &[u8] = include_bytes!("../../fixtures/cms/timestamp/payload.txt");

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
