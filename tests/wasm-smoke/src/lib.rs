//! Executable qualification of the alloc-only WASM product paths.
//! This separate consumer excludes native-only development dependencies.

use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
use xml_sec::xmldsig::{DsigStatus, FailureReason, verify_signature_with_pem_key};

/// A donor SAML 2.0 response signed by its identity provider.
const SIGNED_RESPONSE: &str = include_str!("../../fixtures/saml/response_signed_by_idp_ecdsa.xml");
const SIGNER_KEY: &str = include_str!("../../fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");

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
