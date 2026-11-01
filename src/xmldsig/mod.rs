//! XML Digital Signatures (`XMLDSig`).
//!
//! Implements [XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/).
//!
//! ## Current Status
//!
//! - URI dereference: same-document references (`""`, `#id`, `#xpointer(/)`, `#xpointer(id('...'))`)
//! - ID attribute resolution with configurable attribute names
//! - Exact element, attribute, and namespace node sets for transform processing
//! - Enveloped, canonicalization, Base64, `XPath` 1.0, and `XPath` Filter 2.0 transforms
//!
//! ## Signing and verification
//!
//! Build an enveloped signature with a modern algorithm, then verify it with
//! the embedded certificate. Secure defaults require SHA-224 or stronger;
//! legacy SHA-1 methods require an explicit operation policy opt-in.
//! Signing requires the `xmldsig-sign` feature; `xmldsig` alone verifies.
//!
//! ```no_run
//! # #[cfg(feature = "xmldsig-sign")]
//! use xml_sec::c14n::{C14nAlgorithm, C14nMode};
//! # #[cfg(feature = "xmldsig-sign")]
//! use xml_sec::xmldsig::{
//!     DefaultKeyResolver, DigestAlgorithm, ReferenceBuilder, RsaSigningKey,
//!     SignContext, SignatureAlgorithm, SignatureBuilder, Transform, VerifyContext,
//!     X509CertificateKeyInfoWriter,
//! };
//!
//! # #[cfg(feature = "xmldsig-sign")]
//! # fn example(private_key_pem: &str, certificate_pem: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
//! let template = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256)
//!     .add_reference(
//!         ReferenceBuilder::new(DigestAlgorithm::Sha256)
//!             .uri("#message")
//!             .transform(Transform::Enveloped)
//!             .transform(Transform::C14n(c14n)),
//!     )
//!     .key_info(true)
//!     .build_template()?;
//! let xml = xml_sec::xmldsig::mutation::append_signature_to_root(
//!     "<Message ID=\"message\">hello</Message>",
//!     &template,
//! )?;
//! let signing_key = RsaSigningKey::from_pkcs8_pem(private_key_pem)?;
//! let key_info = X509CertificateKeyInfoWriter::from_pem(certificate_pem)?;
//! let signed = SignContext::new(&signing_key)
//!     .key_info_writer(&key_info)
//!     .sign_template(&xml)?;
//!
//! let resolver = DefaultKeyResolver::default();
//! let result = VerifyContext::new().key_resolver(&resolver).verify(&signed)?;
//! assert!(matches!(result.status, xml_sec::xmldsig::DsigStatus::Valid));
//! # Ok(())
//! # }
//! ```
#![doc = include_str!("../../docs/xmldsig.md")]

mod base64_stream;
#[cfg(feature = "xmldsig-sign")]
pub mod builder;
#[cfg(feature = "cms")]
pub mod cms;
pub mod digest;
pub mod extension;
pub mod keys;
pub(crate) mod modern;
#[cfg(feature = "experimental-pq")]
pub(crate) mod post_quantum;
mod pq_algorithm;
#[cfg(all(feature = "experimental-pq", feature = "xmldsig-sign"))]
pub use post_quantum::PostQuantumSigningKey;
pub use pq_algorithm::PqAlgorithm;
#[cfg(feature = "xmldsig-sign")]
pub mod mutation;
pub mod parse;
pub(crate) mod pkix;
#[cfg(feature = "xmldsig-sign")]
pub mod sign;
pub mod signature;
mod signing_key;
pub mod transforms;
pub mod trust;
pub mod types;
pub mod uri;
pub mod verify;
pub(crate) mod whitespace;
pub mod x509;
mod xpath;

#[cfg(feature = "xmldsig-sign")]
pub use builder::{ReferenceBuilder, SignatureBuilder, SignatureBuilderError};
pub use digest::{DigestAlgorithm, compute_digest, compute_digest_with_provider, constant_time_eq};
pub use keys::{
    DefaultKeyResolver, HmacSha1VerificationKey, HmacVerificationKey, InspectedKeyCandidateBudget,
    KeyResolutionError, KeyResolverConfig, VerificationKey,
};
#[cfg(feature = "xmldsig-sign")]
pub use modern::EdDsaSigningKey;
pub use parse::{
    KeyInfo, KeyInfoSource, KeyValueInfo, ParseError, Reference, RetrievalMethodTransforms,
    RsaPssParameters, SignatureAlgorithm, SignatureContext, SignedInfo, X509DataInfo,
    find_signature_node, parse_key_info, parse_reference, parse_signed_info,
    x509_certificate_matches_selectors,
};
pub use pkix::CertificatePathVerifier;
#[cfg(feature = "xmldsig-sign")]
pub use sign::{
    ComputedReferenceDigest, DerEncodedKeyValueInfoWriter, DsaSigningKey, EcdsaP256SigningKey,
    EcdsaP384SigningKey, EcdsaP521SigningKey, HmacSigningKey, KeyInfoWriteError, KeyInfoWriter,
    KeyValueInfoWriter, RsaSigningKey, SignContext, SignatureTemplateSelection, SigningDigestError,
    SigningError, X509CertificateKeyInfoWriter, X509DigestKeyInfoWriter,
    compute_reference_digest_values, fill_reference_digest_values, validate_signing_key,
};
pub use signature::{
    SignatureVerificationError, verify_dsa_signature_spki, verify_ecdsa_signature_pem,
    verify_ecdsa_signature_pem_with_encoding, verify_ecdsa_signature_spki,
    verify_ecdsa_signature_spki_with_encoding, verify_rsa_signature_pem, verify_rsa_signature_spki,
};
pub use signing_key::{SigningKey, SigningKeyError, SigningPublicKeyInfo};
#[cfg(feature = "xslt")]
pub use transforms::XsltStylesheet;
pub use transforms::{
    BASE64_TRANSFORM_URI, DEFAULT_IMPLICIT_C14N_URI, ENVELOPED_SIGNATURE_URI,
    RELATIONSHIP_TRANSFORM_URI, RelationshipSelector, Transform, XPATH_FILTER2_TRANSFORM_URI,
    XPATH_TRANSFORM_URI, XPathExpression, XPathFilter, XPathFilterOperation, XPathHereSemantics,
    XSLT_TRANSFORM_URI, execute_transforms, execute_transforms_with_policy, parse_transforms,
};
pub use trust::{KeyTrustEvidence, ResolvedVerificationKey, TrustedPublicKey, X509TrustEvidence};
pub use types::{NodeSet, TransformData, TransformError};
pub use verify::{
    AuthenticatedReference, BareNameTarget, CallerTrustedSignatureKey, CatalogueCompleteness,
    CatalogueError, DetachedChain, DetachedCompletion, DetachedPayload, DigestMethodResolution,
    DsigError, DsigStatus, ExternalPayload, ExternalResourceUnavailable, FailureReason,
    HashUseAlgorithm, HashUseCompleteness, HashUseRole, HashUseState, KeyInfoCandidate,
    KeyInfoMaterial, KeyInfoOrigin, KeyInfoReading, KeyResolver, LexicalSource, PendingDetached,
    ReferenceCoverage, ReferenceLocation, ReferenceParent, ReferenceProcessingError,
    ReferenceResolution, ReferenceResult, ReferenceSet, ReferencesResult, ReplayError, ReplayMode,
    ReplayOutcome, SelectedKeyReceipt, SelectedSignature, SelectedSignatureMethod, SessionDigest,
    SignatureEvidence, SignatureHashUse, SignatureKeyInfoMetadata, SignatureRequirement,
    SignatureSelection, UriTypeSet, VerificationRequest, VerificationScope, VerifiedSession,
    VerifyContext, VerifyEvidence, VerifyResult, VerifyingKey, has_same_document_encapsulation,
    inspect_pinned_verification_key_info, inspect_signing_key_info, inspect_verification_key_info,
    materialize_signing_key_info_references, materialize_verification_key_info_references,
    process_all_references, process_reference, verify_signature_with_pem_key,
    with_verified_request,
};
pub use x509::{
    X509ChainError, X509ChainOptions, verify_x509_certificate_chain,
    verify_x509_certificate_chain_with_resources,
};
