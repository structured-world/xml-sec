//! XML Digital Signatures (XMLDSig).
//!
//! Implements [XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/).
//!
//! ## Current Status
//!
//! - URI dereference: same-document references (`""`, `#id`, `#xpointer(/)`, `#xpointer(id('...'))`)
//! - ID attribute resolution with configurable attribute names
//! - Exact element, attribute, and namespace node sets for transform processing
//! - Enveloped, canonicalization, Base64, XPath 1.0, and XPath Filter 2.0 transforms
//!
//! ## Signing and verification
//!
//! Build an enveloped signature with a modern algorithm, then verify it with
//! the embedded certificate. New signatures must use SHA-256 or stronger;
//! SHA-1 remains verification-only for legacy interoperability.
//!
//! ```no_run
//! use xml_sec::c14n::{C14nAlgorithm, C14nMode};
//! use xml_sec::xmldsig::{
//!     DefaultKeyResolver, DigestAlgorithm, ReferenceBuilder, RsaSigningKey,
//!     SignContext, SignatureAlgorithm, SignatureBuilder, Transform, VerifyContext,
//!     X509CertificateKeyInfoWriter,
//! };
//!
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

pub mod builder;
pub mod digest;
pub mod keys;
pub mod mutation;
pub mod parse;
pub mod sign;
pub mod signature;
pub mod transforms;
pub mod types;
pub mod uri;
pub mod verify;
pub(crate) mod whitespace;
pub mod x509;
mod xpath;

pub use builder::{ReferenceBuilder, SignatureBuilder, SignatureBuilderError};
pub use digest::{DigestAlgorithm, compute_digest, constant_time_eq};
pub use keys::{DefaultKeyResolver, KeyResolutionError, KeyResolverConfig, VerificationKey};
pub use parse::{
    KeyInfo, KeyInfoSource, KeyValueInfo, ParseError, Reference, SignatureAlgorithm, SignedInfo,
    X509DataInfo, find_signature_node, parse_key_info, parse_reference, parse_signed_info,
};
pub use sign::{
    ComputedReferenceDigest, EcdsaP256SigningKey, EcdsaP384SigningKey, KeyInfoWriteError,
    KeyInfoWriter, RsaSigningKey, SignContext, SigningDigestError, SigningError, SigningKey,
    SigningKeyError, SigningPublicKeyInfo, X509CertificateKeyInfoWriter,
    compute_reference_digest_values, fill_reference_digest_values,
};
pub use signature::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_ecdsa_signature_spki,
    verify_rsa_signature_pem, verify_rsa_signature_spki,
};
pub use transforms::{
    BASE64_TRANSFORM_URI, DEFAULT_IMPLICIT_C14N_URI, ENVELOPED_SIGNATURE_URI, Transform,
    XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI, XPathExpression, XPathFilter,
    XPathFilterOperation, execute_transforms, parse_transforms,
};
pub use types::{NodeSet, TransformData, TransformError};
pub use verify::{
    DsigError, DsigStatus, FailureReason, KeyResolver, ReferenceProcessingError, ReferenceResult,
    ReferenceSet, ReferencesResult, UriTypeSet, VerifyContext, VerifyResult, VerifyingKey,
    process_all_references, process_reference, verify_signature_with_pem_key,
};
pub use x509::{X509ChainError, X509ChainOptions, verify_x509_certificate_chain};
