//! XML Digital Signatures (XMLDSig).
//!
//! Implements [XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/).
//!
//! ## Current Status
//!
//! - URI dereference: same-document references (`""`, `#id`, `#xpointer(/)`, `#xpointer(id('...'))`)
//! - ID attribute resolution with configurable attribute names
//! - Node set types for the transform pipeline

pub mod digest;
pub mod parse;
pub mod signature;
pub mod transforms;
pub mod types;
pub mod uri;
pub mod verify;

pub use digest::{DigestAlgorithm, compute_digest, constant_time_eq};
pub use parse::{
    KeyInfo, KeyInfoSource, KeyValueInfo, ParseError, Reference, SignatureAlgorithm, SignedInfo,
    X509DataInfo, find_signature_node, parse_key_info, parse_signed_info,
};
pub use signature::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_ecdsa_signature_spki,
    verify_rsa_signature_pem, verify_rsa_signature_spki,
};
pub use transforms::{
    DEFAULT_IMPLICIT_C14N_URI, ENVELOPED_SIGNATURE_URI, Transform, XPATH_TRANSFORM_URI,
    execute_transforms, parse_transforms,
};
pub use types::{NodeSet, TransformData, TransformError};
pub use verify::{
    DsigError, DsigStatus, FailureReason, KeyResolver, ReferenceProcessingError, ReferenceResult,
    ReferenceSet, ReferencesResult, UriTypeSet, VerifyContext, VerifyResult, VerifyingKey,
    process_all_references, process_reference, verify_signature_with_pem_key,
};
