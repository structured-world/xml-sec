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
pub mod transforms;
pub mod types;
pub mod uri;
pub mod verify;

pub use digest::{compute_digest, constant_time_eq, DigestAlgorithm};
pub use parse::{
    find_signature_node, parse_signed_info, ParseError, Reference, SignatureAlgorithm, SignedInfo,
};
pub use transforms::{execute_transforms, parse_transforms, Transform};
pub use types::{NodeSet, TransformData, TransformError};
pub use verify::{
    process_all_references, process_reference, ReferenceProcessingError, ReferenceResult,
    ReferencesResult,
};
