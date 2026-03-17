//! XML Digital Signatures (XMLDSig).
//!
//! Implements [XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/).
//!
//! ## Current Status
//!
//! - URI dereference: same-document references (`""`, `#id`, `#xpointer(/)`, `#xpointer(id('...'))`)
//! - ID attribute resolution with configurable attribute names
//! - Node set types for the transform pipeline

pub mod transforms;
pub mod types;
pub mod uri;

pub use transforms::{execute_transforms, parse_transforms, Transform};
pub use types::{NodeSet, TransformData, TransformError};
