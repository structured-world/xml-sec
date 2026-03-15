//! # xml-sec — Pure Rust XML Security
//!
//! Drop-in replacement for libxmlsec1. XMLDSig, XMLEnc, C14N — no C dependencies.
//!
//! ## Features
//!
//! - **C14N** — XML Canonicalization (inclusive + exclusive)
//! - **XMLDSig** — XML Digital Signatures (sign + verify)
//! - **XMLEnc** — XML Encryption (encrypt + decrypt)
//! - **X.509** — Certificate-based key extraction
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use xml_sec::{XmlSigner, XmlVerifier};
//!
//! // Verify a signed XML document
//! let doc = std::fs::read_to_string("signed.xml").unwrap();
//! let cert = std::fs::read("cert.pem").unwrap();
//! let valid = XmlVerifier::new(&cert).verify(&doc).unwrap();
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod c14n;
pub mod error;

#[cfg(feature = "xmldsig")]
pub mod xmldsig;

#[cfg(feature = "xmlenc")]
pub mod xmlenc;

pub use error::XmlSecError;
