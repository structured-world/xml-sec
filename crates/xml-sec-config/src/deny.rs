//! `profiles.NAME.deny`: the permissions a profile withdraws from what it
//! inherits, as `xml_sec::policy::Denials`. Every value must name something
//! this build knows, so a misspelt denial fails loading instead of
//! withdrawing nothing.

use crate::Error;
use serde::Deserialize;
use xml_sec::policy::Denials;
use xml_sec::xmldsig::transforms::implemented_transform_uris;
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm, UriClass};

/// The `deny` table of one profile.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Deny {
    #[serde(default)]
    transforms: Vec<String>,
    #[serde(default)]
    signature_algorithms: Vec<String>,
    #[serde(default)]
    digest_algorithms: Vec<String>,
    #[serde(default)]
    key_sources: Vec<String>,
    #[serde(default)]
    reference_uri_classes: Vec<String>,
}

fn unknown(field: &str, value: &str) -> Error {
    Error::Schema(format!("deny.{field}: unknown value {value}"))
}

impl Deny {
    /// The typed denials, or the first value this build does not know.
    pub(crate) fn denials(&self) -> Result<Denials, Error> {
        let mut denials = Denials::default();
        for uri in &self.transforms {
            if !implemented_transform_uris().any(|known| known == uri) {
                return Err(unknown("transforms", uri));
            }
            denials.transforms.insert(uri.clone());
        }
        // A denied URI withdraws its method in every parameterization: the
        // policy matches denials by URI, so the RSA-PSS URI covers every
        // tuple (RFC 9231 2.3.10), not only the default one parsed here.
        for uri in &self.signature_algorithms {
            let method = SignatureAlgorithm::from_uri(uri)
                .ok_or_else(|| unknown("signature_algorithms", uri))?;
            denials.signature_algorithms.insert(method);
        }
        for uri in &self.digest_algorithms {
            let method =
                DigestAlgorithm::from_uri(uri).ok_or_else(|| unknown("digest_algorithms", uri))?;
            denials.digest_algorithms.insert(method);
        }
        for name in &self.key_sources {
            denials.key_sources.push(
                crate::settings::key_source_named(name)
                    .ok_or_else(|| unknown("key_sources", name))?,
            );
        }
        for name in &self.reference_uri_classes {
            denials.reference_uri_classes.push(match name.as_str() {
                "empty" => UriClass::Empty,
                "same_document" => UriClass::SameDocument,
                "external" => UriClass::External,
                _ => return Err(unknown("reference_uri_classes", name)),
            });
        }
        Ok(denials)
    }
}
