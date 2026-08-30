use crate::{Error, Result};

/// Stable caller-defined identity for resolved bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceIdentity(pub String);

/// Why the engine is resolving a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResolvePurpose {
    Include,
    Import,
    Document,
    XInclude,
}

/// Immutable bytes and provenance supplied by a caller-owned resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedResource {
    pub canonical_uri: String,
    pub identity: ResourceIdentity,
    pub bytes: Vec<u8>,
    pub media_type: Option<String>,
    pub encoding: Option<String>,
}

/// Explicit resource boundary used by compilation and execution.
pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        uri: &str,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> Result<ResolvedResource>;
}

pub(crate) fn decode_resource(bytes: &[u8], explicit: Option<&str>) -> Result<String> {
    let encoding = if let Some(label) = explicit {
        encoding_rs::Encoding::for_label(label.as_bytes())
            .ok_or_else(|| Error::Xml(format!("unsupported resource encoding `{label}`")))?
    } else {
        encoding_rs::Encoding::for_bom(bytes)
            .map(|(encoding, _)| encoding)
            .unwrap_or(encoding_rs::UTF_8)
    };
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        return Err(Error::Xml(format!(
            "external resource contains invalid {} bytes",
            encoding.name()
        )));
    }
    Ok(decoded.into_owned())
}

/// Resolver that denies every external resource.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> Result<ResolvedResource> {
        Err(crate::Error::Resolver {
            uri: uri.to_owned(),
            message: "external resource access is not configured".into(),
        })
    }
}
