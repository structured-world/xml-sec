#[cfg(feature = "embedded")]
use crate::xml_input_shared as xml_sec_xml_input;

use super::Result;

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

/// One external-resource request passed across the caller-owned resolver boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveRequest<'a> {
    /// URI reference supplied by the stylesheet or source document.
    pub uri: &'a str,
    /// Base URI against which the reference is resolved, when known.
    pub base_uri: Option<&'a str>,
    /// Engine operation that requested the resource.
    pub purpose: ResolvePurpose,
    /// Preferred media types from `XInclude`'s `accept` attribute, when present.
    pub accept: Option<&'a str>,
    /// Preferred languages from `XInclude`'s `accept-language` attribute, when present.
    pub accept_language: Option<&'a str>,
}

impl<'a> ResolveRequest<'a> {
    pub(crate) const fn new(
        uri: &'a str,
        base_uri: Option<&'a str>,
        purpose: ResolvePurpose,
    ) -> Self {
        Self {
            uri,
            base_uri,
            purpose,
            accept: None,
            accept_language: None,
        }
    }
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

/// Borrowed access checked independently of acquiring or caching resource bytes.
#[derive(Debug, Clone, Copy)]
pub enum ResourceAccess<'a> {
    /// A URI request, including repeated uses satisfied by the operation cache.
    Request(ResolveRequest<'a>),
    /// Use the exact immutable resource obtained for a request, including a cache hit.
    Retained {
        request: ResolveRequest<'a>,
        identity: &'a ResourceIdentity,
    },
    /// A retained stylesheet dependency admitted before each execution.
    Dependency(&'a ResourceIdentity),
}

/// Caller-owned resource permission refusal, independent of transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessDenialReason {
    NotGranted,
    Revoked,
    Expired,
}

impl ResourceAccess<'_> {
    /// Construct a typed permission refusal without conflating it with transport failure.
    #[must_use]
    pub fn denied(self, reason: AccessDenialReason) -> super::Error {
        let resource = match self {
            Self::Request(request) | Self::Retained { request, .. } => request.uri,
            Self::Dependency(identity) => &identity.0,
        };
        super::Error::ResourceAccessDenied {
            resource: resource.into(),
            reason,
        }
    }
}

/// Explicit resource boundary used by compilation and execution.
pub trait Resolver: Send + Sync {
    /// Authorize use under the caller's current grant, without acquiring resource bytes.
    ///
    /// Called before acquisition and on external document/module cache hits, and for every
    /// compiled dependency before an execution starts. Check expiry, revocation and identity
    /// here: the engine deliberately has no ambient clock or transport policy. Successful
    /// authorization binds the immediately following use; callers must keep identities immutable
    /// and make the acquisition enforce the same grant atomically where revocation can race.
    /// In-memory resolvers with permanent grants may explicitly return `Ok(())`.
    ///
    /// # Errors
    /// Returns a typed access denial when the current grant refuses the resource.
    fn authorize(&self, access: ResourceAccess<'_>) -> Result<()>;

    /// Resolve one URI reference and return stable provenance with its bytes.
    ///
    /// Path-like fallback resolution preserves lexical `..` segments. A resolver
    /// that maps the result onto a filesystem must canonicalize it and enforce its
    /// configured root boundary before reading any bytes.
    ///
    /// # Errors
    /// Returns acquisition or access failures without substituting another resource.
    fn resolve(&self, request: ResolveRequest<'_>) -> Result<ResolvedResource>;
}

pub(crate) fn resolve_uri_reference(base: Option<&str>, reference: &str) -> String {
    if let Ok(absolute) = url::Url::parse(reference) {
        return absolute.to_string();
    }
    if let Some(base) = base {
        if let Ok(base_url) = url::Url::parse(base) {
            if let Ok(joined) = base_url.join(reference) {
                return joined.to_string();
            }
            if base_url.cannot_be_a_base()
                && let Some(joined) = resolve_rootless_absolute_uri(&base_url, reference)
            {
                return joined;
            }
        }
        if reference.is_empty() {
            return base
                .split_once('#')
                .map_or(base, |(document, _)| document)
                .to_owned();
        }
        if reference.starts_with('#') {
            let document = base.split_once('#').map_or(base, |(document, _)| document);
            return format!("{document}{reference}");
        }
        if reference.starts_with('?') {
            let document = base.split(['?', '#']).next().unwrap_or(base);
            return format!("{document}{reference}");
        }
        if reference.starts_with('/') {
            return reference.to_owned();
        }
        let base_path = base.split(['?', '#']).next().unwrap_or(base);
        if let Some((directory, _)) = base_path.rsplit_once('/') {
            return format!("{directory}/{reference}");
        }
    }
    reference.to_owned()
}

fn resolve_rootless_absolute_uri(base: &url::Url, reference: &str) -> Option<String> {
    // XML Base section 4 uses RFC 3986 section 5.2 reference resolution. `url` deliberately
    // treats a rootless absolute URI as opaque, so provide a temporary hierarchical path to reuse
    // its merge and dot-segment removal, then restore the RFC rootless result form.
    // https://www.rfc-editor.org/rfc/rfc3986#section-5.2
    let mut synthetic = url::Url::parse(&format!(
        "{}:/{}",
        base.scheme(),
        base.path().strip_prefix('/').unwrap_or(base.path())
    ))
    .ok()?;
    synthetic.set_query(base.query());
    synthetic.set_fragment(base.fragment());
    let mut joined = synthetic.join(reference).ok()?.to_string();
    if reference.starts_with('/') {
        return Some(joined);
    }
    let synthetic_root = base.scheme().len() + 1;
    debug_assert_eq!(joined.as_bytes().get(synthetic_root), Some(&b'/'));
    joined.remove(synthetic_root);
    Some(joined)
}

pub(crate) fn decode_resource(
    bytes: &[u8],
    explicit: Option<&str>,
    parsed_xml: bool,
    maximum_decoded_bytes: usize,
) -> std::result::Result<String, xml_sec_xml_input::Error> {
    let decoded = if parsed_xml {
        xml_sec_xml_input::decode_xml_bounded(bytes, explicit, maximum_decoded_bytes)
    } else {
        xml_sec_xml_input::decode_text_bounded(
            bytes,
            explicit.unwrap_or("UTF-8"),
            maximum_decoded_bytes,
        )
    };
    decoded.map(std::borrow::Cow::into_owned)
}

/// Resolver that denies every external resource.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn authorize(&self, access: ResourceAccess<'_>) -> Result<()> {
        Err(access.denied(AccessDenialReason::NotGranted))
    }

    fn resolve(&self, request: ResolveRequest<'_>) -> Result<ResolvedResource> {
        Err(ResourceAccess::Request(request).denied(AccessDenialReason::NotGranted))
    }
}

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
