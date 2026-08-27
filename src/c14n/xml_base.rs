//! `xml:base` URI fixup for C14N 1.1 document subsets.
//!
//! When C14N 1.1 processes a document subset and an element's parent is
//! outside the node set, `xml:base` values must be resolved to effective
//! URIs per [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5).
//! The effective URI is absolute only if the ancestor chain includes an
//! absolute (scheme-bearing) base; otherwise it may remain relative.
//!
//! This module provides a minimal RFC 3986 relative URI resolver — just
//! enough for `xml:base` fixup. It is NOT a general-purpose URI library.

use std::cell::Cell;

use crate::xml::dom::Node;

use super::NodeVisibility;

/// The XML namespace URI.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Deterministic limits shared by XML Base consumers in one operation.
pub(crate) struct XmlBaseResolutionBudget {
    remaining_bytes: Cell<usize>,
    max_bytes: usize,
    max_components: usize,
}

impl Default for XmlBaseResolutionBudget {
    fn default() -> Self {
        Self::with_limits(
            crate::hard_limits::XML_BASE_COMPONENT_CEILING,
            crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
        )
    }
}

impl XmlBaseResolutionBudget {
    pub(crate) fn with_limits(max_components: usize, max_bytes: usize) -> Self {
        Self {
            remaining_bytes: Cell::new(max_bytes),
            max_bytes,
            max_components,
        }
    }

    fn check_components(&self, actual: usize) -> Result<(), XmlBaseResolutionError> {
        if actual > self.max_components {
            return Err(XmlBaseResolutionError::Components {
                maximum: self.max_components,
                actual,
            });
        }
        Ok(())
    }

    fn charge_bytes(&self, bytes: usize) -> Result<(), XmlBaseResolutionError> {
        let remaining = self.remaining_bytes.get();
        let Some(next) = remaining.checked_sub(bytes) else {
            self.remaining_bytes.set(0);
            return Err(XmlBaseResolutionError::Bytes {
                maximum: self.max_bytes,
                actual: self
                    .max_bytes
                    .saturating_add(bytes.saturating_sub(remaining)),
            });
        };
        self.remaining_bytes.set(next);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum XmlBaseResolutionError {
    #[error("XML Base resolution exceeds maximum of {maximum} inherited components: got {actual}")]
    Components { maximum: usize, actual: usize },
    #[error("XML Base resolution exceeds cumulative maximum of {maximum} bytes: got {actual}")]
    Bytes { maximum: usize, actual: usize },
}

/// Compute the effective `xml:base` for an element by resolving the ancestor
/// chain per [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5).
///
/// Walks from `start` up the ancestor chain, collecting `xml:base` values
/// from each element. If a `node_set` is provided, the walk stops at the
/// nearest included ancestor that emits its own non-empty `xml:base` in the
/// canonical output. A selected element without such an attribute is not a
/// boundary: inherited source context may still be absent from the output.
/// Likewise, an included ancestor with an excluded `xml:base` attribute is not
/// a boundary because its hidden base still contributes to descendants.
/// The collected bases are resolved from the topmost to the closest.
///
/// The resulting reference is absolute only if some ancestor `xml:base`
/// (or the effective base at that point) is absolute; otherwise it may be
/// a relative reference.
///
/// Returns `None` if the considered ancestor chain has no non-empty
/// `xml:base` attribute.
#[cfg(test)]
pub(crate) fn compute_effective_xml_base(
    start: Node<'_, '_>,
    visibility: Option<&dyn NodeVisibility>,
) -> Option<String> {
    compute_effective_xml_base_with_budget(start, visibility, &XmlBaseResolutionBudget::default())
        .expect("test XML Base fixtures stay within implementation ceilings")
}

/// Budgeted form used for attacker-controlled XMLDSig URI resolution.
pub(crate) fn compute_effective_xml_base_with_budget(
    start: Node<'_, '_>,
    visibility: Option<&dyn NodeVisibility>,
    budget: &XmlBaseResolutionBudget,
) -> Result<Option<String>, XmlBaseResolutionError> {
    let mut bases: Vec<&str> = Vec::new();
    let mut current = Some(start);
    while let Some(node) = current {
        if node.is_element() {
            let base = xml_base_value(node);
            if let Some(set) = visibility
                && preserves_xml_base_context(node, set)
            {
                break;
            }
            if let Some(base) = base {
                let component_count = bases.len().saturating_add(1);
                budget.check_components(component_count)?;
                budget.charge_bytes(base.len())?;
                bases.push(base);
            }
        }
        current = node.parent();
    }

    let Some(first) = bases.pop() else {
        return Ok(None);
    };
    budget.charge_bytes(first.len())?;
    let mut effective = first.to_owned();
    for relative in bases.into_iter().rev() {
        effective = resolve_uri_with_budget(&effective, relative, budget)?;
    }
    Ok(Some(effective))
}

pub(crate) fn resolve_uri_with_budget(
    base: &str,
    reference: &str,
    budget: &XmlBaseResolutionBudget,
) -> Result<String, XmlBaseResolutionError> {
    let input_bytes = base
        .len()
        .checked_add(reference.len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(XmlBaseResolutionError::Bytes {
            maximum: budget.max_bytes,
            actual: usize::MAX,
        })?;
    budget.charge_bytes(input_bytes)?;
    let resolved = resolve_uri(base, reference);
    budget.charge_bytes(resolved.len())?;
    Ok(resolved)
}

/// Resolve a reference against inherited XML Base without traversing ancestors
/// when the reference already supplies an RFC 3986 scheme.
#[cfg(feature = "xmldsig")]
pub(crate) fn resolve_uri_from_node_with_budget(
    origin: Node<'_, '_>,
    reference: &str,
    budget: &XmlBaseResolutionBudget,
) -> Result<String, XmlBaseResolutionError> {
    resolve_uri_from_node_with_document_base_with_budget(origin, reference, None, budget)
}

/// Resolve a URI against an owning external document and its inherited XML Base.
#[cfg(feature = "xmldsig")]
pub(crate) fn resolve_uri_from_node_with_document_base_with_budget(
    origin: Node<'_, '_>,
    reference: &str,
    document_base: Option<&str>,
    budget: &XmlBaseResolutionBudget,
) -> Result<String, XmlBaseResolutionError> {
    if has_scheme(reference) {
        return resolve_uri_with_budget("", reference, budget);
    }
    let inherited_base = compute_effective_xml_base_with_budget(origin, None, budget)?;
    let base = match (document_base, inherited_base) {
        (Some(document_base), Some(xml_base)) => {
            resolve_uri_with_budget(document_base, &xml_base, budget)?
        }
        (Some(document_base), None) => document_base.to_owned(),
        (None, Some(xml_base)) => xml_base,
        (None, None) => String::new(),
    };
    resolve_uri_with_budget(&base, reference, budget)
}

/// Whether a selected element establishes its source `xml:base` context in the
/// canonical output and therefore forms a boundary for descendant fixup.
pub(super) fn preserves_xml_base_context(
    node: Node<'_, '_>,
    visibility: &dyn NodeVisibility,
) -> bool {
    visibility.contains_node(node)
        && xml_base_value(node).is_some()
        && visibility.contains_attribute(node, Some(XML_NS), "base")
}

/// Get the `xml:base` attribute value from an element, if present.
///
/// Per RFC 3986, an empty reference resolves to the current base. We
/// therefore treat `xml:base=""` as if no `xml:base` were present.
fn xml_base_value<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    for attr in node.attributes() {
        if attr.namespace() == Some(XML_NS) && attr.name() == "base" {
            let value = attr.value();
            if value.is_empty() {
                return None;
            }
            return Some(value);
        }
    }
    None
}

/// Resolve a URI reference against a base URI per RFC 3986 §5.2.2.
///
/// C14N 1.1 §2.4 explicitly specifies RFC 3986 §5 for `xml:base` resolution:
/// "IRI resolution of relative references is performed as described in
/// Section 5 of [RFC 3986]." No C14N-specific deviations from RFC 3986.
///
/// Handles: absolute references (with scheme), authority overrides (`//`),
/// absolute paths (`/`), relative paths, and empty references.
///
/// **When base has no scheme** (schemeless/relative base), full RFC 3986
/// resolution is not possible, but path-merge and dot-segment removal are
/// still performed so that chained relative `xml:base` values collapse
/// correctly (e.g. `a/b/` + `c/` → `a/b/c/`). The result remains relative.
pub(crate) fn resolve_uri(base: &str, reference: &str) -> String {
    // Empty reference → base URI
    if reference.is_empty() {
        return base.to_string();
    }

    // A scheme-bearing reference supplies every target component, but RFC 3986
    // section 5.2.2 still requires dot-segment removal from its path.
    if has_scheme(reference) {
        let (absolute, suffix) = split_path_suffix(reference);
        let parts = parse_base(absolute).expect("has_scheme accepted the absolute reference");
        let path = remove_dot_segments_from_absolute_reference(parts.path);
        let mut result = recompose(parts.scheme, parts.authority, &path);
        result.push_str(suffix);
        return result;
    }

    // Query- and fragment-only references preserve the complete base path for
    // both absolute and relative bases (RFC 3986 section 5.2.2).
    if reference.starts_with('?') {
        return format!("{}{reference}", strip_query_fragment(base));
    }
    if reference.starts_with('#') {
        return format!("{}{reference}", base.split('#').next().unwrap_or(base));
    }

    // Parse base URI components
    let base_parts = match parse_base(base) {
        Some(parts) => parts,
        None => {
            // Schemeless bases include both ordinary relative paths and
            // network-path references. Preserve the latter's authority while
            // applying the same RFC 3986 path merge and normalization rules.
            let (ref_path, ref_suffix) = split_path_suffix(reference);
            if let Some((authority, path)) = parse_network_path(ref_path) {
                let path = remove_dot_segments(path);
                return format!("//{authority}{path}{ref_suffix}");
            }
            let (base_path_with_authority, _) = split_path_suffix(base);
            let network_base = parse_network_path(base_path_with_authority);
            if ref_path.starts_with('/') {
                let path = remove_dot_segments(ref_path);
                return match network_base {
                    Some((authority, _)) => format!("//{authority}{path}{ref_suffix}"),
                    None => format!("{path}{ref_suffix}"),
                };
            }
            let (base_path, authority) = match network_base {
                Some((authority, path)) => (path, Some(authority)),
                None => (base_path_with_authority, None),
            };
            let merged = merge_paths(base_path, ref_path, authority.is_some());
            let cleaned = remove_dot_segments(&merged);
            return match authority {
                Some(authority) => format!("//{authority}{cleaned}{ref_suffix}"),
                None => format!("{cleaned}{ref_suffix}"),
            };
        }
    };
    let scheme = base_parts.scheme;
    let authority = base_parts.authority;
    let base_path = base_parts.path;

    // Split reference into path and query/fragment suffix. We apply
    // remove_dot_segments only to the path portion, then reattach the
    // query/fragment to the result.
    let (ref_path, ref_suffix) = split_path_suffix(reference);

    // Reference starts with // → authority override (RFC 3986 §5.2.2:
    // the path component must still be normalized).
    if let Some(rest) = ref_path.strip_prefix("//") {
        let mut auth_end = rest.len();
        for ch in ['/', '?', '#'] {
            if let Some(pos) = rest.find(ch)
                && pos < auth_end
            {
                auth_end = pos;
            }
        }
        let new_authority = &rest[..auth_end];
        let new_path = remove_dot_segments(&rest[auth_end..]);
        let mut result = recompose(scheme, Some(new_authority), &new_path);
        result.push_str(ref_suffix);
        return result;
    }

    // Reference starts with / → absolute path
    if ref_path.starts_with('/') {
        let cleaned = remove_dot_segments(ref_path);
        let mut result = recompose(scheme, authority, &cleaned);
        result.push_str(ref_suffix);
        return result;
    }

    // Relative path — merge with base path (strip query/fragment from
    // base_path first, since merge operates on the path component only).
    let clean_base_path = strip_query_fragment(base_path);
    let merged = merge_paths(clean_base_path, ref_path, authority.is_some());
    let cleaned = remove_dot_segments(&merged);
    let mut result = recompose(scheme, authority, &cleaned);
    result.push_str(ref_suffix);
    result
}

/// Check if a URI string has a scheme (e.g., `http:`, `urn:`).
fn has_scheme(uri: &str) -> bool {
    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    // A scheme is followed by ":"
    if let Some(colon_pos) = uri.find(':') {
        // Must have at least one char before colon, all scheme-chars
        colon_pos > 0
            && uri.as_bytes()[0].is_ascii_alphabetic()
            && uri[..colon_pos]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    } else {
        false
    }
}

/// Parsed base URI components.
struct BaseParts<'a> {
    scheme: &'a str,
    /// `Some("")` = authority present but empty (e.g., `file:///path`).
    /// `None` = no authority (e.g., `urn:foo:bar`).
    authority: Option<&'a str>,
    path: &'a str,
}

/// Parse a base URI into scheme, optional authority, and path per RFC 3986.
///
/// Returns `None` if `base` has no valid RFC 3986 scheme (e.g. relative
/// paths like `a/b:c` where `:` is not a scheme delimiter).
fn parse_base(base: &str) -> Option<BaseParts<'_>> {
    // Only treat ':' as a scheme delimiter if base has a valid scheme.
    // This prevents mis-parsing relative paths containing ':' in later
    // segments (e.g. "a/b:c" would wrongly yield scheme="a/b").
    if !has_scheme(base) {
        return None;
    }
    let scheme_end = base.find(':')?;
    let scheme = &base[..scheme_end];

    let mut rest = &base[scheme_end + 1..];
    let mut authority = None;

    // If the hier-part starts with "//", an authority is present (may be empty).
    if rest.starts_with("//") {
        rest = &rest[2..];
        let mut auth_end = rest.len();
        for ch in ['/', '?', '#'] {
            if let Some(pos) = rest.find(ch)
                && pos < auth_end
            {
                auth_end = pos;
            }
        }
        authority = Some(&rest[..auth_end]);
        rest = &rest[auth_end..];
    }

    Some(BaseParts {
        scheme,
        authority,
        path: rest,
    })
}

/// Split a schemeless network-path reference into authority and path.
/// Query and fragment components must already have been removed.
fn parse_network_path(reference: &str) -> Option<(&str, &str)> {
    let rest = reference.strip_prefix("//")?;
    let authority_end = rest.find('/').unwrap_or(rest.len());
    Some((&rest[..authority_end], &rest[authority_end..]))
}

/// Recompose a URI from scheme, optional authority, and path per RFC 3986 §5.3.
///
/// `authority = Some("")` → `scheme:///path` (empty authority, e.g. `file:///`).
/// `authority = None` → `scheme:path` (no authority, e.g. `urn:foo:bar`).
fn recompose(scheme: &str, authority: Option<&str>, path: &str) -> String {
    match authority {
        Some(auth) => format!("{scheme}://{auth}{path}"),
        None => format!("{scheme}:{path}"),
    }
}

/// Split a reference into (path, suffix) where suffix is `?query#fragment`
/// (or just `#fragment`, or empty). Only considers `?` and `#` after the
/// first character to preserve leading `?`/`#` semantics (those are handled
/// separately as query-only / fragment-only references).
fn split_path_suffix(reference: &str) -> (&str, &str) {
    // Character indices remain valid UTF-8 slice boundaries for untrusted XML
    // attribute values. The first scalar is intentionally skipped because
    // leading query/fragment references are handled before this helper.
    let split_at = reference
        .char_indices()
        .skip(1)
        .find_map(|(index, ch)| matches!(ch, '?' | '#').then_some(index))
        .unwrap_or(reference.len());
    (&reference[..split_at], &reference[split_at..])
}

/// Strip query (`?...`) and fragment (`#...`) from a URI or path component.
fn strip_query_fragment(s: &str) -> &str {
    let end = s
        .find('?')
        .unwrap_or(s.len())
        .min(s.find('#').unwrap_or(s.len()));
    &s[..end]
}

/// Merge a relative reference with a base path per RFC 3986 §5.2.3.
///
/// An authority with an empty path contributes the leading `/`; an empty
/// schemeless base does not. Keeping that distinction explicit prevents a
/// relative XML Base from changing the reference kind.
fn merge_paths(base_path: &str, reference: &str, base_has_authority: bool) -> String {
    if base_has_authority && base_path.is_empty() {
        format!("/{reference}")
    } else {
        // Remove everything after the last segment of base path.
        // If there is no '/' in the base path (non-hierarchical path,
        // e.g. opaque URIs like `urn:foo:bar`), return the reference
        // unchanged per RFC 3986 §5.2.3.
        match base_path.rfind('/') {
            Some(pos) => format!("{}{reference}", &base_path[..=pos]),
            None => reference.to_string(),
        }
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    /// Non-hierarchical base path (no '/') should return reference as-is.
    #[test]
    fn non_hierarchical_base_does_not_add_slash() {
        assert_eq!(merge_paths("foo:bar", "baz", false), "baz");
    }
}

/// Remove `.` and `..` segments from a path per RFC 3986 §5.2.4.
///
/// For absolute paths (starting with `/`), `..` at the root is a no-op.
/// For relative paths, unresolved leading `..` segments are preserved.
fn remove_dot_segments(path: &str) -> String {
    remove_dot_segments_with_unmatched_parents(path, true)
}

/// Apply RFC 3986 section 5.2.4 to a reference that already supplied a scheme.
/// Such a reference is the final target, so unresolved leading parents are
/// discarded rather than retained for a later base-path merge.
fn remove_dot_segments_from_absolute_reference(path: &str) -> String {
    remove_dot_segments_with_unmatched_parents(path, false)
}

fn remove_dot_segments_with_unmatched_parents(
    path: &str,
    preserve_unmatched_parents: bool,
) -> String {
    let is_absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {
                // Current directory — skip
            }
            ".." => {
                // Parent directory — RFC 3986 §5.2.4:
                // - For absolute paths, do not traverse above root (the
                //   leading "" segment from the initial '/' is preserved).
                // - For relative paths, preserve unmatched ".." segments.
                let root_segments = usize::from(is_absolute);
                let can_pop =
                    segments.len() > root_segments && !matches!(segments.last(), Some(&".."));
                if can_pop {
                    segments.pop();
                } else if !is_absolute && preserve_unmatched_parents {
                    segments.push("..");
                }
            }
            s => segments.push(s),
        }
    }

    let mut result = segments.join("/");

    // If the input path ended with /. or /.., ensure trailing slash
    if (path.ends_with("/.") || path.ends_with("/..")) && !result.ends_with('/') {
        result.push('/');
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::xml::dom::Document;

    // ── resolve_uri tests ────────────────────────────────────────────

    #[test]
    fn resolve_absolute_reference() {
        assert_eq!(
            resolve_uri("http://a.com/b", "http://other.com/c"),
            "http://other.com/c"
        );
    }

    #[test]
    fn resolve_absolute_reference_removes_dot_segments() {
        // RFC 3986 applies dot-segment removal to an absolute reference too;
        // its existing scheme only prevents inheritance from the base URI.
        assert_eq!(
            resolve_uri(
                "https://base.example/ignored/",
                "https://example.test/a/../data.bin?version=1#payload"
            ),
            "https://example.test/data.bin?version=1#payload"
        );
    }

    #[test]
    fn resolve_absolute_reference_consumes_interior_empty_segment() {
        // RFC 3986 treats the empty segment introduced by the second slash as
        // an ordinary path segment. The following parent segment removes it;
        // only the leading empty segment represents the absolute-path root.
        assert_eq!(
            resolve_uri(
                "https://base.example/ignored/",
                "https://example.test/a//../b"
            ),
            "https://example.test/a/b"
        );
    }

    #[test]
    fn resolve_empty_reference() {
        assert_eq!(resolve_uri("http://a.com/b/c", ""), "http://a.com/b/c");
    }

    #[test]
    fn resolve_authority_override() {
        assert_eq!(
            resolve_uri("http://a.com/b", "//other.com/c"),
            "http://other.com/c"
        );
    }

    #[test]
    fn resolve_absolute_path() {
        assert_eq!(resolve_uri("http://a.com/b/c", "/d/e"), "http://a.com/d/e");
    }

    #[test]
    fn resolve_relative_path_simple() {
        assert_eq!(
            resolve_uri("http://example.com/a/b/", "c/d"),
            "http://example.com/a/b/c/d"
        );
    }

    #[test]
    fn resolve_relative_path_sibling() {
        // base path /a/b → last segment "b" removed → /a/ + c → /a/c
        assert_eq!(
            resolve_uri("http://example.com/a/b", "c"),
            "http://example.com/a/c"
        );
    }

    #[test]
    fn resolve_relative_path_parent() {
        assert_eq!(
            resolve_uri("http://example.com/a/b/c", "../d"),
            "http://example.com/a/d"
        );
    }

    #[test]
    fn resolve_relative_path_double_parent() {
        assert_eq!(
            resolve_uri("http://example.com/a/b/c/", "../../d"),
            "http://example.com/a/d"
        );
    }

    #[test]
    fn resolve_root_base_with_relative() {
        assert_eq!(
            resolve_uri("http://example.com/", "sub/"),
            "http://example.com/sub/"
        );
    }

    #[test]
    fn resolve_dot_current_dir() {
        assert_eq!(
            resolve_uri("http://example.com/a/b/", "./c"),
            "http://example.com/a/b/c"
        );
    }

    #[test]
    fn resolve_schemeless_base_merges_paths() {
        // Schemeless base: path-merge + dot removal still applies so that
        // chained relative xml:base values collapse correctly.
        assert_eq!(resolve_uri("sub/dir/", "file.xml"), "sub/dir/file.xml");
        assert_eq!(resolve_uri("a/b/", "../c"), "a/c");
        assert_eq!(resolve_uri("a/b", "c"), "a/c");
    }

    #[test]
    fn resolve_absolute_path_normalizes_against_schemeless_base() {
        assert_eq!(resolve_uri("a/b", "/x/../data.bin"), "/data.bin");
    }

    #[test]
    fn resolve_network_path_normalizes_against_schemeless_base() {
        assert_eq!(
            resolve_uri("a/b", "//cdn.example/x/../data.bin?version=1"),
            "//cdn.example/data.bin?version=1"
        );
    }

    #[test]
    fn resolve_against_network_path_base_preserves_authority() {
        // A network-path base has an authority even without a scheme. RFC 3986
        // resolution must not collapse it into an ordinary absolute path.
        assert_eq!(
            resolve_uri("//cdn.example/a/b/", "/x/../data.bin?version=1"),
            "//cdn.example/data.bin?version=1"
        );
        assert_eq!(
            resolve_uri("//cdn.example/a/b/", "../data.bin"),
            "//cdn.example/a/data.bin"
        );
        assert_eq!(
            resolve_uri("//cdn.example/a/b?old#fragment", "?new"),
            "//cdn.example/a/b?new"
        );
        assert_eq!(
            resolve_uri("//cdn.example/a/b?old#fragment", "#new"),
            "//cdn.example/a/b?old#new"
        );
        assert_eq!(
            resolve_uri("//cdn.example/a/b/", "//other.example/x/../data.bin"),
            "//other.example/data.bin"
        );
    }

    #[test]
    fn resolve_pathless_schemeless_base_preserves_relative_reference() {
        // A query-only relative base has no authority. RFC 3986 therefore
        // preserves a relative reference instead of introducing a root slash.
        assert_eq!(resolve_uri("?old", "data.bin"), "data.bin");
    }

    #[test]
    fn resolve_query_and_fragment_against_schemeless_base() {
        // RFC 3986 replaces only the query or fragment even when the effective
        // XML Base is itself relative rather than scheme-bearing.
        assert_eq!(resolve_uri("a/b?old#frag", "?new"), "a/b?new");
        assert_eq!(resolve_uri("a/b?old#frag", "#new"), "a/b?old#new");
    }

    #[test]
    fn resolve_urn_reference() {
        // URN has a scheme, should be returned as-is
        assert_eq!(
            resolve_uri("http://example.com/a", "urn:foo:bar"),
            "urn:foo:bar"
        );
    }

    #[test]
    fn resolve_rootless_absolute_uri_removes_leading_dot_segments() {
        // Once a reference supplies its own scheme, RFC 3986 section 5.2.4
        // discards unresolved leading dot segments from the final target path.
        assert_eq!(
            resolve_uri("https://example.test/base", "urn:../payload?version=1"),
            "urn:payload?version=1"
        );
        assert_eq!(
            resolve_uri("https://example.test/base", "urn:./payload"),
            "urn:payload"
        );
    }

    #[test]
    fn resolve_parent_beyond_root() {
        // Going past root with .. should stop at root
        assert_eq!(
            resolve_uri("http://example.com/a", "../../b"),
            "http://example.com/b"
        );
    }

    #[test]
    fn resolve_file_scheme_no_authority() {
        // file: URIs may lack authority (file:/path or file:///path)
        assert_eq!(
            resolve_uri("file:///home/user/doc.xml", "sub/file.xml"),
            "file:///home/user/sub/file.xml"
        );
    }

    #[test]
    fn resolve_base_with_query_fragment() {
        // Query and fragment in base should be ignored for path merge
        assert_eq!(
            resolve_uri("http://example.com/a/b?q=1#f", "c"),
            "http://example.com/a/c"
        );
    }

    #[test]
    fn resolve_reference_with_query() {
        // Reference contains query — must be preserved in output
        assert_eq!(
            resolve_uri("http://example.com/a/b", "c?x=1"),
            "http://example.com/a/c?x=1"
        );
    }

    #[test]
    fn resolve_unicode_reference_with_query_uses_utf8_boundaries() {
        // XML attributes are Unicode strings. URI component splitting must not
        // index through the first multibyte scalar as if it were one byte.
        assert_eq!(
            resolve_uri("https://example.test/base/", "é?x"),
            "https://example.test/base/é?x"
        );
    }

    #[test]
    fn resolve_reference_with_fragment() {
        // Reference contains fragment — must be preserved in output
        assert_eq!(
            resolve_uri("http://example.com/a/b", "c#frag"),
            "http://example.com/a/c#frag"
        );
    }

    #[test]
    fn resolve_reference_with_query_and_fragment() {
        assert_eq!(
            resolve_uri("http://example.com/a/b", "c?q=1#f"),
            "http://example.com/a/c?q=1#f"
        );
    }

    #[test]
    fn resolve_absolute_path_with_query() {
        assert_eq!(
            resolve_uri("http://example.com/a", "/b/c?q"),
            "http://example.com/b/c?q"
        );
    }

    // ── xml_base_value tests ─────────────────────────────────────────

    #[test]
    fn empty_xml_base_treated_as_absent() {
        let xml = r#"<root xml:base=""><child xml:base="http://ex.com/"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        // xml:base="" on root should be treated as absent
        assert_eq!(xml_base_value(root), None);
        // Non-empty xml:base should be returned
        let child = root.first_element_child().unwrap();
        assert_eq!(xml_base_value(child), Some("http://ex.com/"));
    }

    // ── remove_dot_segments tests ────────────────────────────────────

    #[test]
    fn remove_dots_simple() {
        assert_eq!(remove_dot_segments("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn remove_single_dot() {
        assert_eq!(remove_dot_segments("/a/./b"), "/a/b");
    }

    #[test]
    fn remove_double_dot() {
        assert_eq!(remove_dot_segments("/a/b/../c"), "/a/c");
    }

    #[test]
    fn remove_dots_trailing_slash() {
        assert_eq!(remove_dot_segments("/a/b/.."), "/a/");
    }

    #[test]
    fn remove_dots_at_root() {
        assert_eq!(remove_dot_segments("/../a"), "/a");
    }

    #[test]
    fn remove_dots_relative_leading_dotdot() {
        // Relative paths: unmatched ".." segments must be preserved
        assert_eq!(remove_dot_segments("../../a"), "../../a");
        assert_eq!(remove_dot_segments("foo/../../bar"), "../bar");
    }

    // ── has_scheme tests ─────────────────────────────────────────────

    #[test]
    fn scheme_detection() {
        assert!(has_scheme("http://example.com"));
        assert!(has_scheme("https://x"));
        assert!(has_scheme("urn:foo:bar"));
        assert!(has_scheme("ftp://a"));
        assert!(!has_scheme("/a/b"));
        assert!(!has_scheme("a/b"));
        assert!(!has_scheme(""));
        assert!(!has_scheme("://bad"));
    }

    // ── compute_effective_xml_base tests ─────────────────────────────

    #[test]
    fn effective_base_single_ancestor() {
        let xml = r#"<root xml:base="http://example.com/"><child/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        // Compute from child's parent (root)
        let base = compute_effective_xml_base(child.parent().unwrap(), None);
        assert_eq!(base.as_deref(), Some("http://example.com/"));
    }

    #[test]
    fn effective_base_chain_resolved() {
        let xml = r#"<a xml:base="http://example.com/"><b xml:base="sub/"><c/></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();

        // From c's parent (b): chain is [b: "sub/", a: "http://example.com/"]
        // Resolved: "http://example.com/" + "sub/" = "http://example.com/sub/"
        let base = compute_effective_xml_base(c.parent().unwrap(), None);
        assert_eq!(base.as_deref(), Some("http://example.com/sub/"));
    }

    #[test]
    fn effective_base_three_levels() {
        let xml =
            r#"<a xml:base="http://ex.com/"><b xml:base="x/"><c xml:base="y/"><d/></c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();
        let d = c.first_element_child().unwrap();

        let base = compute_effective_xml_base(d.parent().unwrap(), None);
        assert_eq!(base.as_deref(), Some("http://ex.com/x/y/"));
    }

    #[test]
    fn effective_base_none_when_no_xml_base() {
        let xml = r#"<root><child/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        assert_eq!(
            compute_effective_xml_base(child.parent().unwrap(), None),
            None
        );
    }

    #[test]
    fn effective_base_with_dotdot() {
        let xml = r#"<a xml:base="http://example.com/a/b/"><b xml:base="../c/"><d/></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let d = b.first_element_child().unwrap();

        // "http://example.com/a/b/" + "../c/" = "http://example.com/a/c/"
        let base = compute_effective_xml_base(d.parent().unwrap(), None);
        assert_eq!(base.as_deref(), Some("http://example.com/a/c/"));
    }
}
