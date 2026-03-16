//! `xml:base` URI fixup for C14N 1.1 document subsets.
//!
//! When C14N 1.1 processes a document subset and an element's parent is
//! outside the node set, `xml:base` values must be resolved to effective
//! (absolute) URIs per [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5).
//!
//! This module provides a minimal RFC 3986 relative URI resolver — just
//! enough for `xml:base` fixup. It is NOT a general-purpose URI library.

use roxmltree::Node;

/// The XML namespace URI.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Compute the effective `xml:base` for an element by resolving the ancestor
/// chain per [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5).
///
/// Walks from `start` up the ancestor chain, collecting `xml:base` values.
/// Stops at the nearest ancestor that is included in the node set (if
/// provided), since that ancestor will render its own `xml:base` in the
/// canonical output. Resolves from the topmost collected base to the closest.
///
/// Returns `None` if no ancestor in the omitted chain has `xml:base`.
pub(crate) fn compute_effective_xml_base(
    start: Node<'_, '_>,
    node_set: Option<&dyn Fn(Node) -> bool>,
) -> Option<String> {
    let mut bases: Vec<&str> = Vec::new();
    let mut current = Some(start);
    while let Some(n) = current {
        if n.is_element() {
            // Stop at the nearest included ancestor — it renders its own
            // xml:base in the canonical output, so we only need to resolve
            // the contiguous omitted chain below it.
            if let Some(pred) = node_set {
                if pred(n) {
                    break;
                }
            }
            if let Some(base) = xml_base_value(n) {
                bases.push(base);
            }
        }
        current = n.parent();
    }

    if bases.is_empty() {
        return None;
    }

    // bases is closest-first, root-last. Reverse to resolve root→closest.
    bases.reverse();
    let mut effective = bases[0].to_string();
    for &relative in &bases[1..] {
        effective = resolve_uri(&effective, relative);
    }
    Some(effective)
}

/// Get the `xml:base` attribute value from an element, if present.
fn xml_base_value<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    for attr in node.attributes() {
        if attr.namespace() == Some(XML_NS) && attr.name() == "base" {
            return Some(attr.value());
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
pub(crate) fn resolve_uri(base: &str, reference: &str) -> String {
    // Empty reference → base URI
    if reference.is_empty() {
        return base.to_string();
    }

    // Reference with scheme → use as-is (already absolute)
    if has_scheme(reference) {
        return reference.to_string();
    }

    // Parse base URI components
    let (scheme, authority, base_path) = match parse_base(base) {
        Some(parts) => parts,
        None => return reference.to_string(), // base has no scheme, can't resolve
    };

    // Reference starts with // → authority override
    if reference.starts_with("//") {
        return format!("{scheme}:{reference}");
    }

    // Reference starts with / → absolute path
    if reference.starts_with('/') {
        let cleaned = remove_dot_segments(reference);
        return format!("{scheme}://{authority}{cleaned}");
    }

    // Relative path — merge with base path
    let merged = merge_paths(base_path, reference);
    let cleaned = remove_dot_segments(&merged);
    format!("{scheme}://{authority}{cleaned}")
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

/// Parse a base URI into (scheme, authority, path).
fn parse_base(base: &str) -> Option<(&str, &str, &str)> {
    let scheme_end = base.find("://")?;
    let scheme = &base[..scheme_end];
    let after_scheme = &base[scheme_end + 3..];
    let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let path = &after_scheme[authority_end..];
    Some((scheme, authority, path))
}

/// Merge a relative reference with a base path per RFC 3986 §5.2.3.
fn merge_paths(base_path: &str, reference: &str) -> String {
    if base_path.is_empty() {
        format!("/{reference}")
    } else {
        // Remove everything after (and including) the last segment of base path
        match base_path.rfind('/') {
            Some(pos) => format!("{}{reference}", &base_path[..=pos]),
            None => format!("/{reference}"),
        }
    }
}

/// Remove `.` and `..` segments from a path per RFC 3986 §5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {
                // Current directory — skip
            }
            ".." => {
                // Parent directory — remove last segment (but not past root)
                if segments.len() > 1 {
                    segments.pop();
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
    use roxmltree::Document;

    // ── resolve_uri tests ────────────────────────────────────────────

    #[test]
    fn resolve_absolute_reference() {
        assert_eq!(
            resolve_uri("http://a.com/b", "http://other.com/c"),
            "http://other.com/c"
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
    fn resolve_urn_reference() {
        // URN has a scheme, should be returned as-is
        assert_eq!(
            resolve_uri("http://example.com/a", "urn:foo:bar"),
            "urn:foo:bar"
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
