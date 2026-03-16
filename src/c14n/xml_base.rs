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
/// The resulting reference is absolute only if some ancestor `xml:base`
/// (or the effective base at that point) is absolute; otherwise it may be
/// a relative reference.
///
/// Returns `None` if no ancestor in the omitted chain has a non-empty
/// `xml:base` attribute.
pub(crate) fn compute_effective_xml_base(
    start: Node<'_, '_>,
    node_set: Option<&dyn Fn(Node) -> bool>,
) -> Option<String> {
    let mut bases: Vec<&str> = Vec::new();
    let mut current = Some(start);
    while let Some(n) = current {
        if n.is_element() {
            // Stop at the nearest included ancestor — it renders its own
            // xml:base in the canonical output. However, we still collect
            // its xml:base value as the resolution seed, so that the
            // omitted chain below resolves against an absolute base.
            if let Some(pred) = node_set {
                if pred(n) {
                    if let Some(base) = xml_base_value(n) {
                        bases.push(base);
                    }
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
/// **When base has no scheme** (schemeless/relative base), resolution is not
/// possible per RFC 3986 §5.2.2. In this case the reference is returned
/// unchanged. Callers must provide a scheme-bearing base for absolute output.
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

    // Reference starts with // → authority override (RFC 3986 §5.2.2:
    // the path component must still be normalized).
    if let Some(rest) = reference.strip_prefix("//") {
        // Split authority from path at first '/', '?', or '#'
        let mut auth_end = rest.len();
        for ch in ['/', '?', '#'] {
            if let Some(pos) = rest.find(ch) {
                if pos < auth_end {
                    auth_end = pos;
                }
            }
        }
        let new_authority = &rest[..auth_end];
        let new_path = remove_dot_segments(&rest[auth_end..]);
        return format!("{scheme}://{new_authority}{new_path}");
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
///
/// This follows the basic RFC 3986 structure:
///   URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
///   where hier-part may start with "//" authority.
///
/// We return:
/// - `scheme` as everything before the first `:`;
/// - `authority` if there is a `//authority` component, otherwise the
///   empty string;
/// - `path` as the remainder after the authority, including any query
///   or fragment.
fn parse_base(base: &str) -> Option<(&str, &str, &str)> {
    // Find the scheme separator.
    let scheme_end = base.find(':')?;
    let scheme = &base[..scheme_end];

    let mut rest = &base[scheme_end + 1..];

    // Default: no authority.
    let mut authority = "";

    // If the hier-part starts with "//", then an authority is present.
    if rest.starts_with("//") {
        rest = &rest[2..];
        // Authority goes up to the first '/', '?', or '#' (or end of string).
        let mut auth_end = rest.len();
        for ch in ['/', '?', '#'] {
            if let Some(pos) = rest.find(ch) {
                if pos < auth_end {
                    auth_end = pos;
                }
            }
        }
        authority = &rest[..auth_end];
        rest = &rest[auth_end..];
    }

    let path = rest;
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
    fn resolve_schemeless_base_returns_reference() {
        // When base has no scheme, parse_base returns None and resolve_uri
        // falls back to returning the reference as-is. This is correct:
        // without an absolute base, relative resolution is undefined.
        assert_eq!(resolve_uri("sub/dir/", "file.xml"), "file.xml");
        assert_eq!(resolve_uri("relative", "../other"), "../other");
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
