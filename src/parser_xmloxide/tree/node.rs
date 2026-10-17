//! Node type definitions.
//!
//! The `NodeKind` enum represents all node types in an XML document tree,
//! corresponding to libxml2's `xmlElementType`. Each variant carries the
//! node-type-specific payload (e.g., element name and attributes, text content).

use super::Attribute;
use crate::xml::dom::storage::{Native, Storage};

/// The kind of an XML node and its associated data.
///
/// This enum carries the payload for each node type. Navigation links
/// (parent, children, siblings) are stored in `NodeData`, not here.
#[derive(Clone)]
pub enum NodeKind<S: Storage = Native> {
    /// The document node — there is exactly one per `Document`.
    Document,

    /// An element node, e.g., `<div class="x">`.
    Element {
        /// The element's local name (or full `QName` before namespace resolution).
        name: S::Text,
        /// Namespace prefix (e.g., `"svg"` in `svg:rect`), if any.
        prefix: Option<S::Text>,
        /// Namespace URI after resolution, if any.
        namespace: Option<S::Text>,
        /// Attributes on this element.
        attributes: S::Values<Attribute<S>>,
    },

    /// A text node containing character data.
    Text {
        /// The text content (already decoded — character references resolved).
        content: S::Text,
    },

    /// A CDATA section, e.g., `<![CDATA[...]]>`.
    CData {
        /// The CDATA content (no escaping applied).
        content: S::Text,
    },

    /// A comment node, e.g., `<!-- ... -->`.
    Comment {
        /// The comment text (without the `<!--` and `-->` delimiters).
        content: S::Text,
    },

    /// A processing instruction, e.g., `<?target data?>`.
    ProcessingInstruction {
        /// The PI target (e.g., `"xml-stylesheet"`).
        target: S::Text,
        /// The PI data, if any.
        data: Option<S::Text>,
    },

    /// An entity reference node (e.g., `&amp;` when not expanded).
    EntityRef {
        /// The entity name (without `&` and `;`).
        name: S::Text,
        /// The expanded value of the entity (used for `text_content()`).
        value: Option<S::Text>,
    },

    /// A document type declaration node, e.g., `<!DOCTYPE html>`.
    ///
    /// See XML 1.0 §2.8: `[28]` doctypedecl
    DocumentType {
        /// The root element name declared in the DOCTYPE.
        name: S::Text,
        /// The SYSTEM identifier (URI), if any.
        system_id: Option<S::Text>,
        /// The PUBLIC identifier, if any.
        public_id: Option<S::Text>,
        /// The serialized internal subset content (between `[` and `]`), if any.
        internal_subset: Option<S::Text>,
    },
}

impl<S: Storage> std::fmt::Debug for NodeKind<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document => f.write_str("Document"),
            Self::Element {
                name,
                prefix,
                namespace,
                attributes,
            } => f
                .debug_struct("Element")
                .field("name", name)
                .field("prefix", prefix)
                .field("namespace", namespace)
                .field("attributes", &&attributes[..])
                .finish(),
            Self::Text { content } => f.debug_struct("Text").field("content", content).finish(),
            Self::CData { content } => f.debug_struct("CData").field("content", content).finish(),
            Self::Comment { content } => {
                f.debug_struct("Comment").field("content", content).finish()
            }
            Self::ProcessingInstruction { target, data } => f
                .debug_struct("ProcessingInstruction")
                .field("target", target)
                .field("data", data)
                .finish(),
            Self::EntityRef { name, value } => f
                .debug_struct("EntityRef")
                .field("name", name)
                .field("value", value)
                .finish(),
            Self::DocumentType {
                name,
                system_id,
                public_id,
                internal_subset,
            } => f
                .debug_struct("DocumentType")
                .field("name", name)
                .field("system_id", system_id)
                .field("public_id", public_id)
                .field("internal_subset", internal_subset)
                .finish(),
        }
    }
}
