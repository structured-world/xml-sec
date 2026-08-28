//! Backend-neutral XML semantic tree contract.
//!
//! Exactly one parser backend builds this tree. All XML Security semantics are
//! implemented above it, so selecting a backend cannot change C14N, XPath,
//! XMLDSig, or XMLEnc behavior.

#[cfg(feature = "xml-backend-differential")]
mod differential;
mod preflight;
#[cfg(any(
    feature = "xml-backend-roxmltree",
    feature = "xml-backend-differential"
))]
mod roxmltree;
mod tree;
#[cfg(any(feature = "xml-backend-xmloxide", feature = "xml-backend-differential"))]
mod xmloxide;

use std::fmt;

use self::preflight::LexicalPreflight;

#[cfg(feature = "xml-backend-differential")]
use self::differential::DifferentialBackend as SelectedBackend;
#[cfg(feature = "xml-backend-roxmltree")]
use self::roxmltree::RoxmltreeBackend as SelectedBackend;
#[cfg(feature = "xml-backend-xmloxide")]
use self::xmloxide::XmloxideBackend as SelectedBackend;

pub use tree::{
    Ancestors, Attribute, Attributes, Children, Descendants, Document, ExpandedName, Namespace,
    Namespaces, Node, NodeId, NodeType, PI,
};

/// Parser-neutral options used after bounded lexical preflight.
#[derive(Clone, Copy, Debug)]
pub struct ParsingOptions {
    /// Whether an internal DTD subset is accepted.
    pub allow_dtd: bool,
    /// Maximum retained semantic node count.
    pub nodes_limit: u32,
}

impl Default for ParsingOptions {
    fn default() -> Self {
        Self {
            allow_dtd: false,
            nodes_limit: u32::MAX,
        }
    }
}

/// Stable parser-neutral XML parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The absolute source-document byte ceiling was exceeded.
    ByteLimitReached {
        /// Maximum accepted UTF-8 source length.
        maximum: usize,
        /// Source length presented by the caller.
        actual: usize,
    },
    /// A DTD was found while DTD processing was disabled.
    DtdDetected,
    /// The retained semantic node ceiling was exceeded.
    NodesLimitReached,
    /// The absolute general-entity substitution ceiling was exceeded.
    EntityExpansionLimitReached {
        /// Maximum substitutions accepted for one document.
        maximum: u32,
        /// First substitution beyond the ceiling.
        actual: u32,
    },
    /// The absolute entity replacement-work ceiling was exceeded.
    EntityExpansionWorkLimitReached {
        /// Maximum replacement bytes traversed for one document.
        maximum: usize,
        /// First cumulative replacement size beyond the ceiling.
        actual: usize,
    },
    /// The source-position sidecar reached its absolute allocation ceiling.
    SourcePositionLimitReached {
        /// Maximum lexical positions retained for one document.
        maximum: usize,
        /// First lexical position beyond the ceiling.
        actual: usize,
    },
    /// The absolute XML element nesting ceiling was exceeded.
    DepthLimitReached {
        /// Maximum accepted element depth.
        maximum: usize,
        /// First observed depth beyond the ceiling.
        actual: usize,
    },
    /// The selected backend rejected malformed XML.
    Backend {
        /// Compile-time selected backend name.
        backend: &'static str,
        /// Backend diagnostic retained for troubleshooting.
        message: String,
    },
    /// The two parsers produced different retained XML semantics.
    BackendDivergence {
        /// Bounded diagnostic identifying the divergent semantic component.
        reason: String,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteLimitReached { maximum, actual } => {
                write!(
                    formatter,
                    "XML byte limit reached: maximum {maximum}, actual {actual}"
                )
            }
            Self::DtdDetected => formatter.write_str("DTD detected"),
            Self::NodesLimitReached => formatter.write_str("nodes limit reached"),
            Self::EntityExpansionLimitReached { maximum, actual } => write!(
                formatter,
                "XML entity expansion limit {maximum} exceeded at expansion {actual}"
            ),
            Self::EntityExpansionWorkLimitReached { maximum, actual } => write!(
                formatter,
                "XML entity expansion-work limit {maximum} bytes exceeded at {actual} bytes"
            ),
            Self::SourcePositionLimitReached { maximum, actual } => write!(
                formatter,
                "XML source-position limit {maximum} exceeded at position {actual}"
            ),
            Self::DepthLimitReached { maximum, actual } => {
                write!(
                    formatter,
                    "XML depth limit {maximum} exceeded at depth {actual}"
                )
            }
            Self::Backend { backend, message } => {
                write!(formatter, "{backend} rejected XML: {message}")
            }
            Self::BackendDivergence { reason } => {
                write!(formatter, "XML backend semantic divergence: {reason}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

trait XmlBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError>;
}

/// Stable parser-independent identity of a semantic tree node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SemanticNodeId(u32);

impl SemanticNodeId {
    pub(super) const fn new(raw: u32) -> Self {
        Self(raw)
    }
    pub(super) const fn raw(self) -> u32 {
        self.0
    }
}

/// Identity portion of the semantic contract used by owned documents.
pub(crate) trait SemanticDocument {
    type Node<'a>: Copy
    where
        Self: 'a;
    fn node(&self, id: SemanticNodeId) -> Option<Self::Node<'_>>;
    fn node_id<'a>(&'a self, node: Self::Node<'a>) -> SemanticNodeId;
}

impl SemanticDocument for Document<'_> {
    type Node<'a>
        = Node<'a, 'a>
    where
        Self: 'a;

    fn node(&self, id: SemanticNodeId) -> Option<Self::Node<'_>> {
        self.get_node(NodeId::from(id.raw()))
    }

    fn node_id<'a>(&'a self, node: Self::Node<'a>) -> SemanticNodeId {
        SemanticNodeId::new(node.id().get())
    }
}
