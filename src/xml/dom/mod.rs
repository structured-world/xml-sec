//! Backend-neutral XML semantic tree contract.
//!
//! One explicitly selected parser backend builds this tree. All XML Security semantics are
//! implemented above it, so selecting a backend cannot change C14N, `XPath`,
//! `XMLDSig`, or `XMLEnc` behavior.

#[cfg(feature = "benchmark-internals")]
pub(crate) mod benchmark;
#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
mod differential;
mod preflight;
#[cfg(feature = "xml-backend-roxmltree")]
mod roxmltree;
#[doc(hidden)]
pub mod storage;
mod tree;
#[cfg(feature = "xml-backend-xmloxide")]
mod xmloxide;

use alloc::string::String;
use core::fmt;

use self::preflight::LexicalPreflight;
#[cfg(feature = "xml-backend-xmloxide")]
pub(crate) use self::preflight::{PositionRecorder, SourceKind, SourceNode};

pub use tree::{
    Ancestors, Attribute, Attributes, Children, Descendants, Document, ExpandedName, Namespace,
    Namespaces, Node, NodeId, NodeType, PI, XmlIdError,
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

/// XML parser implementation selected for one document or operation.
///
/// Cargo features control which implementations are compiled. Selecting an
/// implementation absent from a thin build fails explicitly; no parser
/// fallback is performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XmlBackend {
    /// Parse with the xmloxide adapter.
    Xmloxide,
    /// Parse with the roxmltree adapter.
    Roxmltree,
    /// Parse with both adapters and fail closed unless their semantic arenas agree.
    Differential,
}

impl XmlBackend {
    pub(crate) const fn build_default() -> Self {
        if cfg!(feature = "xml-backend-differential") {
            Self::Differential
        } else if cfg!(feature = "xml-backend-xmloxide") {
            Self::Xmloxide
        } else {
            Self::Roxmltree
        }
    }

    /// Returns whether this backend can run in the current build.
    #[must_use]
    pub const fn is_available(self) -> bool {
        match self {
            Self::Xmloxide => cfg!(feature = "xml-backend-xmloxide"),
            Self::Roxmltree => cfg!(feature = "xml-backend-roxmltree"),
            Self::Differential => cfg!(all(
                feature = "xml-backend-xmloxide",
                feature = "xml-backend-roxmltree"
            )),
        }
    }

    /// Iterate over every runtime mode available in this build.
    pub fn available() -> impl Iterator<Item = Self> {
        [Self::Xmloxide, Self::Roxmltree, Self::Differential]
            .into_iter()
            .filter(|backend| backend.is_available())
    }

    /// Whether this parse needs no lexical scan: xmloxide knows every source
    /// range, and only a DOCTYPE, whose keyword is case-sensitive (XML 1.0
    /// production 28), brings declarations and entity expansion.
    fn records_positions(self, input: &str) -> bool {
        cfg!(feature = "xml-backend-xmloxide")
            && self == Self::Xmloxide
            && !input.contains("<!DOCTYPE")
    }

    fn parse<'input>(
        self,
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        match self {
            Self::Xmloxide => parse_with_xmloxide(input, options, preflight),
            Self::Roxmltree => parse_with_roxmltree(input, options, preflight),
            Self::Differential => parse_differentially(input, options, preflight),
        }
    }

    #[cfg(feature = "xmldsig")]
    fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
        self,
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight<'input, storage::Accounted<'w, W>>,
        storage: storage::Accounted<'w, W>,
    ) -> Result<Document<'input, storage::Accounted<'w, W>>, AccountedParseError> {
        match self {
            Self::Xmloxide => {
                #[cfg(feature = "xml-backend-xmloxide")]
                return xmloxide::XmloxideBackend::parse_in(input, options, preflight, storage);
                #[cfg(not(feature = "xml-backend-xmloxide"))]
                Err(ParseError::BackendUnavailable { backend: self }.into())
            }
            Self::Roxmltree => {
                #[cfg(feature = "xml-backend-roxmltree")]
                return roxmltree::RoxmltreeBackend::parse_in(input, options, preflight, storage);
                #[cfg(not(feature = "xml-backend-roxmltree"))]
                Err(ParseError::BackendUnavailable { backend: self }.into())
            }
            Self::Differential => {
                #[cfg(all(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree"))]
                return differential::parse_in(input, options, preflight, storage);
                #[cfg(not(all(
                    feature = "xml-backend-xmloxide",
                    feature = "xml-backend-roxmltree"
                )))]
                Err(ParseError::BackendUnavailable { backend: self }.into())
            }
        }
    }
}

fn parse_with_xmloxide<'input>(
    input: &'input str,
    options: ParsingOptions,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    #[cfg(feature = "xml-backend-xmloxide")]
    return xmloxide::XmloxideBackend::parse(input, options, preflight);
    #[cfg(not(feature = "xml-backend-xmloxide"))]
    {
        let _ = (input, options, preflight);
        Err(ParseError::BackendUnavailable {
            backend: XmlBackend::Xmloxide,
        })
    }
}

fn parse_with_roxmltree<'input>(
    input: &'input str,
    options: ParsingOptions,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    #[cfg(feature = "xml-backend-roxmltree")]
    return roxmltree::RoxmltreeBackend::parse(input, options, preflight);
    #[cfg(not(feature = "xml-backend-roxmltree"))]
    {
        let _ = (input, options, preflight);
        Err(ParseError::BackendUnavailable {
            backend: XmlBackend::Roxmltree,
        })
    }
}

fn parse_differentially<'input>(
    input: &'input str,
    options: ParsingOptions,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    #[cfg(all(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree"))]
    return differential::DifferentialBackend::parse(input, options, preflight);
    #[cfg(not(all(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")))]
    {
        let _ = (input, options, preflight);
        Err(ParseError::BackendUnavailable {
            backend: XmlBackend::Differential,
        })
    }
}

impl Default for XmlBackend {
    fn default() -> Self {
        Self::build_default()
    }
}

/// Parser failure retaining labels in their admitted allocation account.
///
/// This is error transport for scoped parsing, not a different XML grammar.
#[cfg(feature = "xmldsig")]
#[derive(Debug, thiserror::Error)]
pub enum AccountedParseError {
    /// Backend-neutral structural or resource refusal.
    #[error("{0}")]
    Semantic(#[from] ParseError),
    /// Original lexical failure with its completed, paid diagnostic labels.
    #[error("{0}")]
    Lexical(
        #[source]
        crate::xml_input::lexical::Error<
            structured_asn1::memory::OwnedText,
            structured_asn1::memory::MemoryError,
        >,
    ),
    /// Original roxmltree failure with its completed, paid diagnostic labels.
    #[cfg(feature = "xml-backend-roxmltree")]
    #[error("{0}")]
    Roxmltree(#[source] crate::parser_roxmltree::Error<structured_asn1::memory::OwnedText>),
    /// Original xmloxide diagnostics retain their actual allocation charges.
    #[cfg(feature = "xml-backend-xmloxide")]
    #[error("{0}")]
    Xmloxide(
        #[source]
        crate::parser_xmloxide::error::ParseError<
            structured_asn1::memory::OwnedText,
            structured_asn1::memory::OwnedVec<
                crate::parser_xmloxide::error::ParseDiagnostic<structured_asn1::memory::OwnedText>,
            >,
        >,
    ),
    /// Semantic disagreement with its completed, paid diagnostic.
    #[error("XML backend divergence: {0}")]
    Divergence(structured_asn1::memory::OwnedText),
}

/// Stable parser-neutral XML parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The semantic tree could not acquire its requested allocation.
    AllocationFailed,
    /// The current query refused tree construction work or storage.
    #[cfg(feature = "xmldsig")]
    SharedExecution(structured_asn1::memory::MemoryError),
    /// The requested parser implementation was not compiled into this build.
    BackendUnavailable {
        /// Runtime selection that cannot be satisfied.
        backend: XmlBackend,
    },
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
    /// The absolute in-scope namespace-binding ceiling was exceeded.
    NamespaceBindingLimitReached {
        /// Maximum accepted user-declared bindings in scope at once.
        maximum: usize,
        /// First in-scope binding count beyond the ceiling.
        actual: usize,
    },
    /// A backend node does not match the original lexical source sidecar.
    SourceMapMismatch {
        /// Expected fixed lexical node kind.
        expected: &'static str,
        /// Observed fixed lexical node kind, or end of stream.
        found: &'static str,
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

#[cfg(feature = "xmldsig")]
impl From<structured_asn1::memory::MemoryError> for ParseError {
    fn from(error: structured_asn1::memory::MemoryError) -> Self {
        Self::SharedExecution(error)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed => formatter.write_str("XML tree allocation failed"),
            #[cfg(feature = "xmldsig")]
            Self::SharedExecution(error) => write!(formatter, "XML tree execution: {error}"),
            Self::BackendUnavailable { backend } => {
                write!(
                    formatter,
                    "XML backend {backend:?} is not compiled into this build"
                )
            }
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
            Self::NamespaceBindingLimitReached { maximum, actual } => write!(
                formatter,
                "XML namespace binding limit {maximum} exceeded at {actual} active bindings"
            ),
            Self::SourceMapMismatch { expected, found } => write!(
                formatter,
                "xmloxide-source-map rejected XML: expected {expected}, found {found}"
            ),
            Self::Backend { backend, message } => {
                write!(formatter, "{backend} rejected XML: {message}")
            }
            Self::BackendDivergence { reason } => {
                write!(formatter, "XML backend semantic divergence: {reason}")
            }
        }
    }
}

impl core::error::Error for ParseError {}

trait XmlBackendImplementation {
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
