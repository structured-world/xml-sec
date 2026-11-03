//! Policy limits a parser enforces while it reads a document, in place of a
//! separate lexical pass over the source before it.
//!
//! The counts follow the semantic tree both backends build: the document root
//! is a node, a run of character data (text, references and CDATA sections
//! that no markup separates) is one node, and whitespace outside the document
//! element is none. An element applies its namespace declarations, then counts
//! as a node, then as a level of nesting, and is refused at the first of these
//! limits it passes, before the parser allocates it.

use super::ParseError;
use super::storage::Values;
use super::storage::names::{NameStorage, Names};

/// The structural limits of one parse.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParseLimits {
    /// Semantic nodes, the document root included.
    pub(crate) nodes: u32,
    /// Element nesting.
    pub(crate) depth: usize,
    /// Namespace bindings a document declares that are in scope at once.
    pub(crate) namespace_bindings: usize,
}

/// The limit a parse stopped at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LimitRefusal {
    Nodes,
    Depth { maximum: usize, actual: usize },
    NamespaceBindings { maximum: usize, actual: usize },
}

/// Counts a document against its [`ParseLimits`] as a parser reports what it
/// reads.
pub(crate) struct LimitCounter<S: NameStorage> {
    limits: ParseLimits,
    nodes: u32,
    depth: usize,
    in_character_data: bool,
    /// Prefixes bound in scope, the default namespace as the empty prefix.
    active: S::Names<S::Text, ()>,
    peak_namespace_bindings: usize,
    /// Each open element's binding changes, as a prefix and whether it was
    /// bound before the element.
    scopes: S::Values<S::Values<(S::Text, bool)>>,
    storage: S,
    refusal: Option<LimitRefusal>,
}

impl<S: NameStorage> LimitCounter<S> {
    pub(crate) fn new(limits: ParseLimits, storage: S) -> Result<Self, ParseError> {
        Ok(Self {
            limits,
            // The document root.
            nodes: 1,
            depth: 0,
            in_character_data: false,
            active: storage.names(),
            peak_namespace_bindings: 0,
            scopes: storage.values(0)?,
            storage,
            refusal: None,
        })
    }

    /// The limit the parse stopped at, if it stopped at one.
    pub(crate) fn refusal(&self) -> Option<LimitRefusal> {
        self.refusal
    }

    /// The most namespace bindings the document had in scope at once.
    pub(crate) fn peak_namespace_bindings(&self) -> usize {
        self.peak_namespace_bindings
    }

    /// Record `refusal` and return the error that stops the parser.
    fn refuse(&mut self, refusal: LimitRefusal) -> ParseError {
        self.refusal = Some(refusal);
        match refusal {
            LimitRefusal::Nodes => ParseError::NodesLimitReached,
            LimitRefusal::Depth { maximum, actual } => {
                ParseError::DepthLimitReached { maximum, actual }
            }
            LimitRefusal::NamespaceBindings { maximum, actual } => {
                ParseError::NamespaceBindingLimitReached { maximum, actual }
            }
        }
    }

    fn count(&mut self) -> Result<(), ParseError> {
        // A count past `u32::MAX` is past any limit.
        match self.nodes.checked_add(1) {
            Some(nodes) if nodes <= self.limits.nodes => {
                self.nodes = nodes;
                Ok(())
            }
            _ => Err(self.refuse(LimitRefusal::Nodes)),
        }
    }

    /// Markup that is no node and ends a run of character data: an XML
    /// declaration, or whitespace outside the document element.
    pub(crate) fn markup(&mut self) {
        self.in_character_data = false;
    }

    /// A comment or processing instruction.
    pub(crate) fn node(&mut self) -> Result<(), ParseError> {
        self.in_character_data = false;
        self.count()
    }

    /// Character data, a node unless it continues a run.
    pub(crate) fn character_data(&mut self) -> Result<(), ParseError> {
        if self.in_character_data {
            return Ok(());
        }
        self.in_character_data = true;
        self.count()
    }

    /// An element's start tag with the namespace declarations it makes, each
    /// a prefix (empty for the default namespace) and whether it undeclares
    /// it; an empty-element tag closes at once.
    pub(crate) fn start_element<'d>(
        &mut self,
        declarations: impl Iterator<Item = (&'d str, bool)>,
        empty: bool,
    ) -> Result<(), ParseError> {
        self.in_character_data = false;
        let storage = self.storage;
        let mut changes = storage.values(0)?;
        for (prefix, undeclares) in declarations {
            storage.charge(1)?;
            let was_active = if undeclares {
                self.active.remove(prefix, storage)?.is_some()
            } else if self.active.get(prefix, storage)?.is_some() {
                true
            } else {
                self.active.insert(storage.text(prefix)?, ())?;
                false
            };
            changes.push((storage.text(prefix)?, was_active))?;
        }
        let actual = self.active.len();
        self.peak_namespace_bindings = self.peak_namespace_bindings.max(actual);
        let maximum = self.limits.namespace_bindings;
        if actual > maximum {
            return Err(self.refuse(LimitRefusal::NamespaceBindings { maximum, actual }));
        }
        self.count()?;
        // Nesting is bounded by the source length, far below `usize::MAX`.
        let depth = self.depth + 1;
        if depth > self.limits.depth {
            let maximum = self.limits.depth;
            return Err(self.refuse(LimitRefusal::Depth {
                maximum,
                actual: depth,
            }));
        }
        if empty {
            self.restore(changes)
        } else {
            self.depth = depth;
            self.scopes.push(changes)
        }
    }

    /// The end tag of the innermost open element.
    pub(crate) fn end_element(&mut self) -> Result<(), ParseError> {
        self.in_character_data = false;
        debug_assert!(self.depth > 0, "an end tag follows its start tag");
        // The parser reports an end tag only for an element it opened.
        self.depth -= 1;
        match self.scopes.pop() {
            Some(changes) => self.restore(changes),
            None => Ok(()),
        }
    }

    fn restore(&mut self, mut changes: S::Values<(S::Text, bool)>) -> Result<(), ParseError> {
        let storage = self.storage;
        while let Some((prefix, was_active)) = changes.pop() {
            storage.charge(1)?;
            if was_active {
                if self.active.get(prefix.as_ref(), storage)?.is_none() {
                    self.active.insert(prefix, ())?;
                }
            } else {
                self.active.remove(prefix.as_ref(), storage)?;
            }
        }
        Ok(())
    }
}
