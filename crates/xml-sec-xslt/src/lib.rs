#![deny(unsafe_code)]
#![forbid(clippy::unwrap_used)]
//! A parser-independent XSLT 1.0 compiler and execution engine.
//!
//! Compilation and execution are separate: [`Compiler`] produces an immutable
//! [`Stylesheet`] which can be shared between threads and applied repeatedly.
//! The crate performs no implicit filesystem, network, or environment access.
//! Principal and resolver-provided XML bytes honor declarations, BOMs, UTF-16
//! initial patterns, and explicit encoding metadata through [`Document::parse_bytes`]
//! and [`Compiler::compile_bytes`]. Untrusted source documents use
//! [`Document::parse_with_budget`] or [`Document::parse_bytes_with_budget`] so decoded bytes,
//! arena nodes, element depth, entity references, and namespace-scope storage are rejected before
//! their corresponding work or allocations.
//!
//! ```
//! use std::sync::Arc;
//! use xml_sec_xslt::{CompileBudget, Compiler, NoResolver};
//!
//! # fn main() -> Result<(), xml_sec_xslt::Error> {
//! let stylesheet = Compiler::new(
//!     Arc::new(NoResolver),
//!     CompileBudget::new(64 * 1024, 0, 128, 256 * 1024),
//! ).compile(
//!     r#"<xsl:stylesheet version="1.0"
//!          xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
//!          <xsl:template match="/"><result/></xsl:template>
//!        </xsl:stylesheet>"#,
//!     None,
//! )?;
//! assert_eq!(stylesheet.resource_identities(), []);
//! # Ok(())
//! # }
//! ```

mod budget;
mod compiler;
mod environment;
mod error;
mod expression;
mod exslt_date;
mod lexical;
mod model;
mod resolver;
mod runtime;
mod serializer;
mod value;
mod xpath;

pub use budget::{BudgetKind, CompileBudget, ExecutionBudget, ParseBudget};
pub use compiler::{Compiler, Stylesheet};
pub use environment::{Clock, ExecutionEnvironment, ExtensionPolicy, FixedClock, SystemClock};
pub use error::{Error, ErrorKind, Result};
pub use model::{
    Attribute, Document, ExpandedName, Namespace, Node, NodeId, NodeKind, NodeReference,
};
pub use resolver::{
    NoResolver, ResolvePurpose, ResolveRequest, ResolvedResource, Resolver, ResourceIdentity,
};
pub use runtime::{
    ExecutionOptions, Message, Parameters, SecondaryOutput, SourceProcessing, TransformResult,
};
pub use serializer::{OutputDefinition, OutputMethod, SerializedOutput};
pub use value::Value;
