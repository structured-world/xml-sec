//! DTD (Document Type Definition) data model, parser, and validator.
//!
//! This module implements DTD processing as defined in XML 1.0 (Fifth Edition)
//! sections 2.8, 3.2, 3.3, 3.4, and 4.2. It provides:
//!
//! - A data model for DTD declarations (elements, attributes, entities, notations)
//! - A parser that processes DTD internal subset content
//! - A validator that checks document conformance against a parsed DTD
//!
//! # Content Model Matching
//!
//! The validator implements deterministic content model matching for:
//! - `EMPTY`: element must have no element or text children
//! - `ANY`: any content is allowed
//! - Mixed content `(#PCDATA|a|b)*`: text and listed elements in any order
//! - Element content with sequences `(a,b,c)`, choices `(a|b|c)`, and
//!   occurrence indicators `?`, `*`, `+`
//!
//! See XML 1.0 section 3.2 for the full content model specification.

use std::collections::HashSet;
use std::fmt;

use crate::parser_xmloxide::error::ParseError;
use crate::parser_xmloxide::parser::input::ParserInput;
use crate::parser_xmloxide::tree::{Document, NodeId, NodeKind};
use crate::xml::dom::storage::names::{NameStorage, Names};
use crate::xml::dom::storage::{Native, Storage, Values};

use super::{ValidationError, ValidationResult};

// ---------------------------------------------------------------------------
// DTD Data Model
// ---------------------------------------------------------------------------

/// A parsed DTD containing all declarations from the internal subset.
///
/// This is the result of [`parse_dtd`] and serves as input to [`validate`].
pub struct Dtd<S: NameStorage = Native> {
    /// Element declarations, keyed by element name.
    pub elements: S::Names<S::Text, ElementDecl<S>>,
    /// Attribute declarations, keyed by `(element_name, attribute_name)`.
    pub attributes: S::Names<S::Text, S::Values<AttributeDecl<S>>>,
    /// General entity declarations, keyed by entity name.
    pub entities: S::Names<S::Text, EntityDecl<S>>,
    /// Parameter entity declarations, keyed by entity name.
    pub param_entities: S::Names<S::Text, EntityDecl<S>>,
    /// Notation declarations, keyed by notation name.
    pub notations: S::Names<S::Text, NotationDecl<S>>,
    /// Ordered list of all declarations (preserving source order and comments).
    pub declarations: S::Values<DtdDeclaration<S>>,
}

impl<S: NameStorage> Dtd<S> {
    fn with_storage(storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self {
            elements: storage.names(),
            attributes: storage.names(),
            entities: storage.names(),
            param_entities: storage.names(),
            notations: storage.names(),
            declarations: storage.values(0)?,
        })
    }
}
impl Default for Dtd {
    fn default() -> Self {
        Self::with_storage(Native).expect("empty native DTD does not allocate")
    }
}
impl fmt::Debug for Dtd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dtd")
            .field("elements", &self.elements)
            .field("attributes", &self.attributes)
            .field("entities", &self.entities)
            .field("param_entities", &self.param_entities)
            .field("notations", &self.notations)
            .field("declarations", &self.declarations)
            .finish()
    }
}

/// A single DTD declaration, preserving source order for re-serialization.
pub enum DtdDeclaration<S: Storage = Native> {
    /// An element declaration.
    Element(ElementDecl<S>),
    /// A single attribute declaration (one per attribute, even if the source
    /// used a multi-attribute ATTLIST).
    Attlist(AttributeDecl<S>),
    /// A general entity declaration.
    Entity(EntityDecl<S>),
    /// A notation declaration.
    Notation(NotationDecl<S>),
    /// A comment.
    Comment(S::Text),
    /// A processing instruction.
    Pi(S::Text, Option<S::Text>),
}

/// An element declaration from `<!ELEMENT name content-model>`.
///
/// See XML 1.0 section 3.2.
pub struct ElementDecl<S: Storage = Native> {
    /// The element name.
    pub name: S::Text,
    /// The declared content model.
    pub content_model: ContentModel<S>,
}

/// The content model for an element declaration.
///
/// See XML 1.0 section 3.2 for the grammar:
/// - `contentspec ::= 'EMPTY' | 'ANY' | Mixed | children`
pub enum ContentModel<S: Storage = Native> {
    /// The element must have no children (no elements, no text).
    /// Declared as `<!ELEMENT name EMPTY>`.
    Empty,
    /// Any content is allowed.
    /// Declared as `<!ELEMENT name ANY>`.
    Any,
    /// Mixed content: text and optionally listed elements in any order.
    /// Declared as `<!ELEMENT name (#PCDATA)>` or `<!ELEMENT name (#PCDATA|a|b)*>`.
    ///
    /// The `Vec<String>` contains the allowed element names (empty for `#PCDATA` only).
    Mixed(S::Values<S::Text>),
    /// Element-only content following a content spec pattern.
    /// Declared as `<!ELEMENT name (a,b,c)>` etc.
    Children(ContentSpec<S>),
}

/// A content specification for element-only content models.
///
/// Represents the recursive structure of `(a,b)`, `(a|b)`, etc.
/// with occurrence indicators.
///
/// See XML 1.0 section 3.2.1 and 3.2.2.
pub struct ContentSpec<S: Storage = Native> {
    /// The content particle kind.
    pub kind: ContentSpecKind<S>,
    /// How many times this particle may occur.
    pub occurrence: Occurrence,
}

/// The kind of a content specification particle.
pub enum ContentSpecKind<S: Storage = Native> {
    /// A single named element, e.g., `a`.
    Name(S::Text),
    /// A sequence of particles, e.g., `(a, b, c)`.
    Seq(S::Values<ContentSpec<S>>),
    /// A choice among particles, e.g., `(a | b | c)`.
    Choice(S::Values<ContentSpec<S>>),
}

/// Occurrence indicator for a content particle.
///
/// See XML 1.0 section 3.2.1: `'?' | '*' | '+'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occurrence {
    /// Exactly once (no indicator).
    Once,
    /// Zero or one time (`?`).
    Optional,
    /// Zero or more times (`*`).
    ZeroOrMore,
    /// One or more times (`+`).
    OneOrMore,
}

/// An attribute declaration from `<!ATTLIST element-name attr-name type default>`.
///
/// See XML 1.0 section 3.3.
pub struct AttributeDecl<S: Storage = Native> {
    /// The element this attribute belongs to.
    pub element_name: S::Text,
    /// The attribute name.
    pub attribute_name: S::Text,
    /// The attribute type.
    pub attribute_type: AttributeType<S>,
    /// The default value specification.
    pub default: AttributeDefault<S>,
}

/// The type of an attribute as declared in `<!ATTLIST>`.
///
/// See XML 1.0 section 3.3.1.
pub enum AttributeType<S: Storage = Native> {
    /// Character data (`CDATA`).
    CData,
    /// A unique identifier (`ID`).
    Id,
    /// A reference to an ID (`IDREF`).
    IdRef,
    /// Space-separated list of ID references (`IDREFS`).
    IdRefs,
    /// An entity name (`ENTITY`).
    Entity,
    /// Space-separated list of entity names (`ENTITIES`).
    Entities,
    /// A name token (`NMTOKEN`).
    NmToken,
    /// Space-separated list of name tokens (`NMTOKENS`).
    NmTokens,
    /// A notation type with allowed notation names (`NOTATION (a|b|c)`).
    Notation(S::Values<S::Text>),
    /// An enumeration of allowed values (`(a|b|c)`).
    Enumeration(S::Values<S::Text>),
}

/// The default value specification for an attribute.
///
/// See XML 1.0 section 3.3.2.
pub enum AttributeDefault<S: Storage = Native> {
    /// The attribute is required (`#REQUIRED`).
    Required,
    /// The attribute is optional with no default (`#IMPLIED`).
    Implied,
    /// The attribute has a fixed value (`#FIXED "value"`).
    Fixed(S::Text),
    /// The attribute has a default value (`"value"`).
    Default(S::Text),
}

/// A general entity declaration.
///
/// See XML 1.0 section 4.2.
pub struct EntityDecl<S: Storage = Native> {
    /// The entity name.
    pub name: S::Text,
    /// The entity's value, either internal or external.
    pub kind: EntityKind<S>,
}

/// Whether an entity is internal (has a literal value) or external
/// (references an external resource).
pub enum EntityKind<S: Storage = Native> {
    /// Internal entity with a literal replacement text.
    Internal(S::Text),
    /// External entity identified by a system URI and optional public ID.
    External {
        /// The SYSTEM identifier (URI).
        system_id: S::Text,
        /// The PUBLIC identifier, if any.
        public_id: Option<S::Text>,
    },
}

/// A notation declaration from `<!NOTATION name ...>`.
///
/// See XML 1.0 section 4.7.
pub struct NotationDecl<S: Storage = Native> {
    /// The notation name.
    pub name: S::Text,
    /// The SYSTEM identifier, if any.
    pub system_id: Option<S::Text>,
    /// The PUBLIC identifier, if any.
    pub public_id: Option<S::Text>,
}

impl<S: Storage> ContentModel<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        storage.charge(1)?;
        Ok(match self {
            Self::Empty => Self::Empty,
            Self::Any => Self::Any,
            Self::Mixed(names) => Self::Mixed(copy_names(names, storage)?),
            Self::Children(spec) => Self::Children(spec.copy_in(storage)?),
        })
    }
}

fn copy_names<S: Storage>(
    names: &[S::Text],
    storage: S,
) -> Result<S::Values<S::Text>, crate::xml::dom::ParseError> {
    storage.charge(names.len())?;
    let mut copied = storage.values(names.len())?;
    for name in names {
        copied.push(storage.text(name)?)?;
    }
    Ok(copied)
}

impl<S: Storage> ContentSpec<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        // Only the parser creates particles. Its fixed content-model depth
        // ceiling bounds this traversal and subsequent owning destruction.
        storage.charge(1)?;
        let kind = match &self.kind {
            ContentSpecKind::Name(name) => ContentSpecKind::Name(storage.text(name)?),
            ContentSpecKind::Seq(items) | ContentSpecKind::Choice(items) => {
                storage.charge(items.len())?;
                let mut copied = storage.values(items.len())?;
                for item in &**items {
                    copied.push(item.copy_in(storage)?)?;
                }
                if matches!(self.kind, ContentSpecKind::Seq(_)) {
                    ContentSpecKind::Seq(copied)
                } else {
                    ContentSpecKind::Choice(copied)
                }
            }
        };
        Ok(Self {
            kind,
            occurrence: self.occurrence,
        })
    }
}

impl<S: Storage> ElementDecl<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self {
            name: storage.text(&self.name)?,
            content_model: self.content_model.copy_in(storage)?,
        })
    }
}

impl<S: Storage> AttributeDecl<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        let attribute_type = match &self.attribute_type {
            AttributeType::CData => AttributeType::CData,
            AttributeType::Id => AttributeType::Id,
            AttributeType::IdRef => AttributeType::IdRef,
            AttributeType::IdRefs => AttributeType::IdRefs,
            AttributeType::Entity => AttributeType::Entity,
            AttributeType::Entities => AttributeType::Entities,
            AttributeType::NmToken => AttributeType::NmToken,
            AttributeType::NmTokens => AttributeType::NmTokens,
            AttributeType::Notation(names) => AttributeType::Notation(copy_names(names, storage)?),
            AttributeType::Enumeration(names) => {
                AttributeType::Enumeration(copy_names(names, storage)?)
            }
        };
        let default = match &self.default {
            AttributeDefault::Required => AttributeDefault::Required,
            AttributeDefault::Implied => AttributeDefault::Implied,
            AttributeDefault::Fixed(value) => AttributeDefault::Fixed(storage.text(value)?),
            AttributeDefault::Default(value) => AttributeDefault::Default(storage.text(value)?),
        };
        Ok(Self {
            element_name: storage.text(&self.element_name)?,
            attribute_name: storage.text(&self.attribute_name)?,
            attribute_type,
            default,
        })
    }
}

impl<S: Storage> EntityDecl<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self {
            name: storage.text(&self.name)?,
            kind: match &self.kind {
                EntityKind::Internal(value) => EntityKind::Internal(storage.text(value)?),
                EntityKind::External {
                    system_id,
                    public_id,
                } => EntityKind::External {
                    system_id: storage.text(system_id)?,
                    public_id: storage.optional_text(public_id.as_deref())?,
                },
            },
        })
    }
}

impl<S: Storage> NotationDecl<S> {
    fn copy_in(&self, storage: S) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self {
            name: storage.text(&self.name)?,
            system_id: storage.optional_text(self.system_id.as_deref())?,
            public_id: storage.optional_text(self.public_id.as_deref())?,
        })
    }
}

impl<S: Storage> fmt::Display for ContentModel<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "EMPTY"),
            Self::Any => write!(f, "ANY"),
            Self::Mixed(names) => {
                if names.is_empty() {
                    write!(f, "(#PCDATA)")
                } else {
                    f.write_str("(#PCDATA")?;
                    for name in &**names {
                        write!(f, "|{name}")?;
                    }
                    f.write_str(")*")
                }
            }
            Self::Children(spec) => write!(f, "{spec}"),
        }
    }
}

impl<S: Storage> fmt::Display for ContentSpec<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ContentSpecKind::Name(name) => write!(f, "{name}")?,
            ContentSpecKind::Seq(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " , ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, ")")?;
            }
            ContentSpecKind::Choice(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " | ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, ")")?;
            }
        }
        match self.occurrence {
            Occurrence::Once => {}
            Occurrence::Optional => write!(f, "?")?,
            Occurrence::ZeroOrMore => write!(f, "*")?,
            Occurrence::OneOrMore => write!(f, "+")?,
        }
        Ok(())
    }
}

// The upstream validation/serialization API is native. Scoped construction
// does not require Clone, Debug or infallible formatting of its containers.
macro_rules! native_debug_struct {
    ($type:ident, $($field:ident),+ $(,)?) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($type))$(.field(stringify!($field), &self.$field))+.finish()
            }
        }
    };
}
native_debug_struct!(ElementDecl, name, content_model);
native_debug_struct!(ContentSpec, kind, occurrence);
native_debug_struct!(
    AttributeDecl,
    element_name,
    attribute_name,
    attribute_type,
    default
);
native_debug_struct!(EntityDecl, name, kind);
native_debug_struct!(NotationDecl, name, system_id, public_id);

impl fmt::Debug for ContentModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Any => f.write_str("Any"),
            Self::Mixed(values) => f.debug_tuple("Mixed").field(values).finish(),
            Self::Children(value) => f.debug_tuple("Children").field(value).finish(),
        }
    }
}
impl PartialEq for ContentModel {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) | (Self::Any, Self::Any) => true,
            (Self::Mixed(left), Self::Mixed(right)) => left == right,
            (Self::Children(left), Self::Children(right)) => left == right,
            _ => false,
        }
    }
}
impl PartialEq for ContentSpec {
    fn eq(&self, other: &Self) -> bool {
        self.occurrence == other.occurrence && self.kind == other.kind
    }
}
impl fmt::Debug for ContentSpecKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(value) => f.debug_tuple("Name").field(value).finish(),
            Self::Seq(values) => f.debug_tuple("Seq").field(values).finish(),
            Self::Choice(values) => f.debug_tuple("Choice").field(values).finish(),
        }
    }
}
impl PartialEq for ContentSpecKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Name(left), Self::Name(right)) => left == right,
            (Self::Seq(left), Self::Seq(right)) | (Self::Choice(left), Self::Choice(right)) => {
                left == right
            }
            _ => false,
        }
    }
}
impl fmt::Debug for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CData => f.write_str("CData"),
            Self::Id => f.write_str("Id"),
            Self::IdRef => f.write_str("IdRef"),
            Self::IdRefs => f.write_str("IdRefs"),
            Self::Entity => f.write_str("Entity"),
            Self::Entities => f.write_str("Entities"),
            Self::NmToken => f.write_str("NmToken"),
            Self::NmTokens => f.write_str("NmTokens"),
            Self::Notation(values) => f.debug_tuple("Notation").field(values).finish(),
            Self::Enumeration(values) => f.debug_tuple("Enumeration").field(values).finish(),
        }
    }
}
impl PartialEq for AttributeType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Notation(left), Self::Notation(right))
            | (Self::Enumeration(left), Self::Enumeration(right)) => left == right,
            (Self::Notation(_) | Self::Enumeration(_), _)
            | (_, Self::Notation(_) | Self::Enumeration(_)) => false,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}
impl fmt::Debug for AttributeDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Required => f.write_str("Required"),
            Self::Implied => f.write_str("Implied"),
            Self::Fixed(value) => f.debug_tuple("Fixed").field(value).finish(),
            Self::Default(value) => f.debug_tuple("Default").field(value).finish(),
        }
    }
}
impl PartialEq for AttributeDefault {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Required, Self::Required) | (Self::Implied, Self::Implied) => true,
            (Self::Fixed(left), Self::Fixed(right))
            | (Self::Default(left), Self::Default(right)) => left == right,
            _ => false,
        }
    }
}
impl fmt::Debug for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal(value) => f.debug_tuple("Internal").field(value).finish(),
            Self::External {
                system_id,
                public_id,
            } => f
                .debug_struct("External")
                .field("system_id", system_id)
                .field("public_id", public_id)
                .finish(),
        }
    }
}
impl fmt::Debug for DtdDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Element(value) => f.debug_tuple("Element").field(value).finish(),
            Self::Attlist(value) => f.debug_tuple("Attlist").field(value).finish(),
            Self::Entity(value) => f.debug_tuple("Entity").field(value).finish(),
            Self::Notation(value) => f.debug_tuple("Notation").field(value).finish(),
            Self::Comment(value) => f.debug_tuple("Comment").field(value).finish(),
            Self::Pi(target, data) => f.debug_tuple("Pi").field(target).field(data).finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// DTD Serializer
// ---------------------------------------------------------------------------

/// Serializes a parsed DTD's declarations into the internal subset format
/// used by libxml2.
///
/// Each declaration appears on its own line. The output does NOT include
/// the surrounding `[` and `]>` — the caller adds those.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn serialize_dtd(dtd: &Dtd) -> String {
    serialize_dtd_in(dtd, Native).expect("native DTD serialization allocation")
}

struct DtdOutput<S: Storage> {
    storage: S,
    text: S::Text,
}

impl<S: Storage> DtdOutput<S> {
    fn push_str(&mut self, value: &str) -> Result<(), crate::xml::dom::ParseError> {
        self.storage.append(&mut self.text, value)
    }
    fn push(&mut self, value: char) -> Result<(), crate::xml::dom::ParseError> {
        self.push_str(value.encode_utf8(&mut [0; 4]))
    }
    fn format(&mut self, value: fmt::Arguments<'_>) -> Result<(), crate::xml::dom::ParseError> {
        self.storage.format_into(&mut self.text, value)
    }
}

pub(crate) fn serialize_dtd_in<R: NameStorage, S: Storage>(
    dtd: &Dtd<R>,
    storage: S,
) -> Result<S::Text, crate::xml::dom::ParseError> {
    let mut out = DtdOutput {
        storage,
        text: storage.text("")?,
    };
    let mut last_was_comment = false;

    for decl in &*dtd.declarations {
        storage.charge(1)?;
        // Don't add a newline before declarations that immediately follow
        // a comment — the comment text already contains any needed whitespace.
        // libxml2 concatenates the comment closing `-->` and the next
        // declaration on the same line.
        if !last_was_comment {
            out.push('\n')?;
        }
        match decl {
            DtdDeclaration::Element(e) => {
                out.format(format_args!("<!ELEMENT {} ", e.name))?;
                write_content_model(&mut out, &e.content_model)?;
                out.push('>')?;
                last_was_comment = false;
            }
            DtdDeclaration::Attlist(a) => {
                out.format(format_args!(
                    "<!ATTLIST {} {} ",
                    a.element_name, a.attribute_name
                ))?;
                write_attribute_type(&mut out, &a.attribute_type)?;
                out.push(' ')?;
                write_attribute_default(&mut out, &a.default)?;
                out.push('>')?;
                last_was_comment = false;
            }
            DtdDeclaration::Entity(e) => {
                out.format(format_args!("<!ENTITY {}", e.name))?;
                match &e.kind {
                    EntityKind::Internal(value) => {
                        out.push(' ')?;
                        write_entity_value(&mut out, value)?;
                    }
                    EntityKind::External {
                        system_id,
                        public_id,
                    } => {
                        if let Some(pub_id) = public_id {
                            out.format(format_args!(" PUBLIC \"{pub_id}\" \"{system_id}\""))?;
                        } else {
                            out.format(format_args!(" SYSTEM \"{system_id}\""))?;
                        }
                    }
                }
                out.push('>')?;
                last_was_comment = false;
            }
            DtdDeclaration::Notation(n) => {
                out.format(format_args!("<!NOTATION {}", n.name))?;
                match (&n.public_id, &n.system_id) {
                    (Some(pub_id), Some(sys_id)) => {
                        out.format(format_args!(" PUBLIC \"{pub_id}\" \"{sys_id}\""))?;
                    }
                    (Some(pub_id), None) => {
                        out.format(format_args!(" PUBLIC \"{pub_id}\""))?;
                    }
                    (None, Some(sys_id)) => {
                        out.format(format_args!(" SYSTEM \"{sys_id}\""))?;
                    }
                    (None, None) => {}
                }
                out.push('>')?;
                last_was_comment = false;
            }
            DtdDeclaration::Comment(text) => {
                out.format(format_args!("<!--{text}-->"))?;
                last_was_comment = true;
            }
            DtdDeclaration::Pi(target, data) => {
                out.format(format_args!("<?{target}"))?;
                if let Some(d) = data {
                    out.format(format_args!(" {d}"))?;
                }
                out.push_str("?>")?;
                last_was_comment = false;
            }
        }
    }

    // libxml2 adds a newline before ]> unless the last item was a comment.
    if !last_was_comment && !dtd.declarations.is_empty() {
        out.push('\n')?;
    }

    Ok(out.text)
}

/// Writes a content model in libxml2's format.
fn write_content_model<R: Storage, S: Storage>(
    out: &mut DtdOutput<S>,
    model: &ContentModel<R>,
) -> Result<(), crate::xml::dom::ParseError> {
    match model {
        ContentModel::Empty => out.push_str("EMPTY")?,
        ContentModel::Any => out.push_str("ANY")?,
        ContentModel::Mixed(names) => {
            if names.is_empty() {
                out.push_str("(#PCDATA)")?;
            } else {
                out.push_str("(#PCDATA")?;
                for name in &**names {
                    out.format(format_args!(" | {name}"))?;
                }
                out.push_str(")*")?;
            }
        }
        ContentModel::Children(spec) => {
            out.format(format_args!("{spec}"))?;
        }
    }
    Ok(())
}

/// Writes an attribute type in libxml2's format.
fn write_attribute_type<R: Storage, S: Storage>(
    out: &mut DtdOutput<S>,
    attr_type: &AttributeType<R>,
) -> Result<(), crate::xml::dom::ParseError> {
    match attr_type {
        AttributeType::CData => out.push_str("CDATA")?,
        AttributeType::Id => out.push_str("ID")?,
        AttributeType::IdRef => out.push_str("IDREF")?,
        AttributeType::IdRefs => out.push_str("IDREFS")?,
        AttributeType::Entity => out.push_str("ENTITY")?,
        AttributeType::Entities => out.push_str("ENTITIES")?,
        AttributeType::NmToken => out.push_str("NMTOKEN")?,
        AttributeType::NmTokens => out.push_str("NMTOKENS")?,
        AttributeType::Notation(values) | AttributeType::Enumeration(values) => {
            if matches!(attr_type, AttributeType::Notation(_)) {
                out.push_str("NOTATION ")?;
            }
            out.push('(')?;
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    out.push_str(" | ")?;
                }
                out.push_str(v)?;
            }
            out.push(')')?;
        }
    }
    Ok(())
}

/// Writes an attribute default in libxml2's format.
fn write_attribute_default<R: Storage, S: Storage>(
    out: &mut DtdOutput<S>,
    default: &AttributeDefault<R>,
) -> Result<(), crate::xml::dom::ParseError> {
    match default {
        AttributeDefault::Required => out.push_str("#REQUIRED")?,
        AttributeDefault::Implied => out.push_str("#IMPLIED")?,
        AttributeDefault::Fixed(value) => {
            out.format(format_args!("#FIXED \"{value}\""))?;
        }
        AttributeDefault::Default(value) => {
            out.format(format_args!("\"{value}\""))?;
        }
    }
    Ok(())
}

/// Escapes an entity value for DTD serialization.
///
/// Entity references (`&name;`) and character references (`&#...;`) within
/// the value are preserved as-is (matching libxml2 behavior). Only standalone
/// `&` characters are escaped. The quote character is chosen to minimize
/// escaping: single quotes when the value contains double quotes.
fn write_entity_value<S: Storage>(
    out: &mut DtdOutput<S>,
    value: &str,
) -> Result<(), crate::xml::dom::ParseError> {
    // Quote selection, escaping/reference recognition, and reference UTF-8
    // validation are bounded passes over this actual entity value.
    for _ in 0..5 {
        out.storage.charge(value.len())?;
    }
    // Choose quote character: use single quotes if value contains double quotes
    // but not single quotes (avoids escaping). Otherwise use double quotes.
    let quote = if value.contains('"') && !value.contains('\'') {
        '\''
    } else {
        '"'
    };
    out.push(quote)?;

    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'&' {
            // Check if this is a valid entity or character reference — if so, pass through.
            if let Some(ref_end) = find_reference_end(bytes, i) {
                // Copy the reference as-is
                let ref_str = std::str::from_utf8(&bytes[i..=ref_end]).unwrap_or("&amp;");
                out.push_str(ref_str)?;
                i = ref_end + 1;
            } else {
                out.push_str("&amp;")?;
                i += 1;
            }
        } else if bytes[i] == b'%' {
            out.push_str("&#37;")?;
            i += 1;
        } else if bytes[i] == quote as u8 {
            if quote == '"' {
                out.push_str("&quot;")?;
            } else {
                out.push_str("&apos;")?;
            }
            i += 1;
        } else {
            // Push the char (may be multi-byte UTF-8)
            let ch = &value[i..];
            if let Some(c) = ch.chars().next() {
                out.push(c)?;
                i += c.len_utf8();
            } else {
                i += 1;
            }
        }
    }

    out.push(quote)?;
    Ok(())
}

/// Finds the end position (inclusive, the `;`) of an entity or character
/// reference starting at `start` in `bytes`. Returns `None` if the `&` at
/// `start` is not the beginning of a valid reference.
fn find_reference_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() || bytes[start] != b'&' {
        return None;
    }
    let mut i = start + 1;
    if i >= bytes.len() {
        return None;
    }

    if bytes[i] == b'#' {
        // Character reference: &#digits; or &#xhexdigits;
        i += 1;
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b'x' {
            i += 1;
            let digit_start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i == digit_start || i >= bytes.len() || bytes[i] != b';' {
                return None;
            }
        } else {
            let digit_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i == digit_start || i >= bytes.len() || bytes[i] != b';' {
                return None;
            }
        }
        Some(i)
    } else {
        // Named entity reference: &name;
        // Name must start with a name start char (letter or _)
        if !is_name_start_byte(bytes[i]) {
            return None;
        }
        i += 1;
        while i < bytes.len() && is_name_byte(bytes[i]) {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b';' {
            return None;
        }
        Some(i)
    }
}

/// Checks if a byte is valid as the start of an XML name.
fn is_name_start_byte(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}

/// Checks if a byte is valid within an XML name.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b'-' || b == b'.'
}

// ---------------------------------------------------------------------------
// DTD Parser
// ---------------------------------------------------------------------------

/// Parses a DTD internal subset string into a [`Dtd`] data structure.
///
/// The input should be the content from inside `<!DOCTYPE root [ ... ]>`,
/// i.e., just the internal subset without the surrounding brackets.
///
/// # Errors
///
/// Returns a `ParseError` if the DTD content is malformed.
///
/// # Examples
///
/// ```text,xml-sec-example
/// use xmloxide::validation::dtd::parse_dtd;
///
/// let dtd = parse_dtd("<!ELEMENT root (#PCDATA)>").unwrap();
/// assert!(dtd.elements.contains_key("root"));
/// ```
pub fn parse_dtd(input: &str) -> Result<Dtd, ParseError> {
    DtdParser::new(input).parse()
}

type DtdError<S> = ParseError<
    <S as Storage>::FrozenText,
    <S as Storage>::Values<
        crate::parser_xmloxide::error::ParseDiagnostic<<S as Storage>::FrozenText>,
    >,
>;

pub(crate) fn parse_dtd_in<S: NameStorage>(input: &str, storage: S) -> Result<Dtd<S>, DtdError<S>> {
    DtdParser::with_storage(input, storage)?.parse()
}

/// Maximum nesting depth for `<!ELEMENT>` content-model groups.
///
/// The iterative parser enforces this ceiling for the retained model's
/// formatting, copying and destruction as well as parsing (CWE-674).
const MAX_CONTENT_MODEL_DEPTH: u32 = 256;

/// Internal DTD parser state.
struct DtdParser<'a, S: NameStorage = Native> {
    input: ParserInput<'a, S>,
    dtd: Dtd<S>,
    storage: S,
}

impl<'a> DtdParser<'a> {
    fn new(input: &'a str) -> Self {
        Self::with_storage(input, Native).expect("empty native DTD does not allocate")
    }
}

impl<'a, S: NameStorage> DtdParser<'a, S> {
    fn with_storage(input: &'a str, storage: S) -> Result<Self, DtdError<S>> {
        Ok(Self {
            input: {
                let mut cursor = ParserInput::with_storage(input, storage)?;
                // DTD names share the XML grammar. The adapter's compiled
                // preflight, not a second parser default, owns name limits.
                cursor.set_max_name_length(usize::MAX);
                cursor
            },
            dtd: Dtd::with_storage(storage)?,
            storage,
        })
    }

    fn parse(mut self) -> Result<Dtd<S>, DtdError<S>> {
        loop {
            self.skip_whitespace()?;
            if self.at_end() {
                break;
            }

            if self.looking_at(b"<!--") {
                self.parse_comment_decl()?;
            } else if self.looking_at(b"<!ELEMENT") {
                self.parse_element_decl()?;
            } else if self.looking_at(b"<!ATTLIST") {
                self.parse_attlist_decl()?;
            } else if self.looking_at(b"<!ENTITY") {
                self.parse_entity_decl()?;
            } else if self.looking_at(b"<!NOTATION") {
                self.parse_notation_decl()?;
            } else if self.looking_at(b"<?") {
                self.parse_pi_decl()?;
            } else if self.peek() == Some(b'%') {
                // Parameter entity reference — skip it since we don't expand
                self.skip_pe_reference()?;
            } else {
                return Err(self.fatal(format_args!(
                    "unexpected character '{}' in DTD",
                    self.peek().map_or('?', |b| b as char)
                )));
            }
        }

        self.post_validate()?;

        Ok(self.dtd)
    }

    /// Post-parse validation checks that require the complete entity map.
    ///
    /// Detects entity recursion (WFC: No Recursion), validates that entity
    /// references in attribute defaults refer to internal parsed entities,
    /// and checks for `<` in entity replacement text used in attributes.
    fn post_validate(&self) -> Result<(), DtdError<S>> {
        // Check for entity recursion (WFC: No Recursion, XML 1.0 §4.1).
        // `safe` memoizes entities already proven acyclic so the walk is
        // linear in the total size of the entity declarations rather than
        // exponential in chain depth.
        let mut safe = self.storage.names();
        for (name, decl) in self.dtd.entities.entries(self.storage)? {
            if let EntityKind::Internal(ref value) = decl.kind {
                if safe.get(name.as_ref(), self.storage)?.is_some() {
                    continue;
                }
                let mut visited = self.storage.names();
                Names::insert(&mut visited, name.as_ref(), ())?;
                self.check_entity_recursion(value, &mut visited, &mut safe)?;
                Names::insert(&mut safe, name.as_ref(), ())?;
            }
        }

        // Check for parameter entity recursion (WFC: No Recursion, XML 1.0 §4.1).
        // PE values may contain encoded PE references via &#37; (which is '%').
        // After char ref expansion, if %name; appears in its own value, that's
        // direct or indirect recursion.
        let mut safe = self.storage.names();
        for (name, decl) in self.dtd.param_entities.entries(self.storage)? {
            if let EntityKind::Internal(ref value) = decl.kind {
                if safe.get(name.as_ref(), self.storage)?.is_some() {
                    continue;
                }
                let expanded = expand_char_refs_only(value, self.storage)?;
                let mut visited = self.storage.names();
                Names::insert(&mut visited, name.as_ref(), ())?;
                self.check_pe_recursion(&expanded, &mut visited, &mut safe)?;
                Names::insert(&mut safe, name.as_ref(), ())?;
            }
        }

        // Validate entity replacement text after character reference
        // expansion (XML 1.0 §4.5). Character references in entity
        // values are expanded at declaration time. The resulting
        // replacement text must be well-formed when re-parsed.
        for (name, decl) in self.dtd.entities.entries(self.storage)? {
            if let EntityKind::Internal(ref value) = decl.kind {
                self.validate_replacement_text(name.as_ref(), value)?;
            }
        }

        // Validate predefined entity redeclarations (XML 1.0 §4.6).
        // If lt, gt, amp, apos, or quot are declared, their replacement
        // text must be a character reference to the respective character.
        self.validate_predefined_entities()?;

        // Note: content production validation (XML 1.0 §4.3.2) is
        // performed at entity expansion time in the XML parser, not
        // here, because it only applies to entities that are actually
        // referenced in the document.

        // Validate entity references in ATTLIST defaults. `checked`
        // memoizes entities already validated so shared references are
        // walked once (the reference graph is acyclic at this point).
        let mut checked = self.storage.names();
        for (_, attrs) in self.dtd.attributes.entries(self.storage)? {
            self.storage.charge(attrs.len())?;
            for attr in &**attrs {
                let (AttributeDefault::Default(default_value)
                | AttributeDefault::Fixed(default_value)) = &attr.default
                else {
                    continue;
                };
                self.validate_attr_default_entities(default_value, &mut checked)?;
            }
        }

        Ok(())
    }

    /// Validates that predefined entity redeclarations (lt, gt, amp, apos,
    /// quot) use the correct character reference as replacement text.
    ///
    /// Per XML 1.0 §4.6: "If the entities lt or amp are declared, they MUST
    /// be declared as internal entities whose replacement text is a character
    /// reference to the respective character."
    fn validate_predefined_entities(&self) -> Result<(), DtdError<S>> {
        // Per XML 1.0 §4.6: lt and amp MUST use character references.
        // gt, apos, and quot may use either the literal character or a
        // character reference.
        let expected: &[(&str, &str, &[&str])] = &[
            ("lt", "<", &["&#60;", "&#x3C;", "&#x3c;"]),
            ("gt", ">", &[">", "&#62;", "&#x3E;", "&#x3e;"]),
            ("amp", "&", &["&#38;", "&#x26;"]),
            ("apos", "'", &["'", "&#39;", "&#x27;"]),
            ("quot", "\"", &["\"", "&#34;", "&#x22;"]),
        ];
        for &(name, _char_val, valid_refs) in expected {
            if let Some(decl) = self.dtd.entities.get(name, self.storage)? {
                match &decl.kind {
                    EntityKind::Internal(value) => {
                        // Check if the value is a valid character reference
                        // for this predefined entity.
                        for _ in valid_refs {
                            self.storage.charge(value.len())?;
                        }
                        if !valid_refs.iter().any(|r| *r == value.as_ref()) {
                            return Err(self.fatal(format_args!(
                                "predefined entity '{name}' must be declared as \
                                 a character reference (e.g., '{}')",
                                valid_refs[0]
                            )));
                        }
                    }
                    EntityKind::External { .. } => {
                        return Err(self.fatal(format_args!(
                            "predefined entity '{name}' must be an internal entity"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates entity replacement text after character reference
    /// expansion per XML 1.0 §4.5.
    ///
    /// Expands only character references in the entity value (not entity
    /// references), then checks the resulting replacement text for basic
    /// well-formedness: bare `&` characters from `&#38;` expansion that
    /// don't form valid references are rejected.
    fn validate_replacement_text(&self, entity_name: &str, value: &str) -> Result<(), DtdError<S>> {
        // Only check values that contain character references
        self.storage.charge(value.len())?;
        if !value.contains("&#") {
            return Ok(());
        }

        // Build replacement text by expanding only character references
        let replacement = expand_char_refs_only(value, self.storage)?;

        // Check for bare '&' in the replacement text that don't form
        // valid entity or character references
        self.storage.charge(replacement.len())?;
        let bytes = replacement.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'&' {
                i += 1;
                if i >= bytes.len() {
                    return Err(self.fatal(format_args!(
                        "entity '{entity_name}' replacement text contains \
                         bare '&' at end of text"
                    )));
                }
                if bytes[i] == b'#' {
                    // Character reference — check it's complete
                    i += 1;
                    let has_digits = if i < bytes.len() && bytes[i] == b'x' {
                        i += 1;
                        let start = i;
                        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                            i += 1;
                        }
                        i > start
                    } else {
                        let start = i;
                        while i < bytes.len() && bytes[i].is_ascii_digit() {
                            i += 1;
                        }
                        i > start
                    };
                    if !has_digits || i >= bytes.len() || bytes[i] != b';' {
                        return Err(self.fatal(format_args!(
                            "entity '{entity_name}' replacement text contains \
                             incomplete character reference"
                        )));
                    }
                    i += 1;
                } else if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b':' {
                    // Entity reference — skip name
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return Err(self.fatal(format_args!(
                            "entity '{entity_name}' replacement text contains \
                             incomplete entity reference"
                        )));
                    }
                    i += 1;
                } else {
                    return Err(self.fatal(format_args!(
                        "entity '{entity_name}' replacement text contains \
                         bare '&' not followed by a valid reference"
                    )));
                }
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Checks the declaration graph without using the native call stack.
    fn check_entity_recursion<'b>(
        &'b self,
        value: &'b str,
        visited: &mut S::Names<&'b str, ()>,
        safe: &mut S::Names<&'b str, ()>,
    ) -> Result<(), DtdError<S>> {
        // XML 1.0 §4.1 WFC No Recursion forbids direct and indirect cycles,
        // not deep acyclic graphs. Keep DFS continuation state on the heap.
        // https://www.w3.org/TR/2008/REC-xml-20081126/#norecursion
        let mut frames = self.storage.values(0)?;
        self.storage.charge(value.len())?;
        Values::push(&mut frames, (None, Self::extract_entity_refs(value)))?;
        while let Some((_, references)) = frames.last_mut() {
            let Some(ref_name) = references.next() else {
                if let Some((Some(name), _)) = frames.pop() {
                    visited.remove(name, self.storage)?;
                    Names::insert(safe, name, ())?;
                }
                continue;
            };
            if safe.get(ref_name, self.storage)?.is_some() {
                continue;
            }
            if visited.get(ref_name, self.storage)?.is_some() {
                return Err(self.fatal(format_args!("recursive entity reference: '{ref_name}'")));
            }
            if let Some(decl) = self.dtd.entities.get(ref_name, self.storage)?
                && let EntityKind::Internal(ref inner_value) = decl.kind
            {
                Names::insert(visited, ref_name, ())?;
                self.storage.charge(inner_value.len())?;
                // The cursor borrows retained replacement text; no reference
                // list or entity-name copy is needed for an edge or a frame.
                Values::push(
                    &mut frames,
                    (Some(ref_name), Self::extract_entity_refs(inner_value)),
                )?;
            }
        }
        Ok(())
    }

    /// Iteratively checks for parameter entity reference cycles.
    ///
    /// Examines the char-ref-expanded replacement text for `%name;` patterns.
    fn check_pe_recursion<'b>(
        &'b self,
        value: &str,
        visited: &mut S::Names<&'b str, ()>,
        safe: &mut S::Names<&'b str, ()>,
    ) -> Result<(), DtdError<S>> {
        // The same No Recursion rule applies to PEs. Decoded frame text owns
        // its storage, while active/completed names borrow the declaration map.
        let mut frames = self.storage.values(0)?;
        self.storage.charge(value.len())?;
        Values::push(&mut frames, (None, ReferenceText::<S>::Borrowed(value), 0))?;
        while let Some((_, text, cursor)) = frames.last_mut() {
            let Some(ref_name) = Self::next_pe_ref(text.as_ref(), cursor) else {
                if let Some((Some(name), _, _)) = frames.pop() {
                    visited.remove(name, self.storage)?;
                    Names::insert(safe, name, ())?;
                }
                continue;
            };
            if safe.get(ref_name, self.storage)?.is_some() {
                continue;
            }
            if visited.get(ref_name, self.storage)?.is_some() {
                return Err(self.fatal(format_args!(
                    "recursive parameter entity reference: '%{ref_name}'"
                )));
            }
            if let Some((name, decl)) = self.dtd.param_entities.key_value(ref_name, self.storage)?
                && let EntityKind::Internal(ref inner_value) = decl.kind
            {
                let expanded = expand_char_refs_only(inner_value, self.storage)?;
                self.storage.charge(expanded.len())?;
                Names::insert(visited, name.as_ref(), ())?;
                Values::push(
                    &mut frames,
                    (
                        Some(name.as_ref()),
                        ReferenceText::<S>::Decoded(expanded),
                        0,
                    ),
                )?;
            }
        }
        Ok(())
    }

    /// Scans the next PE edge without allocating an edge list or copying names.
    fn next_pe_ref<'b>(value: &'b str, cursor: &mut usize) -> Option<&'b str> {
        let bytes = value.as_bytes();
        let mut i = *cursor;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                i += 1;
                if i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
                    let start = i;
                    while i < bytes.len() && bytes[i] != b';' && !bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == b';' && i > start {
                        let end = i;
                        i += 1;
                        *cursor = i;
                        return Some(&value[start..end]);
                    }
                }
            } else {
                i += 1;
            }
        }
        *cursor = i;
        None
    }

    /// Validates entity references in attribute default values.
    ///
    /// Checks WFC: No External Entity References (§3.1) and
    /// WFC: No `<` in Attribute Values for entity replacement text.
    fn validate_attr_default_entities<'b>(
        &'b self,
        value: &'b str,
        checked: &mut S::Names<&'b str, ()>,
    ) -> Result<(), DtdError<S>> {
        let mut frames = self.storage.values(0)?;
        self.storage.charge(value.len())?;
        Values::push(&mut frames, Self::extract_entity_refs(value))?;
        while let Some(references) = frames.last_mut() {
            let Some(ref_name) = references.next() else {
                frames.pop();
                continue;
            };
            // Built-in entities are always fine
            if matches!(ref_name, "amp" | "lt" | "gt" | "apos" | "quot") {
                continue;
            }
            if checked.get(ref_name, self.storage)?.is_some() {
                continue;
            }
            match self.dtd.entities.get(ref_name, self.storage)? {
                None => {
                    return Err(self.fatal(format_args!(
                        "undeclared entity '{ref_name}' referenced in \
                         attribute default value"
                    )));
                }
                Some(decl) => match &decl.kind {
                    EntityKind::External { .. } => {
                        return Err(self.fatal(format_args!(
                            "attribute default value must not reference \
                             external entity '{ref_name}'"
                        )));
                    }
                    EntityKind::Internal(text) => {
                        // Check for '<' in replacement text (WFC: No < in
                        // Attribute Values, XML 1.0 §3.1)
                        self.storage.charge(text.len())?;
                        if text.contains('<') {
                            return Err(self.fatal(format_args!(
                                "entity '{ref_name}' contains '<' and cannot \
                                 be used in attribute values"
                            )));
                        }
                        // The graph is known acyclic. Memoize before entering
                        // its continuation, without copying the retained name.
                        Names::insert(checked, ref_name, ())?;
                        self.storage.charge(text.len())?;
                        Values::push(&mut frames, Self::extract_entity_refs(text))?;
                    }
                },
            }
        }
        Ok(())
    }

    /// Extracts entity reference names from a string value.
    ///
    /// Returns an iterator over entity names found in `&name;` patterns,
    /// excluding character references (`&#...;`).
    fn extract_entity_refs(value: &str) -> EntityReferences<'_> {
        EntityReferences { value, cursor: 0 }
    }

    // --- ELEMENT declaration ---
    // See XML 1.0 §3.2: [45] elementdecl

    fn parse_element_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<!ELEMENT")?;
        self.skip_whitespace_required()?;
        let name = self.parse_name()?;
        self.skip_whitespace_required()?;
        let content_model = self.parse_content_model()?;
        self.skip_whitespace()?;
        self.expect_byte(b'>')?;

        let decl = ElementDecl {
            name: self.storage.text(&name)?,
            content_model,
        };
        self.dtd
            .declarations
            .push(DtdDeclaration::Element(decl.copy_in(self.storage)?))?;
        Names::insert(&mut self.dtd.elements, name, decl)?;
        Ok(())
    }

    fn parse_content_model(&mut self) -> Result<ContentModel<S>, DtdError<S>> {
        if self.looking_at(b"EMPTY") {
            self.expect_str(b"EMPTY")?;
            return Ok(ContentModel::Empty);
        }
        if self.looking_at(b"ANY") {
            self.expect_str(b"ANY")?;
            return Ok(ContentModel::Any);
        }

        // Must be Mixed or Children, both start with '('
        self.expect_byte(b'(')?;
        self.skip_whitespace()?;

        // Check for mixed content: (#PCDATA ...)
        if self.looking_at(b"#PCDATA") {
            self.expect_str(b"#PCDATA")?;
            self.skip_whitespace()?;

            let mut names = self.storage.values(0)?;

            if self.peek() == Some(b')') {
                // (#PCDATA) — text only
                self.advance(1)?;
                // Optional '*' after (#PCDATA) — some DTDs write (#PCDATA)*
                if self.peek() == Some(b'*') {
                    self.advance(1)?;
                }
                return Ok(ContentModel::Mixed(names));
            }

            // (#PCDATA|a|b)*
            while self.peek() == Some(b'|') {
                self.advance(1)?;
                self.skip_whitespace()?;
                let elem_name = self.parse_name()?;
                names.push(elem_name)?;
                self.skip_whitespace()?;
            }

            self.expect_byte(b')')?;
            self.expect_byte(b'*')?;

            return Ok(ContentModel::Mixed(names));
        }

        // Element-only content: parse as a content spec group. The opening
        // '(' has already been consumed, so we are one level deep.
        let spec = self.parse_content_groups()?;
        Ok(ContentModel::Children(spec))
    }

    fn parse_content_groups(&mut self) -> Result<ContentSpec<S>, DtdError<S>> {
        struct Group<S: Storage> {
            items: S::Values<ContentSpec<S>>,
            separator: Option<u8>,
            need_particle: bool,
        }
        let mut groups: S::Values<Group<S>> = self.storage.values(0)?;
        groups.push(Group {
            items: self.storage.values(0)?,
            separator: None,
            need_particle: true,
        })?;
        loop {
            self.storage.charge(1)?;
            if groups.last().expect("outer group exists").need_particle {
                if self.peek() == Some(b'(') {
                    if groups.len() == MAX_CONTENT_MODEL_DEPTH as usize {
                        return Err(self.fatal(format_args!("content model nesting exceeds maximum depth of {MAX_CONTENT_MODEL_DEPTH}")));
                    }
                    self.advance(1)?;
                    self.skip_whitespace()?;
                    groups.push(Group {
                        items: self.storage.values(0)?,
                        separator: None,
                        need_particle: true,
                    })?;
                    continue;
                }
                let name = self.parse_name()?;
                let occurrence = self.parse_occurrence()?;
                let group = groups.last_mut().expect("outer group exists");
                group.items.push(ContentSpec {
                    kind: ContentSpecKind::Name(name),
                    occurrence,
                })?;
                group.need_particle = false;
            }
            self.skip_whitespace()?;
            if let Some(separator @ (b',' | b'|')) = self.peek() {
                let group = groups.last_mut().expect("outer group exists");
                if let Some(expected) = group.separator {
                    if expected != separator {
                        return Err(
                            self.fatal("content-model group mixes sequence and choice separators")
                        );
                    }
                } else {
                    group.separator = Some(separator);
                }
                group.need_particle = true;
                self.advance(1)?;
                self.skip_whitespace()?;
                continue;
            }
            self.expect_byte(b')')?;
            let occurrence = self.parse_occurrence()?;
            let mut group = groups.pop().expect("outer group exists");
            let spec = match group.separator {
                Some(b',') => ContentSpec {
                    kind: ContentSpecKind::Seq(group.items),
                    occurrence,
                },
                Some(b'|') => ContentSpec {
                    kind: ContentSpecKind::Choice(group.items),
                    occurrence,
                },
                Some(_) => unreachable!("only XML content-model separators are stored"),
                None => {
                    let mut item = group
                        .items
                        .pop()
                        .expect("a group contains a parsed particle");
                    if occurrence == Occurrence::Once && item.occurrence == Occurrence::Once {
                        item
                    } else {
                        // Preserve the donor's single-particle normalization:
                        // (X+) becomes (X)+; an explicit outer occurrence is
                        // not merged with the inner particle's occurrence.
                        let outer = if occurrence == Occurrence::Once {
                            let inner = item.occurrence;
                            item.occurrence = Occurrence::Once;
                            inner
                        } else {
                            occurrence
                        };
                        group.items.push(item)?;
                        ContentSpec {
                            kind: ContentSpecKind::Seq(group.items),
                            occurrence: outer,
                        }
                    }
                }
            };
            let Some(parent) = groups.last_mut() else {
                return Ok(spec);
            };
            parent.items.push(spec)?;
            parent.need_particle = false;
        }
    }

    fn parse_occurrence(&mut self) -> Result<Occurrence, DtdError<S>> {
        Ok(match self.peek() {
            Some(b'?') => {
                self.advance(1)?;
                Occurrence::Optional
            }
            Some(b'*') => {
                self.advance(1)?;
                Occurrence::ZeroOrMore
            }
            Some(b'+') => {
                self.advance(1)?;
                Occurrence::OneOrMore
            }
            _ => Occurrence::Once,
        })
    }

    // --- ATTLIST declaration ---
    // See XML 1.0 §3.3: [52] AttlistDecl

    fn parse_attlist_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<!ATTLIST")?;
        self.skip_whitespace_required()?;
        let element_name = self.parse_name()?;

        loop {
            self.skip_whitespace()?;
            if self.peek() == Some(b'>') {
                self.advance(1)?;
                break;
            }

            let attribute_name = self.parse_name()?;
            self.skip_whitespace_required()?;
            let attribute_type = self.parse_attribute_type()?;
            self.skip_whitespace_required()?;
            let default = self.parse_attribute_default()?;

            let decl = AttributeDecl {
                element_name: self.storage.text(&element_name)?,
                attribute_name,
                attribute_type,
                default,
            };

            // Per XML 1.0 §3.3, the first attribute declaration is binding;
            // subsequent declarations for the same attribute are ignored.
            if self
                .dtd
                .attributes
                .get(&element_name, self.storage)?
                .is_none()
            {
                Names::insert(
                    &mut self.dtd.attributes,
                    self.storage.text(&element_name)?,
                    self.storage.values(0)?,
                )?;
            }
            let attrs = self
                .dtd
                .attributes
                .get_mut(&element_name, self.storage)?
                .expect("attribute group inserted above");
            self.storage.charge(attrs.len())?;
            let mut declared = false;
            for attribute in &**attrs {
                self.storage.charge(attribute.attribute_name.len())?;
                if attribute.attribute_name.as_ref() == decl.attribute_name.as_ref() {
                    declared = true;
                    break;
                }
            }
            if !declared {
                self.dtd
                    .declarations
                    .push(DtdDeclaration::Attlist(decl.copy_in(self.storage)?))?;
                attrs.push(decl)?;
            }
        }

        Ok(())
    }

    fn parse_attribute_type(&mut self) -> Result<AttributeType<S>, DtdError<S>> {
        if self.looking_at(b"CDATA") {
            self.expect_str(b"CDATA")?;
            Ok(AttributeType::CData)
        } else if self.looking_at(b"IDREFS") {
            self.expect_str(b"IDREFS")?;
            Ok(AttributeType::IdRefs)
        } else if self.looking_at(b"IDREF") {
            self.expect_str(b"IDREF")?;
            Ok(AttributeType::IdRef)
        } else if self.looking_at(b"ID") {
            self.expect_str(b"ID")?;
            Ok(AttributeType::Id)
        } else if self.looking_at(b"ENTITIES") {
            self.expect_str(b"ENTITIES")?;
            Ok(AttributeType::Entities)
        } else if self.looking_at(b"ENTITY") {
            self.expect_str(b"ENTITY")?;
            Ok(AttributeType::Entity)
        } else if self.looking_at(b"NMTOKENS") {
            self.expect_str(b"NMTOKENS")?;
            Ok(AttributeType::NmTokens)
        } else if self.looking_at(b"NMTOKEN") {
            self.expect_str(b"NMTOKEN")?;
            Ok(AttributeType::NmToken)
        } else if self.looking_at(b"NOTATION") {
            self.expect_str(b"NOTATION")?;
            self.skip_whitespace_required()?;
            let values = self.parse_enumerated_values()?;
            Ok(AttributeType::Notation(values))
        } else if self.peek() == Some(b'(') {
            let values = self.parse_enumerated_values()?;
            Ok(AttributeType::Enumeration(values))
        } else {
            Err(self.fatal("expected attribute type"))
        }
    }

    fn parse_enumerated_values(&mut self) -> Result<S::Values<S::Text>, DtdError<S>> {
        self.expect_byte(b'(')?;
        self.skip_whitespace()?;
        let mut values = self.storage.values(0)?;

        let first = self.parse_nmtoken()?;
        values.push(first)?;

        loop {
            self.skip_whitespace()?;
            if self.peek() == Some(b')') {
                self.advance(1)?;
                break;
            }
            self.expect_byte(b'|')?;
            self.skip_whitespace()?;
            let val = self.parse_nmtoken()?;
            values.push(val)?;
        }

        Ok(values)
    }

    fn parse_attribute_default(&mut self) -> Result<AttributeDefault<S>, DtdError<S>> {
        if self.looking_at(b"#REQUIRED") {
            self.expect_str(b"#REQUIRED")?;
            Ok(AttributeDefault::Required)
        } else if self.looking_at(b"#IMPLIED") {
            self.expect_str(b"#IMPLIED")?;
            Ok(AttributeDefault::Implied)
        } else if self.looking_at(b"#FIXED") {
            self.expect_str(b"#FIXED")?;
            self.skip_whitespace_required()?;
            let value = self.parse_quoted_value()?;
            self.validate_default_value(&value)?;
            Ok(AttributeDefault::Fixed(value))
        } else {
            let value = self.parse_quoted_value()?;
            self.validate_default_value(&value)?;
            Ok(AttributeDefault::Default(value))
        }
    }

    // --- ENTITY declaration ---
    // See XML 1.0 §4.2: [70] EntityDecl

    #[allow(clippy::too_many_lines)]
    fn parse_entity_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<!ENTITY")?;
        self.skip_whitespace_required()?;

        // Parameter entities (% name)
        if self.peek() == Some(b'%') {
            self.advance(1)?;
            self.skip_whitespace_required()?;
            let pe_name = self.parse_name()?;
            // Namespaces in XML 1.0: entity names must be NCNames (no colons).
            if pe_name.contains(':') {
                return Err(self.fatal(format_args!(
                    "entity name '{pe_name}' must not contain a colon"
                )));
            }
            self.skip_whitespace_required()?;

            let pe_kind = if self.peek() == Some(b'"') || self.peek() == Some(b'\'') {
                // Internal PE — parse and validate the value
                let value = self.parse_quoted_value()?;
                self.validate_entity_value(&value, true)?;
                Some(EntityKind::Internal(value))
            } else if self.looking_at(b"SYSTEM") {
                // External PE — parse external ID
                self.expect_str(b"SYSTEM")?;
                self.skip_whitespace_required()?;
                let system_id = self.parse_quoted_value()?;
                Some(EntityKind::External {
                    system_id,
                    public_id: None,
                })
            } else if self.looking_at(b"PUBLIC") {
                self.expect_str(b"PUBLIC")?;
                self.skip_whitespace_required()?;
                let public_id = self.parse_quoted_value()?;
                self.validate_public_id(&public_id)?;
                self.skip_whitespace_required()?;
                let system_id = self.parse_quoted_value()?;
                Some(EntityKind::External {
                    system_id,
                    public_id: Some(public_id),
                })
            } else {
                return Err(self.fatal("expected entity value or external ID"));
            };

            self.skip_whitespace()?;
            // Reject NDATA on parameter entities (XML 1.0 §4.2.2)
            if self.looking_at(b"NDATA") {
                return Err(self.fatal("NDATA annotation is not allowed on parameter entities"));
            }
            self.expect_byte(b'>')?;

            // Store PE declaration (first declaration wins per XML 1.0 §4.2)
            if let Some(kind) = pe_kind
                && self
                    .dtd
                    .param_entities
                    .get(&pe_name, self.storage)?
                    .is_none()
            {
                Names::insert(
                    &mut self.dtd.param_entities,
                    pe_name,
                    EntityDecl {
                        name: self.storage.text("")?,
                        kind,
                    },
                )?;
            }
            return Ok(());
        }

        let name = self.parse_name()?;
        // Namespaces in XML 1.0: entity names must be NCNames (no colons).
        if name.contains(':') {
            return Err(self.fatal(format_args!(
                "entity name '{name}' must not contain a colon"
            )));
        }
        self.skip_whitespace_required()?;

        let is_parameter_entity = false;
        let kind = if self.peek() == Some(b'"') || self.peek() == Some(b'\'') {
            // Internal entity
            let value = self.parse_quoted_value()?;
            self.validate_entity_value(&value, is_parameter_entity)?;
            EntityKind::Internal(value)
        } else if self.looking_at(b"SYSTEM") {
            self.expect_str(b"SYSTEM")?;
            self.skip_whitespace_required()?;
            let system_id = self.parse_quoted_value()?;
            EntityKind::External {
                system_id,
                public_id: None,
            }
        } else if self.looking_at(b"PUBLIC") {
            self.expect_str(b"PUBLIC")?;
            self.skip_whitespace_required()?;
            let public_id = self.parse_quoted_value()?;
            self.validate_public_id(&public_id)?;
            self.skip_whitespace_required()?;
            let system_id = self.parse_quoted_value()?;
            EntityKind::External {
                system_id,
                public_id: Some(public_id),
            }
        } else {
            return Err(self.fatal("expected entity value or external ID"));
        };

        let had_ws = self.skip_whitespace()?;

        // Handle optional NDATA for unparsed external entities (XML 1.0 §4.2.2)
        if self.looking_at(b"NDATA") {
            // NDATA is only allowed on external entities
            if matches!(kind, EntityKind::Internal(_)) {
                return Err(self.fatal("NDATA annotation is not allowed on internal entities"));
            }
            // Whitespace is required before NDATA (XML 1.0 §4.2.2)
            if !had_ws {
                return Err(self.fatal("whitespace required before NDATA"));
            }
            self.expect_str(b"NDATA")?;
            self.skip_whitespace_required()?;
            let _notation_name = self.parse_name()?;
            self.skip_whitespace()?;
        }

        self.expect_byte(b'>')?;

        // Per XML 1.0 §4.2, the first entity declaration is binding;
        // subsequent declarations of the same entity are ignored.
        let decl = EntityDecl {
            name: self.storage.text(&name)?,
            kind,
        };
        self.dtd
            .declarations
            .push(DtdDeclaration::Entity(decl.copy_in(self.storage)?))?;
        if self.dtd.entities.get(&name, self.storage)?.is_none() {
            Names::insert(&mut self.dtd.entities, name, decl)?;
        }
        Ok(())
    }

    // --- NOTATION declaration ---
    // See XML 1.0 §4.7: [82] NotationDecl

    fn parse_notation_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<!NOTATION")?;
        self.skip_whitespace_required()?;
        let name = self.parse_name()?;
        // Namespaces in XML 1.0: notation names must be NCNames (no colons).
        if name.contains(':') {
            return Err(self.fatal(format_args!(
                "notation name '{name}' must not contain a colon"
            )));
        }
        self.skip_whitespace_required()?;

        let (system_id, public_id) = if self.looking_at(b"SYSTEM") {
            self.expect_str(b"SYSTEM")?;
            self.skip_whitespace_required()?;
            let sid = self.parse_quoted_value()?;
            (Some(sid), None)
        } else if self.looking_at(b"PUBLIC") {
            self.expect_str(b"PUBLIC")?;
            self.skip_whitespace_required()?;
            let pid = self.parse_quoted_value()?;
            self.validate_public_id(&pid)?;
            // System ID is optional for notations with PUBLIC
            self.skip_whitespace()?;
            let sid = if self.peek() == Some(b'"') || self.peek() == Some(b'\'') {
                Some(self.parse_quoted_value()?)
            } else {
                None
            };
            (sid, Some(pid))
        } else {
            return Err(self.fatal("expected SYSTEM or PUBLIC in NOTATION declaration"));
        };

        self.skip_whitespace()?;
        self.expect_byte(b'>')?;

        let decl = NotationDecl {
            name: self.storage.text(&name)?,
            system_id,
            public_id,
        };
        self.dtd
            .declarations
            .push(DtdDeclaration::Notation(decl.copy_in(self.storage)?))?;
        Names::insert(&mut self.dtd.notations, name, decl)?;
        Ok(())
    }

    // --- Skip helpers ---

    /// Parses a comment and stores it as a `DtdDeclaration::Comment`.
    fn parse_comment_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<!--")?;
        let start = self.input.pos();
        loop {
            if self.at_end() {
                return Err(self.fatal("unexpected end of input in comment"));
            }
            if self.looking_at(b"-->") {
                self.storage.charge(self.input.pos() - start)?;
                let text = self.storage.text(
                    std::str::from_utf8(self.input.slice(start, self.input.pos()))
                        .expect("comment ends at an ASCII UTF-8 boundary"),
                )?;
                self.advance(3)?;
                self.dtd.declarations.push(DtdDeclaration::Comment(text))?;
                return Ok(());
            }
            self.advance(1)?;
        }
    }

    /// Parses a processing instruction and stores it as a `DtdDeclaration::Pi`.
    fn parse_pi_decl(&mut self) -> Result<(), DtdError<S>> {
        self.expect_str(b"<?")?;

        // Parse and validate the PI target name (XML 1.0 §2.6)
        let target = self.parse_name()?;

        // Reject <?xml ...?> inside DTD (XML 1.0 §2.8)
        if target.eq_ignore_ascii_case("xml") {
            return Err(self.fatal("XML declaration is not allowed inside DTD"));
        }

        // If we're immediately at ?>, no data — that's fine
        if self.looking_at(b"?>") {
            self.advance(2)?;
            self.dtd
                .declarations
                .push(DtdDeclaration::Pi(target, None))?;
            return Ok(());
        }

        // If there's data, whitespace is required between target and data
        let is_ws = self
            .peek()
            .is_some_and(|b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n');
        if !is_ws {
            return Err(self.fatal("space required between PI target and data"));
        }

        let start = self.input.pos();
        loop {
            if self.at_end() {
                return Err(self.fatal("unexpected end of input in processing instruction"));
            }
            if self.looking_at(b"?>") {
                self.storage.charge(self.input.pos() - start)?;
                self.storage.charge(self.input.pos() - start)?;
                let data = self.storage.text(
                    std::str::from_utf8(self.input.slice(start, self.input.pos()))
                        .expect("PI ends at an ASCII UTF-8 boundary")
                        .trim(),
                )?;
                self.advance(2)?;
                let data = if data.is_empty() { None } else { Some(data) };
                self.dtd
                    .declarations
                    .push(DtdDeclaration::Pi(target, data))?;
                return Ok(());
            }
            self.advance(1)?;
        }
    }

    fn skip_pe_reference(&mut self) -> Result<(), DtdError<S>> {
        self.expect_byte(b'%')?;
        // Read the name
        let _name = self.parse_name()?;
        self.expect_byte(b';')?;
        Ok(())
    }

    // --- Name / token parsing ---

    fn parse_name(&mut self) -> Result<S::Text, DtdError<S>> {
        Ok(self.storage.text(self.input.parse_name()?)?)
    }

    fn parse_nmtoken(&mut self) -> Result<S::Text, DtdError<S>> {
        Ok(self.storage.text(self.input.parse_nmtoken()?)?)
    }

    /// Validates an entity value per XML 1.0 §4.3.2 `EntityValue` production.
    ///
    /// Checks that `&` is only used in valid entity/character references,
    /// and that `%` is not present in general entity values.
    #[allow(clippy::too_many_lines)]
    fn validate_entity_value(
        &self,
        value: &str,
        is_parameter_entity: bool,
    ) -> Result<(), DtdError<S>> {
        // Character validation, reference scanning, numeric conversion and
        // referenced-name validation are separate passes over known text.
        for _ in 0..4 {
            self.storage.charge(value.len())?;
        }
        for c in value.chars() {
            if !crate::parser_xmloxide::parser::input::is_xml_char(c) {
                return Err(self.fatal(format_args!(
                    "invalid XML character U+{:04X} in entity value",
                    c as u32
                )));
            }
        }

        // Text declarations (<?xml ...?>) are forbidden in internal
        // entities (XML 1.0 §4.3.1). They may only appear at the start
        // of external parsed entities.
        if value.starts_with("<?xml") {
            let after = value.as_bytes().get(5).copied();
            if after.is_none_or(|b| b == b' ' || b == b'\t' || b == b'?') {
                return Err(self.fatal("text declaration is not allowed in internal entity value"));
            }
        }

        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'&' => {
                    // Must be a valid reference: &name; or &#N; or &#xH;
                    i += 1;
                    if i >= bytes.len() {
                        return Err(self.fatal("incomplete reference in entity value: '&' at end"));
                    }
                    if bytes[i] == b'#' {
                        // Character reference — parse and validate
                        i += 1;
                        let char_val = if i < bytes.len() && bytes[i] == b'x' {
                            i += 1;
                            let hex_start = i;
                            if i >= bytes.len() || !bytes[i].is_ascii_hexdigit() {
                                return Err(
                                    self.fatal("malformed character reference in entity value")
                                );
                            }
                            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                                i += 1;
                            }
                            let hex_str = std::str::from_utf8(&bytes[hex_start..i]).unwrap_or("");
                            u32::from_str_radix(hex_str, 16).unwrap_or(0)
                        } else {
                            let dec_start = i;
                            if i >= bytes.len() || !bytes[i].is_ascii_digit() {
                                return Err(
                                    self.fatal("malformed character reference in entity value")
                                );
                            }
                            while i < bytes.len() && bytes[i].is_ascii_digit() {
                                i += 1;
                            }
                            let dec_str = std::str::from_utf8(&bytes[dec_start..i]).unwrap_or("");
                            dec_str.parse::<u32>().unwrap_or(0)
                        };
                        if i >= bytes.len() || bytes[i] != b';' {
                            return Err(
                                self.fatal("incomplete character reference in entity value")
                            );
                        }
                        i += 1;
                        // Validate the referenced character is a valid XML char
                        if let Some(c) = char::from_u32(char_val) {
                            if !crate::parser_xmloxide::parser::input::is_xml_char(c) {
                                return Err(self.fatal(format_args!(
                                    "character reference &#x{char_val:X}; refers to invalid XML character"
                                )));
                            }
                        } else {
                            return Err(self.fatal(format_args!(
                                "character reference value {char_val} is not a valid Unicode code point"
                            )));
                        }
                    } else {
                        // Entity reference — must be Name followed by ';'
                        let start = i;
                        while i < bytes.len()
                            && bytes[i] != b';'
                            && bytes[i] != b'&'
                            && !bytes[i].is_ascii_whitespace()
                        {
                            i += 1;
                        }
                        if i == start || i >= bytes.len() || bytes[i] != b';' {
                            return Err(self.fatal("malformed entity reference in entity value"));
                        }
                        // Validate the entity name starts with a NameStartChar
                        let name_str = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
                        if let Some(first_char) = name_str.chars().next()
                            && !is_name_start_char(first_char)
                        {
                            return Err(self.fatal(format_args!(
                                "entity reference name must start with a letter or underscore, found '{first_char}'"
                            )));
                        }
                        i += 1;
                    }
                }
                b'%' if !is_parameter_entity => {
                    // '%' is not allowed in general entity values (XML 1.0 §4.3.2)
                    return Err(self.fatal("'%' not allowed in general entity value"));
                }
                b'%' if is_parameter_entity => {
                    // WFC: PEs in Internal Subset — PE references MUST NOT
                    // occur within markup declarations in the internal subset
                    // (XML 1.0 §2.8).
                    i += 1;
                    if i < bytes.len() {
                        let first = bytes[i];
                        if first.is_ascii_alphabetic() || first == b'_' || first == b':' {
                            return Err(self.fatal(
                                "parameter entity reference not allowed within \
                                 markup declaration in internal subset",
                            ));
                        }
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }
        Ok(())
    }

    /// Validates an attribute default value per XML 1.0 §3.3.2.
    ///
    /// Checks that entity references within the default value refer to
    /// entities that have already been declared (WFC: Entity Declared).
    /// Also rejects `<` in default values (WFC: No `<` in Attribute Values).
    fn validate_default_value(&self, value: &str) -> Result<(), DtdError<S>> {
        self.storage.charge(value.len())?;
        self.storage.charge(value.len())?;
        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'<' => {
                    return Err(self.fatal("'<' not allowed in attribute default value"));
                }
                b'&' => {
                    i += 1;
                    if i < bytes.len() && bytes[i] == b'#' {
                        // Character reference — skip over it
                        i += 1;
                        while i < bytes.len() && bytes[i] != b';' {
                            i += 1;
                        }
                        if i < bytes.len() {
                            i += 1;
                        }
                    } else {
                        // Entity reference — extract name and check declaration
                        let start = i;
                        while i < bytes.len() && bytes[i] != b';' {
                            i += 1;
                        }
                        if i > start && i < bytes.len() {
                            let name = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
                            // Built-in entities are always available
                            let is_builtin = matches!(name, "amp" | "lt" | "gt" | "apos" | "quot");
                            if !is_builtin && self.dtd.entities.get(name, self.storage)?.is_none() {
                                return Err(self.fatal(format_args!(
                                    "undeclared entity '{name}' in attribute default value"
                                )));
                            }
                        }
                        if i < bytes.len() {
                            i += 1;
                        }
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }
        Ok(())
    }

    /// Validates that a public ID string contains only valid `PubidChar`s
    /// per XML 1.0 §2.3 `[13]`.
    fn validate_public_id(&self, pid: &str) -> Result<(), DtdError<S>> {
        self.storage.charge(pid.len())?;
        for c in pid.chars() {
            let valid = matches!(c,
                ' ' | '\r' | '\n' |
                'a'..='z' | 'A'..='Z' | '0'..='9' |
                '-' | '\'' | '(' | ')' | '+' | ',' | '.' | '/' | ':' |
                '=' | '?' | ';' | '!' | '*' | '#' | '@' | '$' | '_' | '%'
            );
            if !valid {
                return Err(self.fatal(format_args!(
                    "invalid character in public ID: U+{:04X}",
                    c as u32
                )));
            }
        }
        Ok(())
    }

    fn parse_quoted_value(&mut self) -> Result<S::Text, DtdError<S>> {
        Ok(self.storage.text(self.input.parse_quoted_value()?)?)
    }

    // --- Low-level input helpers ---

    fn at_end(&self) -> bool {
        self.input.at_end()
    }

    fn peek(&self) -> Option<u8> {
        self.input.peek()
    }

    fn advance(&mut self, count: usize) -> Result<(), DtdError<S>> {
        self.input.advance(count)
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), DtdError<S>> {
        self.input.expect_byte(expected)
    }

    fn expect_str(&mut self, expected: &[u8]) -> Result<(), DtdError<S>> {
        self.input.expect_str(expected)
    }

    fn looking_at(&self, s: &[u8]) -> bool {
        self.input.looking_at(s)
    }

    fn skip_whitespace(&mut self) -> Result<bool, DtdError<S>> {
        self.input.skip_whitespace()
    }

    fn skip_whitespace_required(&mut self) -> Result<(), DtdError<S>> {
        self.input.skip_whitespace_required()
    }

    fn fatal(&self, message: impl fmt::Display) -> DtdError<S> {
        self.input.fatal(message)
    }
}

// ---------------------------------------------------------------------------
// Entity value helper functions (used by DTD parser and XML parser)
// ---------------------------------------------------------------------------

/// Only PE decoding owns text; the initial frame borrows its existing input.
enum ReferenceText<'a, S: Storage> {
    Borrowed(&'a str),
    Decoded(S::Text),
}

impl<S: Storage> AsRef<str> for ReferenceText<'_, S> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Decoded(text) => text.as_ref(),
        }
    }
}

/// Resumable borrowed references; DFS frames keep a cursor, not a list of edges.
struct EntityReferences<'a> {
    value: &'a str,
    cursor: usize,
}

impl<'a> Iterator for EntityReferences<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.value.as_bytes();
        while self.cursor < bytes.len() {
            if bytes[self.cursor] != b'&' {
                self.cursor += 1;
                continue;
            }
            self.cursor += 1;
            if bytes.get(self.cursor) == Some(&b'#') {
                while self.cursor < bytes.len() && bytes[self.cursor] != b';' {
                    self.cursor += 1;
                }
                if self.cursor < bytes.len() {
                    self.cursor += 1;
                }
                continue;
            }
            let start = self.cursor;
            while self.cursor < bytes.len()
                && bytes[self.cursor] != b';'
                && bytes[self.cursor] != b'&'
            {
                self.cursor += 1;
            }
            if bytes.get(self.cursor) == Some(&b';') {
                let end = self.cursor;
                self.cursor += 1;
                if end > start {
                    return Some(&self.value[start..end]);
                }
            }
        }
        None
    }
}

/// Expands only character references in a string, leaving entity references
/// as-is. Returns the expanded text.
///
/// Used to compute the replacement text of an internal entity per XML 1.0
/// §4.5: character references are expanded at declaration time, while
/// entity references are left for expansion at reference time.
pub(crate) fn expand_char_refs_only<S: Storage>(
    value: &str,
    storage: S,
) -> Result<S::Text, crate::xml::dom::ParseError> {
    // XML 1.0 §4.5 expands character references at declaration time, while
    // retaining general references for the later inclusion step.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#intern-replacement
    // Admit scanning, numeric conversion, and source slicing before doing them.
    storage.charge(value.len())?;
    storage.charge(value.len())?;
    storage.charge(value.len())?;
    let bytes = value.as_bytes();
    let mut result = storage.text("")?;
    // Expansion cannot grow a validated character-reference spelling. Keeping
    // this input-sized capacity avoids repeatedly moving the accumulated text.
    storage.reserve_text(&mut result, value.len())?;
    let mut i = 0;
    let mut literal_start = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'#' {
            crate::parser_xmloxide::parser::input::append_normalized_line_ends(
                storage,
                &mut result,
                &value[literal_start..i],
            )?;
            i += 2;
            let char_val = if i < bytes.len() && bytes[i] == b'x' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let hex = std::str::from_utf8(&bytes[start..i]).unwrap_or("0");
                u32::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let dec = std::str::from_utf8(&bytes[start..i]).unwrap_or("0");
                dec.parse::<u32>().unwrap_or(0)
            };
            if i < bytes.len() && bytes[i] == b';' {
                i += 1;
            }
            if let Some(ch) = char::from_u32(char_val) {
                storage.append(&mut result, ch.encode_utf8(&mut [0; 4]))?;
            }
            literal_start = i;
        } else {
            // Only ASCII '&' can split a literal span, so scanning bytes never
            // splits a UTF-8 character at an eventual append boundary.
            i += 1;
        }
    }
    crate::parser_xmloxide::parser::input::append_normalized_line_ends(
        storage,
        &mut result,
        &value[literal_start..],
    )?;
    Ok(result)
}

/// Replaces entity references (`&name;`) with spaces, leaving character
/// references (`&#...;`) and other text unchanged. Correctly handles
/// multi-byte UTF-8 characters.
///
/// Used to sanitize entity replacement text before fragment parsing so
/// that entity references (which are valid `Reference` productions in
/// content) don't cause undeclared-entity errors.
pub(crate) fn replace_entity_refs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 1 < bytes.len() && bytes[i + 1] != b'#' {
            // Possible entity reference: &name;
            let start = i;
            i += 1;
            if i < bytes.len()
                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b':')
            {
                // Scan to semicolon
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b';' {
                    // Complete entity reference — replace with space
                    result.push(' ');
                    i += 1;
                } else {
                    // Incomplete — keep original text
                    result.push_str(&text[start..i]);
                }
            } else {
                // Not a valid entity ref start — keep the '&'
                result.push('&');
            }
        } else {
            // Copy one complete UTF-8 character
            let ch = text[i..].chars().next().unwrap_or('\u{FFFD}');
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}

// ---------------------------------------------------------------------------
// XML Name character classes (shared with parser/xml.rs)
// ---------------------------------------------------------------------------

fn is_ascii_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}

fn is_ascii_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b'-' || b == b'.'
}

fn is_name_start_char(c: char) -> bool {
    matches!(c,
        ':' | 'A'..='Z' | '_' | 'a'..='z' |
        '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' |
        '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' |
        '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' |
        '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' |
        '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' |
        '\u{10000}'..='\u{EFFFF}'
    )
}

fn is_name_char(c: char) -> bool {
    is_name_start_char(c)
        || matches!(c,
            '-' | '.' | '0'..='9' | '\u{B7}' |
            '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

// ---------------------------------------------------------------------------
// DTD Validator
// ---------------------------------------------------------------------------

/// Validates a document against a DTD.
///
/// Checks that the document conforms to the element declarations, attribute
/// declarations, and other constraints in the DTD. Returns a
/// [`ValidationResult`] with any errors and warnings.
///
/// # Checks Performed
///
/// - Root element name matches DOCTYPE declaration
/// - Element content matches declared content models
/// - Required attributes are present
/// - Attribute values match their declared types (ID uniqueness, IDREF targets,
///   enumeration values)
/// - No undeclared elements (when the DTD declares elements)
/// - No undeclared attributes (when the DTD declares attributes for that element)
/// - `#FIXED` attribute values match the declared value
///
/// # Examples
///
/// ```text,xml-sec-example
/// use xmloxide::Document;
/// use xmloxide::validation::dtd::{parse_dtd, validate};
///
/// let dtd = parse_dtd("<!ELEMENT root (#PCDATA)>").unwrap();
/// let mut doc = Document::parse_str("<!DOCTYPE root><root>hello</root>").unwrap();
/// let result = validate(&mut doc, &dtd);
/// assert!(result.is_valid);
/// ```
pub fn validate(doc: &mut Document, dtd: &Dtd) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut id_values: HashSet<String> = HashSet::new();
    let mut idref_values: Vec<String> = Vec::new();

    // Check root element name against DOCTYPE
    check_root_element(doc, dtd, &mut errors);

    // Walk all element nodes and validate
    if let Some(root_elem) = doc.root_element() {
        validate_element_recursive(
            doc,
            dtd,
            root_elem,
            &mut errors,
            &mut warnings,
            &mut id_values,
            &mut idref_values,
        );
    }

    // Check that all IDREF values point to existing IDs
    for idref in &idref_values {
        if !id_values.contains(idref) {
            errors.push(ValidationError {
                message: format!("IDREF '{idref}' does not match any ID in the document"),
                line: None,
                column: None,
            });
        }
    }

    let is_valid = errors.is_empty();
    ValidationResult {
        is_valid,
        errors,
        warnings,
    }
}

/// Checks that the root element name matches the DOCTYPE name.
fn check_root_element(doc: &Document, _dtd: &Dtd, errors: &mut Vec<ValidationError>) {
    // Find the DOCTYPE node to get the declared root name
    let doctype_name = doc.children(doc.root()).find_map(|id| {
        if let NodeKind::DocumentType { ref name, .. } = doc.node(id).kind {
            Some(name.clone())
        } else {
            None
        }
    });

    if let Some(ref expected_name) = doctype_name
        && let Some(root_elem) = doc.root_element()
        && let Some(actual_name) = doc.node_name(root_elem)
        && actual_name != expected_name
    {
        errors.push(ValidationError {
            message: format!(
                "root element '{actual_name}' does not match \
                 DOCTYPE name '{expected_name}'"
            ),
            line: None,
            column: None,
        });
    }
}

/// Recursively validates an element and its descendants.
#[allow(clippy::too_many_arguments)]
fn validate_element_recursive(
    doc: &mut Document,
    dtd: &Dtd,
    node_id: NodeId,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationError>,
    id_values: &mut HashSet<String>,
    idref_values: &mut Vec<String>,
) {
    let elem_name = match doc.node_name(node_id) {
        Some(name) => name.to_string(),
        None => return,
    };

    // Check if element is declared
    let has_element_decls = !dtd.elements.is_empty();
    if has_element_decls && !dtd.elements.contains_key(elem_name.as_str()) {
        errors.push(ValidationError {
            message: format!("element '{elem_name}' is not declared in the DTD"),
            line: None,
            column: None,
        });
    }

    // Check content model
    if let Some(elem_decl) = dtd.elements.get(elem_name.as_str()) {
        validate_content_model(doc, node_id, &elem_name, &elem_decl.content_model, errors);
    }

    // Check attributes
    validate_attributes(
        doc,
        dtd,
        node_id,
        &elem_name,
        errors,
        warnings,
        id_values,
        idref_values,
    );

    // Collect child element IDs first to avoid borrow conflicts. Entity
    // references are looked through so that entity-supplied elements are
    // validated too (XML 1.0 §4.4.3: included replacement text participates
    // in validation).
    let child_ids: Vec<NodeId> = effective_content_children(doc, node_id)
        .into_iter()
        .filter(|&child_id| matches!(doc.node(child_id).kind, NodeKind::Element { .. }))
        .collect();

    // Recurse into child elements
    for child_id in child_ids {
        validate_element_recursive(
            doc,
            dtd,
            child_id,
            errors,
            warnings,
            id_values,
            idref_values,
        );
    }
}

/// Collects an element's content children in document order, transparently
/// expanding entity-reference nodes into their parsed replacement children.
///
/// Per XML 1.0 §4.4.3, replacement text included for an entity reference is
/// part of the document's content and participates in validation, so the
/// content-model checks must see through `EntityRef` nodes. An entity
/// reference without parsed children (e.g. an undeclared entity preserved in
/// tolerant mode) contributes nothing.
fn effective_content_children(doc: &Document, node_id: NodeId) -> Vec<NodeId> {
    fn collect(doc: &Document, node_id: NodeId, out: &mut Vec<NodeId>) {
        for child in doc.children(node_id) {
            if matches!(doc.node(child).kind, NodeKind::EntityRef { .. }) {
                collect(doc, child, out);
            } else {
                out.push(child);
            }
        }
    }
    let mut out = Vec::new();
    collect(doc, node_id, &mut out);
    out
}

/// Validates that an element's children match its declared content model.
fn validate_content_model(
    doc: &Document,
    node_id: NodeId,
    elem_name: &str,
    model: &ContentModel,
    errors: &mut Vec<ValidationError>,
) {
    // Entity references are looked through: their parsed replacement
    // children are part of the content being validated (XML 1.0 §4.4.3).
    let content_children = effective_content_children(doc, node_id);
    match model {
        ContentModel::Empty => {
            // No children at all
            let has_content = content_children.iter().any(|&child| {
                matches!(
                    doc.node(child).kind,
                    NodeKind::Element { .. } | NodeKind::Text { .. } | NodeKind::CData { .. }
                )
            });
            if has_content {
                errors.push(ValidationError {
                    message: format!(
                        "element '{elem_name}' is declared EMPTY \
                         but has content"
                    ),
                    line: None,
                    column: None,
                });
            }
        }
        ContentModel::Any => {
            // Anything is valid
        }
        ContentModel::Mixed(allowed_names) => {
            // Text is always allowed. Check that element children are in the allowed list.
            for &child_id in &content_children {
                if let NodeKind::Element { ref name, .. } = doc.node(child_id).kind
                    && !allowed_names.contains(name)
                {
                    errors.push(ValidationError {
                        message: format!(
                            "element '{name}' is not allowed in mixed content \
                             of '{elem_name}' (allowed: #PCDATA{})",
                            if allowed_names.is_empty() {
                                String::new()
                            } else {
                                format!("|{}", allowed_names.join("|"))
                            }
                        ),
                        line: None,
                        column: None,
                    });
                }
            }
        }
        ContentModel::Children(spec) => {
            // Collect element child names (ignore text, comments, PIs)
            let child_names: Vec<String> = content_children
                .iter()
                .filter_map(|&child_id| {
                    if let NodeKind::Element { ref name, .. } = doc.node(child_id).kind {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // Check for text content in element-only content model
            let has_text = content_children.iter().any(|&child_id| {
                if let NodeKind::Text { ref content } = doc.node(child_id).kind {
                    !content.trim().is_empty()
                } else {
                    matches!(doc.node(child_id).kind, NodeKind::CData { .. })
                }
            });

            if has_text {
                errors.push(ValidationError {
                    message: format!(
                        "element '{elem_name}' has element-only content model \
                         but contains text"
                    ),
                    line: None,
                    column: None,
                });
            }

            // Match the sequence of child element names against the content spec
            let consumed = match_content_spec(spec, &child_names, 0);
            match consumed {
                Some(n) if n == child_names.len() => {
                    // Perfect match
                }
                _ => {
                    errors.push(ValidationError {
                        message: format!(
                            "element '{elem_name}' content does not match \
                             declared content model {model}; \
                             found children: [{}]",
                            child_names.join(", ")
                        ),
                        line: None,
                        column: None,
                    });
                }
            }
        }
    }
}

/// Matches a content spec against a slice of element names starting at `pos`.
///
/// Returns `Some(count)` if the spec matches, consuming `count` names from
/// position `pos`. Returns `None` if no match is possible.
fn match_content_spec(spec: &ContentSpec, names: &[String], pos: usize) -> Option<usize> {
    match &spec.kind {
        ContentSpecKind::Name(expected) => match_with_occurrence(
            |all_names, p| {
                if p < all_names.len() && all_names[p] == *expected {
                    Some(1)
                } else {
                    None
                }
            },
            names,
            pos,
            spec.occurrence,
        ),
        ContentSpecKind::Seq(items) => match_with_occurrence(
            |all_names, p| {
                let mut current = p;
                for item in items {
                    match match_content_spec(item, all_names, current) {
                        Some(consumed) => current += consumed,
                        None => return None,
                    }
                }
                Some(current - p)
            },
            names,
            pos,
            spec.occurrence,
        ),
        ContentSpecKind::Choice(items) => match_with_occurrence(
            |all_names, p| {
                for item in items {
                    if let Some(consumed) = match_content_spec(item, all_names, p) {
                        return Some(consumed);
                    }
                }
                None
            },
            names,
            pos,
            spec.occurrence,
        ),
    }
}

/// Applies occurrence matching around a base matcher function.
///
/// The `base_match` function attempts a single match at a given position,
/// returning `Some(consumed)` on success.
fn match_with_occurrence(
    base_match: impl Fn(&[String], usize) -> Option<usize>,
    names: &[String],
    pos: usize,
    occurrence: Occurrence,
) -> Option<usize> {
    match occurrence {
        Occurrence::Once => base_match(names, pos),
        Occurrence::Optional => {
            // Try matching once; if it fails, succeed consuming 0
            Some(base_match(names, pos).unwrap_or(0))
        }
        Occurrence::ZeroOrMore | Occurrence::OneOrMore => {
            let mut total = 0;
            loop {
                match base_match(names, pos + total) {
                    Some(0) | None => break, // zero-width or no match
                    Some(n) => total += n,
                }
            }
            // OneOrMore requires at least one match
            if occurrence == Occurrence::OneOrMore && total == 0 {
                None
            } else {
                Some(total)
            }
        }
    }
}

/// Validates attributes for an element against DTD attribute declarations.
#[allow(clippy::too_many_arguments)]
fn validate_attributes(
    doc: &mut Document,
    dtd: &Dtd,
    node_id: NodeId,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
    _warnings: &mut Vec<ValidationError>,
    id_values: &mut HashSet<String>,
    idref_values: &mut Vec<String>,
) {
    let attr_decls = dtd.attributes.get(elem_name);
    let actual_attrs = doc.attributes(node_id).to_vec();

    if let Some(decls) = attr_decls {
        // Check each declared attribute
        for decl in decls {
            let actual = actual_attrs.iter().find(|a| a.name == decl.attribute_name);

            match (&decl.default, actual) {
                (AttributeDefault::Required, None) => {
                    errors.push(ValidationError {
                        message: format!(
                            "required attribute '{}' missing on element '{elem_name}'",
                            decl.attribute_name
                        ),
                        line: None,
                        column: None,
                    });
                }
                (AttributeDefault::Fixed(fixed_val), Some(attr)) if attr.value != *fixed_val => {
                    errors.push(ValidationError {
                        message: format!(
                            "attribute '{}' on element '{elem_name}' must have \
                             fixed value '{fixed_val}', found '{}'",
                            decl.attribute_name, attr.value
                        ),
                        line: None,
                        column: None,
                    });
                }
                _ => {}
            }

            // Type checking for present attributes
            if let Some(attr) = actual {
                validate_attribute_type(
                    doc,
                    node_id,
                    &attr.value,
                    &decl.attribute_type,
                    &decl.attribute_name,
                    elem_name,
                    errors,
                    id_values,
                    idref_values,
                );
            }
        }

        // Check for undeclared attributes (skip xmlns-related attributes)
        for attr in &actual_attrs {
            if attr.name == "xmlns" || attr.prefix.as_deref() == Some("xmlns") {
                continue;
            }
            let is_declared = decls.iter().any(|d| d.attribute_name == attr.name);
            if !is_declared {
                errors.push(ValidationError {
                    message: format!(
                        "attribute '{}' on element '{elem_name}' is not declared in the DTD",
                        attr.name
                    ),
                    line: None,
                    column: None,
                });
            }
        }
    }
}

/// Validates an attribute value against its declared type.
#[allow(clippy::too_many_arguments)]
fn validate_attribute_type(
    doc: &mut Document,
    node_id: NodeId,
    value: &str,
    attr_type: &AttributeType,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
    id_values: &mut HashSet<String>,
    idref_values: &mut Vec<String>,
) {
    match attr_type {
        AttributeType::CData => {
            // Any string is valid CDATA
        }
        AttributeType::Id => {
            validate_id_value(doc, node_id, value, attr_name, elem_name, errors, id_values);
        }
        AttributeType::IdRef => {
            validate_idref_value(value, attr_name, elem_name, errors, idref_values);
        }
        AttributeType::IdRefs => {
            validate_idrefs_value(value, attr_name, elem_name, errors, idref_values);
        }
        AttributeType::NmToken => {
            validate_nmtoken_value(value, attr_name, elem_name, errors);
        }
        AttributeType::NmTokens => {
            validate_nmtokens_value(value, attr_name, elem_name, errors);
        }
        AttributeType::Enumeration(values) | AttributeType::Notation(values) => {
            validate_enumeration_value(value, values, attr_name, elem_name, errors);
        }
        AttributeType::Entity | AttributeType::Entities => {
            validate_entity_value(value, attr_type, attr_name, elem_name, errors);
        }
    }
}

/// Validates an ID attribute value: must be a valid XML Name and unique.
///
/// On success, registers the ID in the document's `id_map` so it can be
/// looked up via [`Document::element_by_id`] and the `XPath` `id()` function.
fn validate_id_value(
    doc: &mut Document,
    node_id: NodeId,
    value: &str,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
    id_values: &mut HashSet<String>,
) {
    if !is_valid_name(value) {
        errors.push(ValidationError {
            message: format!(
                "attribute '{attr_name}' on element '{elem_name}' \
                 has invalid ID value '{value}' (not a valid XML Name)"
            ),
            line: None,
            column: None,
        });
    } else if !id_values.insert(value.to_string()) {
        errors.push(ValidationError {
            message: format!(
                "duplicate ID value '{value}' on attribute '{attr_name}' \
                 of element '{elem_name}'"
            ),
            line: None,
            column: None,
        });
    } else {
        doc.set_id(value, node_id);
    }
}

/// Validates an IDREF attribute value.
fn validate_idref_value(
    value: &str,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
    idref_values: &mut Vec<String>,
) {
    if is_valid_name(value) {
        idref_values.push(value.to_string());
    } else {
        errors.push(ValidationError {
            message: format!(
                "attribute '{attr_name}' on element '{elem_name}' \
                 has invalid IDREF value '{value}'"
            ),
            line: None,
            column: None,
        });
    }
}

/// Validates an IDREFS attribute value (space-separated list).
fn validate_idrefs_value(
    value: &str,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
    idref_values: &mut Vec<String>,
) {
    for token in value.split_whitespace() {
        if is_valid_name(token) {
            idref_values.push(token.to_string());
        } else {
            errors.push(ValidationError {
                message: format!(
                    "attribute '{attr_name}' on element '{elem_name}' \
                     has invalid IDREFS token '{token}'"
                ),
                line: None,
                column: None,
            });
        }
    }
}

/// Validates a NMTOKEN attribute value.
fn validate_nmtoken_value(
    value: &str,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    if !is_valid_nmtoken(value) {
        errors.push(ValidationError {
            message: format!(
                "attribute '{attr_name}' on element '{elem_name}' \
                 has invalid NMTOKEN value '{value}'"
            ),
            line: None,
            column: None,
        });
    }
}

/// Validates a NMTOKENS attribute value (space-separated list).
fn validate_nmtokens_value(
    value: &str,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    for token in value.split_whitespace() {
        if !is_valid_nmtoken(token) {
            errors.push(ValidationError {
                message: format!(
                    "attribute '{attr_name}' on element '{elem_name}' \
                     has invalid NMTOKENS token '{token}'"
                ),
                line: None,
                column: None,
            });
        }
    }
}

/// Validates an enumeration or notation attribute value.
fn validate_enumeration_value(
    value: &str,
    allowed: &[String],
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    if !allowed.contains(&value.to_string()) {
        errors.push(ValidationError {
            message: format!(
                "attribute '{attr_name}' on element '{elem_name}' \
                 has value '{value}' which is not in the allowed \
                 values ({})",
                allowed.join("|")
            ),
            line: None,
            column: None,
        });
    }
}

/// Validates an ENTITY or ENTITIES attribute value.
fn validate_entity_value(
    value: &str,
    attr_type: &AttributeType,
    attr_name: &str,
    elem_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Entity/Entities validation would require checking against
    // declared unparsed entities. For now we just check Name validity.
    let tokens: Vec<&str> = if matches!(attr_type, AttributeType::Entities) {
        value.split_whitespace().collect()
    } else {
        vec![value]
    };
    for token in tokens {
        if !is_valid_name(token) {
            errors.push(ValidationError {
                message: format!(
                    "attribute '{attr_name}' on element '{elem_name}' \
                     has invalid ENTITY/ENTITIES value '{token}'"
                ),
                line: None,
                column: None,
            });
        }
    }
}

/// Checks if a string is a valid XML Name.
fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) if is_name_start_char(first) => chars.all(is_name_char),
        _ => false,
    }
}

/// Checks if a string is a valid NMTOKEN.
fn is_valid_nmtoken(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_name_char)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(feature = "xmldsig")]
    #[test]
    fn scoped_dtd_model_and_serialization_share_current_limits() {
        // DTD model, duplicate declaration records, graph continuations and
        // serialization must keep current Work and actual live capacity.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        const SOURCE: &str = "<!ELEMENT root (child,child?)>\n<!ELEMENT child (#PCDATA)>\n<!ATTLIST root id ID #REQUIRED mode (a|b) 'a' fixed CDATA #FIXED 'yes'>\n<!ENTITY leaf 'α&#9;&amp;'>\n<!ENTITY parent '&leaf;'>\n<!ENTITY % parameter 'literal'>\n<!ENTITY external SYSTEM 'urn:external'>\n<!NOTATION external SYSTEM 'urn:external'>\n<!--comment--><?pi data?>";
        let expected = serialize_dtd(&parse_dtd(SOURCE).unwrap());
        let run = |capacity, local: usize, aggregate| {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, aggregate)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local as u64,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).unwrap();
            let work = reader.execution();
            let storage = Accounted(&work);
            let result = parse_dtd_in(SOURCE, storage);
            let result = match result {
                Ok(dtd) => {
                    assert_eq!(dtd.entities.len(), 3);
                    assert_eq!(dtd.param_entities.len(), 1);
                    assert_eq!(
                        Names::get(&dtd.attributes, "root", storage)
                            .unwrap()
                            .unwrap()
                            .len(),
                        3
                    );
                    let rendered = serialize_dtd_in(&dtd, storage).map_err(ParseError::Resource);
                    drop(dtd);
                    rendered
                }
                Err(error) => Err(error),
            };
            let refusal = match result {
                Ok(rendered) => {
                    assert_eq!(rendered.as_ref(), expected);
                    assert!(memory.used() >= rendered.len());
                    drop(rendered);
                    None
                }
                Err(ParseError::Resource(crate::xml::dom::ParseError::SharedExecution(error))) => {
                    Some(error)
                }
                Err(error) => panic!("unexpected DTD syntax or allocation error: {error}"),
            };
            assert_eq!(
                memory.used(),
                0,
                "all DTD storage must release on success and refusal"
            );
            (refusal, memory.work_used())
        };
        let (refusal, needed) = run(1 << 20, 1 << 24, 1 << 24);
        assert_eq!(refusal, None);
        assert!(needed > SOURCE.len());
        assert_eq!(run(1 << 20, 0, 1 << 24).0, Some(MemoryError::WorkExceeded));
        assert_eq!(run(1 << 20, 1 << 24, 0).0, Some(MemoryError::WorkExceeded));
        assert_eq!(run(0, 1 << 24, 1 << 24).0, Some(MemoryError::LimitExceeded));

        // Hash-table iteration can change graph memoization order between
        // independent parses. Exact admission is measured on the SAME retained
        // model, not guessed from another freshly seeded table's traversal.
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let owner = Parser::der(memory.clone());
        let reader = owner.read(&[], 0).unwrap();
        let producer = reader.execution();
        let dtd =
            parse_dtd_in(SOURCE, Accounted(&producer)).unwrap_or_else(|error| panic!("{error}"));
        let retained = memory.used();
        let before = memory.work_used();
        drop(serialize_dtd_in(&dtd, Accounted(&producer)).unwrap());
        let serialization_work = memory.work_used() - before;
        assert_eq!(memory.used(), retained);
        for limit in [0, serialization_work - 1, serialization_work] {
            let query = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: limit as u64,
                    ..Default::default()
                },
                memory.clone(),
            );
            let cursor = query.read(&[], 0).unwrap();
            let execution = cursor.execution();
            let result = serialize_dtd_in(&dtd, Accounted(&execution));
            if limit == serialization_work {
                assert_eq!(result.unwrap().as_ref(), expected);
            } else {
                assert!(matches!(
                    result,
                    Err(crate::xml::dom::ParseError::SharedExecution(
                        MemoryError::WorkExceeded
                    ))
                ));
            }
            assert_eq!(memory.used(), retained);
        }
        drop(dtd);
        assert_eq!(memory.used(), 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn character_reference_storage_uses_the_current_execution() {
        // The producing account having room must not bypass a local query's
        // Work ceiling; decoded text keeps its capacity charge until dropped.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        let source = "π&#37;&#x1F600;&retained;尾";
        let expected = "π%😀&retained;尾";
        assert_eq!(expand_char_refs_only(source, Native).unwrap(), expected);

        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 0,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let work = reader.execution();
        assert!(matches!(
            expand_char_refs_only(source, Accounted(&work)),
            Err(crate::xml::dom::ParseError::SharedExecution(
                MemoryError::WorkExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
        assert_eq!(memory.work_used(), 0);

        let decoded = expand_char_refs_only(source, Accounted(&memory)).unwrap();
        assert_eq!(&*decoded, expected);
        assert!(memory.used() >= source.len());
        drop(decoded);
        assert_eq!(memory.used(), 0);

        let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 24)));
        assert!(matches!(
            expand_char_refs_only(source, Accounted(&denied)),
            Err(crate::xml::dom::ParseError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(denied.used(), 0);
    }

    // --- DTD Parsing Tests ---

    #[test]
    fn test_parse_element_empty() {
        let dtd = parse_dtd("<!ELEMENT br EMPTY>").unwrap();
        let decl = dtd.elements.get("br").unwrap();
        assert_eq!(decl.content_model, ContentModel::Empty);
    }

    #[test]
    fn test_parse_element_any() {
        let dtd = parse_dtd("<!ELEMENT container ANY>").unwrap();
        let decl = dtd.elements.get("container").unwrap();
        assert_eq!(decl.content_model, ContentModel::Any);
    }

    #[test]
    fn test_parse_element_pcdata() {
        let dtd = parse_dtd("<!ELEMENT title (#PCDATA)>").unwrap();
        let decl = dtd.elements.get("title").unwrap();
        assert_eq!(decl.content_model, ContentModel::Mixed(vec![]));
    }

    #[test]
    fn test_parse_element_mixed_content() {
        let dtd = parse_dtd("<!ELEMENT p (#PCDATA|em|strong)*>").unwrap();
        let decl = dtd.elements.get("p").unwrap();
        assert_eq!(
            decl.content_model,
            ContentModel::Mixed(vec!["em".to_string(), "strong".to_string()])
        );
    }

    #[test]
    fn test_parse_element_sequence() {
        let dtd = parse_dtd("<!ELEMENT book (title,author,year)>").unwrap();
        let decl = dtd.elements.get("book").unwrap();
        match &decl.content_model {
            ContentModel::Children(spec) => {
                assert_eq!(spec.occurrence, Occurrence::Once);
                match &spec.kind {
                    ContentSpecKind::Seq(items) => {
                        assert_eq!(items.len(), 3);
                        assert_eq!(items[0].kind, ContentSpecKind::Name("title".to_string()));
                        assert_eq!(items[1].kind, ContentSpecKind::Name("author".to_string()));
                        assert_eq!(items[2].kind, ContentSpecKind::Name("year".to_string()));
                    }
                    other => panic!("expected Seq, got {other:?}"),
                }
            }
            other => panic!("expected Children, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_element_choice() {
        let dtd = parse_dtd("<!ELEMENT item (a|b|c)>").unwrap();
        let decl = dtd.elements.get("item").unwrap();
        match &decl.content_model {
            ContentModel::Children(spec) => match &spec.kind {
                ContentSpecKind::Choice(items) => {
                    assert_eq!(items.len(), 3);
                }
                other => panic!("expected Choice, got {other:?}"),
            },
            other => panic!("expected Children, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_element_occurrence_indicators() {
        let dtd = parse_dtd("<!ELEMENT doc (head, body?, appendix*)>").unwrap();
        let decl = dtd.elements.get("doc").unwrap();
        match &decl.content_model {
            ContentModel::Children(spec) => match &spec.kind {
                ContentSpecKind::Seq(items) => {
                    assert_eq!(items[0].occurrence, Occurrence::Once);
                    assert_eq!(items[1].occurrence, Occurrence::Optional);
                    assert_eq!(items[2].occurrence, Occurrence::ZeroOrMore);
                }
                other => panic!("expected Seq, got {other:?}"),
            },
            other => panic!("expected Children, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_element_nested_groups() {
        let dtd = parse_dtd("<!ELEMENT article ((title, author), body)>").unwrap();
        let decl = dtd.elements.get("article").unwrap();
        match &decl.content_model {
            ContentModel::Children(spec) => match &spec.kind {
                ContentSpecKind::Seq(items) => {
                    assert_eq!(items.len(), 2);
                    // First item is a nested sequence (title, author)
                    match &items[0].kind {
                        ContentSpecKind::Seq(inner) => {
                            assert_eq!(inner.len(), 2);
                        }
                        other => panic!("expected nested Seq, got {other:?}"),
                    }
                }
                other => panic!("expected Seq, got {other:?}"),
            },
            other => panic!("expected Children, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_attlist_cdata() {
        let dtd = parse_dtd("<!ATTLIST img src CDATA #REQUIRED>").unwrap();
        let decls = dtd.attributes.get("img").unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].attribute_name, "src");
        assert_eq!(decls[0].attribute_type, AttributeType::CData);
        assert_eq!(decls[0].default, AttributeDefault::Required);
    }

    #[test]
    fn test_parse_attlist_id() {
        let dtd = parse_dtd("<!ATTLIST div id ID #IMPLIED>").unwrap();
        let decls = dtd.attributes.get("div").unwrap();
        assert_eq!(decls[0].attribute_type, AttributeType::Id);
        assert_eq!(decls[0].default, AttributeDefault::Implied);
    }

    #[test]
    fn test_parse_attlist_enumeration() {
        let dtd = parse_dtd("<!ATTLIST input type (text|password|submit) \"text\">").unwrap();
        let decls = dtd.attributes.get("input").unwrap();
        assert_eq!(
            decls[0].attribute_type,
            AttributeType::Enumeration(vec![
                "text".to_string(),
                "password".to_string(),
                "submit".to_string()
            ])
        );
        assert_eq!(
            decls[0].default,
            AttributeDefault::Default("text".to_string())
        );
    }

    #[test]
    fn test_parse_attlist_fixed() {
        let dtd = parse_dtd("<!ATTLIST doc version CDATA #FIXED \"1.0\">").unwrap();
        let decls = dtd.attributes.get("doc").unwrap();
        assert_eq!(decls[0].default, AttributeDefault::Fixed("1.0".to_string()));
    }

    #[test]
    fn test_parse_attlist_multiple_attrs() {
        let dtd =
            parse_dtd("<!ATTLIST person\n  name CDATA #REQUIRED\n  age NMTOKEN #IMPLIED>").unwrap();
        let decls = dtd.attributes.get("person").unwrap();
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].attribute_name, "name");
        assert_eq!(decls[1].attribute_name, "age");
        assert_eq!(decls[1].attribute_type, AttributeType::NmToken);
    }

    #[test]
    fn test_parse_entity_internal() {
        let dtd = parse_dtd("<!ENTITY copy \"&#169;\">").unwrap();
        let ent = dtd.entities.get("copy").unwrap();
        match &ent.kind {
            EntityKind::Internal(value) => assert_eq!(value, "&#169;"),
            EntityKind::External { .. } => panic!("expected Internal, got External"),
        }
    }

    #[test]
    fn test_parse_entity_external() {
        let dtd = parse_dtd("<!ENTITY chapter SYSTEM \"chapter.xml\">").unwrap();
        let ent = dtd.entities.get("chapter").unwrap();
        match &ent.kind {
            EntityKind::External {
                system_id,
                public_id,
            } => {
                assert_eq!(system_id, "chapter.xml");
                assert_eq!(*public_id, None);
            }
            EntityKind::Internal(val) => panic!("expected External, got Internal({val})"),
        }
    }

    #[test]
    fn test_parse_notation() {
        let dtd = parse_dtd("<!NOTATION png SYSTEM \"image/png\">").unwrap();
        let notation = dtd.notations.get("png").unwrap();
        assert_eq!(notation.system_id.as_deref(), Some("image/png"));
    }

    #[test]
    fn test_parse_dtd_with_comments() {
        let dtd = parse_dtd(
            "<!-- element declarations -->\n\
             <!ELEMENT root (#PCDATA)>\n\
             <!-- end -->",
        )
        .unwrap();
        assert!(dtd.elements.contains_key("root"));
    }

    #[test]
    fn test_parse_dtd_complex() {
        let input = "\
            <!ELEMENT doc (head, body)>\n\
            <!ELEMENT head (title)>\n\
            <!ELEMENT title (#PCDATA)>\n\
            <!ELEMENT body (p+)>\n\
            <!ELEMENT p (#PCDATA|em)*>\n\
            <!ELEMENT em (#PCDATA)>\n\
            <!ATTLIST doc version CDATA #FIXED \"1.0\">\n\
            <!ATTLIST p id ID #IMPLIED>\n\
            <!ENTITY copyright \"Copyright 2024\">\n";
        let dtd = parse_dtd(input).unwrap();
        assert_eq!(dtd.elements.len(), 6);
        assert!(dtd.attributes.contains_key("doc"));
        assert!(dtd.attributes.contains_key("p"));
        assert!(dtd.entities.contains_key("copyright"));
    }

    // --- Validation Tests ---

    fn make_doc(xml: &str) -> Document {
        Document::parse_str(xml).unwrap()
    }

    #[test]
    fn test_validate_valid_document() {
        let dtd = parse_dtd("<!ELEMENT root (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE root><root>hello</root>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_root_name_mismatch() {
        let dtd = parse_dtd("<!ELEMENT root (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE root><other>text</other>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("root element 'other'")
                    && e.message.contains("does not match DOCTYPE name 'root'")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_empty_element() {
        let dtd = parse_dtd("<!ELEMENT br EMPTY>").unwrap();
        let mut doc = make_doc("<!DOCTYPE br><br/>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_empty_element_has_content() {
        let dtd = parse_dtd("<!ELEMENT br EMPTY>").unwrap();
        let mut doc = make_doc("<!DOCTYPE br><br>text</br>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("EMPTY") && e.message.contains("has content")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_any_content() {
        let dtd = parse_dtd(
            "<!ELEMENT container ANY>\n\
             <!ELEMENT child (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE container><container><child>text</child></container>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_sequence_correct() {
        let dtd = parse_dtd(
            "<!ELEMENT book (title,author)>\n\
             <!ELEMENT title (#PCDATA)>\n\
             <!ELEMENT author (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE book>\
             <book><title>XML</title><author>Jon</author></book>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_sequence_wrong_order() {
        let dtd = parse_dtd(
            "<!ELEMENT book (title,author)>\n\
             <!ELEMENT title (#PCDATA)>\n\
             <!ELEMENT author (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE book>\
             <book><author>Jon</author><title>XML</title></book>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("content does not match")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_required_attribute_missing() {
        let dtd = parse_dtd(
            "<!ELEMENT img EMPTY>\n\
             <!ATTLIST img src CDATA #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE img><img/>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("required attribute 'src'")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_required_attribute_present() {
        let dtd = parse_dtd(
            "<!ELEMENT img EMPTY>\n\
             <!ATTLIST img src CDATA #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE img><img src=\"photo.jpg\"/>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_fixed_attribute_correct() {
        let dtd = parse_dtd(
            "<!ELEMENT doc (#PCDATA)>\n\
             <!ATTLIST doc version CDATA #FIXED \"1.0\">",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE doc><doc version=\"1.0\">text</doc>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_fixed_attribute_wrong_value() {
        let dtd = parse_dtd(
            "<!ELEMENT doc (#PCDATA)>\n\
             <!ATTLIST doc version CDATA #FIXED \"1.0\">",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE doc><doc version=\"2.0\">text</doc>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("fixed value '1.0'")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_enumeration_valid() {
        let dtd = parse_dtd(
            "<!ELEMENT input EMPTY>\n\
             <!ATTLIST input type (text|password) #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE input><input type=\"text\"/>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_enumeration_invalid() {
        let dtd = parse_dtd(
            "<!ELEMENT input EMPTY>\n\
             <!ATTLIST input type (text|password) #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE input><input type=\"checkbox\"/>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("not in the allowed values")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_duplicate_id() {
        let dtd = parse_dtd(
            "<!ELEMENT root (item, item)>\n\
             <!ELEMENT item (#PCDATA)>\n\
             <!ATTLIST item id ID #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE root>\
             <root>\
               <item id=\"a\">first</item>\
               <item id=\"a\">second</item>\
             </root>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("duplicate ID value 'a'")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_idref_valid() {
        let dtd = parse_dtd(
            "<!ELEMENT root (item, ref)>\n\
             <!ELEMENT item (#PCDATA)>\n\
             <!ELEMENT ref (#PCDATA)>\n\
             <!ATTLIST item id ID #REQUIRED>\n\
             <!ATTLIST ref target IDREF #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE root>\
             <root>\
               <item id=\"x\">item</item>\
               <ref target=\"x\">ref</ref>\
             </root>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_idref_dangling() {
        let dtd = parse_dtd(
            "<!ELEMENT root (ref)>\n\
             <!ELEMENT ref (#PCDATA)>\n\
             <!ATTLIST ref target IDREF #REQUIRED>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE root>\
             <root><ref target=\"nonexistent\">ref</ref></root>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result.errors.iter().any(|e| e
                .message
                .contains("IDREF 'nonexistent' does not match any ID")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_undeclared_element() {
        let dtd = parse_dtd("<!ELEMENT root (child)>\n<!ELEMENT child (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE root><root><unknown/></root>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("element 'unknown' is not declared")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_undeclared_attribute() {
        let dtd = parse_dtd(
            "<!ELEMENT root (#PCDATA)>\n\
             <!ATTLIST root id ID #IMPLIED>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE root><root id=\"x\" bogus=\"y\">text</root>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("attribute 'bogus'")
                    && e.message.contains("not declared")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_mixed_content_valid() {
        let dtd = parse_dtd(
            "<!ELEMENT p (#PCDATA|em|strong)*>\n\
             <!ELEMENT em (#PCDATA)>\n\
             <!ELEMENT strong (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE p>\
             <p>Hello <em>world</em> and <strong>friends</strong></p>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_mixed_content_invalid_child() {
        let dtd = parse_dtd(
            "<!ELEMENT p (#PCDATA|em)*>\n\
             <!ELEMENT em (#PCDATA)>\n\
             <!ELEMENT b (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc(
            "<!DOCTYPE p>\
             <p>Hello <b>world</b></p>",
        );
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("'b' is not allowed in mixed content")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_choice_correct() {
        let dtd = parse_dtd(
            "<!ELEMENT item (a|b)>\n\
             <!ELEMENT a (#PCDATA)>\n\
             <!ELEMENT b (#PCDATA)>",
        )
        .unwrap();
        let mut doc = make_doc("<!DOCTYPE item><item><b>hello</b></item>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_one_or_more() {
        let dtd = parse_dtd("<!ELEMENT list (item+)>\n<!ELEMENT item (#PCDATA)>").unwrap();

        // Valid: one item
        let mut doc = make_doc("<!DOCTYPE list><list><item>a</item></list>");
        assert!(validate(&mut doc, &dtd).is_valid);

        // Valid: multiple items
        let mut doc = make_doc("<!DOCTYPE list><list><item>a</item><item>b</item></list>");
        assert!(validate(&mut doc, &dtd).is_valid);

        // Invalid: zero items
        let mut doc = make_doc("<!DOCTYPE list><list></list>");
        assert!(!validate(&mut doc, &dtd).is_valid);
    }

    #[test]
    fn test_validate_zero_or_more() {
        let dtd = parse_dtd("<!ELEMENT list (item*)>\n<!ELEMENT item (#PCDATA)>").unwrap();

        // Valid: zero items
        let mut doc = make_doc("<!DOCTYPE list><list></list>");
        assert!(validate(&mut doc, &dtd).is_valid);

        // Valid: multiple items
        let mut doc = make_doc("<!DOCTYPE list><list><item>a</item><item>b</item></list>");
        assert!(validate(&mut doc, &dtd).is_valid);
    }

    #[test]
    fn test_validate_optional_element() {
        let dtd = parse_dtd(
            "<!ELEMENT doc (title, subtitle?)>\n\
             <!ELEMENT title (#PCDATA)>\n\
             <!ELEMENT subtitle (#PCDATA)>",
        )
        .unwrap();

        // Valid: with optional
        let mut doc = make_doc(
            "<!DOCTYPE doc>\
             <doc><title>T</title><subtitle>S</subtitle></doc>",
        );
        assert!(validate(&mut doc, &dtd).is_valid);

        // Valid: without optional
        let mut doc = make_doc("<!DOCTYPE doc><doc><title>T</title></doc>");
        assert!(validate(&mut doc, &dtd).is_valid);
    }

    #[test]
    fn test_content_model_display() {
        assert_eq!(ContentModel::<Native>::Empty.to_string(), "EMPTY");
        assert_eq!(ContentModel::<Native>::Any.to_string(), "ANY");
        assert_eq!(
            ContentModel::<Native>::Mixed(vec![]).to_string(),
            "(#PCDATA)"
        );
        assert_eq!(
            ContentModel::<Native>::Mixed(vec!["a".to_string(), "b".to_string()]).to_string(),
            "(#PCDATA|a|b)*"
        );

        let spec: ContentSpec = ContentSpec {
            kind: ContentSpecKind::Seq(vec![
                ContentSpec {
                    kind: ContentSpecKind::Name("a".to_string()),
                    occurrence: Occurrence::Once,
                },
                ContentSpec {
                    kind: ContentSpecKind::Name("b".to_string()),
                    occurrence: Occurrence::ZeroOrMore,
                },
            ]),
            occurrence: Occurrence::Once,
        };
        assert_eq!(ContentModel::Children(spec).to_string(), "(a , b*)");
    }

    #[test]
    fn test_parse_attlist_idref_idrefs() {
        let dtd = parse_dtd(
            "<!ATTLIST link target IDREF #REQUIRED>\n\
             <!ATTLIST group members IDREFS #REQUIRED>",
        )
        .unwrap();
        let link_decls = dtd.attributes.get("link").unwrap();
        assert_eq!(link_decls[0].attribute_type, AttributeType::IdRef);
        let group_decls = dtd.attributes.get("group").unwrap();
        assert_eq!(group_decls[0].attribute_type, AttributeType::IdRefs);
    }

    #[test]
    fn test_validate_element_content_with_text() {
        let dtd = parse_dtd("<!ELEMENT book (title)>\n<!ELEMENT title (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE book><book>stray text<title>T</title></book>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("element-only content model")
                    && e.message.contains("contains text")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_parse_entity_public() {
        let dtd = parse_dtd("<!ENTITY logo PUBLIC \"-//LOGO//\" \"logo.png\">").unwrap();
        let ent = dtd.entities.get("logo").unwrap();
        match &ent.kind {
            EntityKind::External {
                system_id,
                public_id,
            } => {
                assert_eq!(system_id, "logo.png");
                assert_eq!(public_id.as_deref(), Some("-//LOGO//"));
            }
            EntityKind::Internal(val) => panic!("expected External, got Internal({val})"),
        }
    }

    #[test]
    fn test_parse_notation_public() {
        let dtd = parse_dtd("<!NOTATION gif PUBLIC \"-//GIF//\">").unwrap();
        let notation = dtd.notations.get("gif").unwrap();
        assert_eq!(notation.public_id.as_deref(), Some("-//GIF//"));
        assert_eq!(notation.system_id, None);
    }

    #[test]
    fn test_parse_parameter_entity_skipped() {
        // Parameter entities should be skipped without error
        let dtd = parse_dtd(
            "<!ENTITY % common \"(#PCDATA)\">\n\
             <!ELEMENT root (#PCDATA)>",
        )
        .unwrap();
        assert!(dtd.elements.contains_key("root"));
    }

    #[test]
    fn test_validate_nmtoken_attribute() {
        let dtd = parse_dtd(
            "<!ELEMENT root (#PCDATA)>\n\
             <!ATTLIST root token NMTOKEN #REQUIRED>",
        )
        .unwrap();

        // Valid NMTOKEN
        let mut doc = make_doc("<!DOCTYPE root><root token=\"abc-123\">text</root>");
        assert!(validate(&mut doc, &dtd).is_valid);

        // Invalid NMTOKEN (spaces not allowed)
        let mut doc = make_doc("<!DOCTYPE root><root token=\"abc 123\">text</root>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("invalid NMTOKEN")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_populates_id_map() {
        let dtd = parse_dtd(
            "<!ELEMENT root (item*)>\n\
             <!ELEMENT item (#PCDATA)>\n\
             <!ATTLIST item id ID #REQUIRED>",
        )
        .unwrap();
        let mut doc =
            make_doc(r#"<!DOCTYPE root><root><item id="a">A</item><item id="b">B</item></root>"#);
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);

        // The id_map should have been populated
        let item_a = doc.element_by_id("a");
        assert!(item_a.is_some(), "expected to find element with id='a'");
        let item_b = doc.element_by_id("b");
        assert!(item_b.is_some(), "expected to find element with id='b'");
        assert_eq!(doc.element_by_id("c"), None);

        // Verify the nodes are the correct elements
        assert_eq!(doc.node_name(item_a.unwrap()), Some("item"));
        assert_eq!(doc.node_name(item_b.unwrap()), Some("item"));
    }

    #[test]
    fn content_model_at_depth_ceiling_can_copy_serialize_and_drop() {
        // Valid groups at the ceiling exercise the retained AST, not just
        // rejection before the parser has constructed nested nodes.
        let mut source = String::from("<!ELEMENT root ");
        for _ in 0..MAX_CONTENT_MODEL_DEPTH {
            source.push_str("(a,");
        }
        source.push('b');
        for _ in 0..MAX_CONTENT_MODEL_DEPTH {
            source.push(')');
        }
        source.push('>');
        let dtd = parse_dtd(&source).unwrap();
        let rendered = serialize_dtd(&dtd);
        let reparsed = parse_dtd(&rendered).unwrap();
        assert_eq!(serialize_dtd(&reparsed), rendered);
    }

    #[test]
    fn test_content_model_deep_nesting_is_bounded() {
        // Regression test for CVE-2026-61727 (GHSA-7jmw-29gc-ffx4): a content
        // model with deeply nested '(' must return a normal error instead of
        // recursing until the stack overflows.
        let depth = (MAX_CONTENT_MODEL_DEPTH as usize) + 50;
        let mut src = String::from("<!ELEMENT r ");
        src.push_str(&"(".repeat(depth));
        src.push('a');
        src.push_str(&")".repeat(depth));
        src.push('>');

        let result = parse_dtd(&src);
        let Err(err) = result else {
            panic!("expected deep content model to be rejected, got Ok");
        };
        assert!(
            err.syntax_message().contains("maximum depth"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_content_model_shallow_nesting_still_parses() {
        // The depth bound must not affect ordinary, shallowly-nested models.
        let dtd = parse_dtd("<!ELEMENT a (b,(c|d),e)>").unwrap();
        assert!(dtd.elements.contains_key("a"));
    }

    // --- Entity recursion checks (WFC: No Recursion, XML 1.0 §4.1) ---

    #[test]
    fn test_entity_recursion_direct_cycle_rejected() {
        let err = parse_dtd("<!ENTITY x \"&x;\">").unwrap_err();
        assert!(
            err.syntax_message().contains("recursive entity reference"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_entity_recursion_indirect_cycle_rejected() {
        let err =
            parse_dtd("<!ENTITY a \"&b;\"><!ENTITY b \"&c;\"><!ENTITY c \"&a;\">").unwrap_err();
        assert!(
            err.syntax_message().contains("recursive entity reference"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_entity_recursion_cycle_behind_safe_entity_rejected() {
        // Regression test for the memoized walk (issue #42): `ok` is acyclic
        // and shared by both cycle members. Marking `ok` as proven-safe must
        // not mask the a<->b cycle behind it.
        let err = parse_dtd(
            "<!ENTITY ok \"text\">\
             <!ENTITY a \"&ok;&b;\">\
             <!ENTITY b \"&ok;&a;\">",
        )
        .unwrap_err();
        assert!(
            err.syntax_message().contains("recursive entity reference"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_entity_recursion_acyclic_diamond_accepted() {
        // d is reachable through two paths (a->b->d and a->c->d) but there
        // is no cycle; the memoized walk must accept this.
        let dtd = parse_dtd(
            "<!ENTITY d \"leaf\">\
             <!ENTITY b \"&d;&d;\">\
             <!ENTITY c \"&d;&d;\">\
             <!ENTITY a \"&b;&c;\">",
        )
        .unwrap();
        assert_eq!(dtd.entities.len(), 4);
    }

    #[test]
    fn test_entity_recursion_deep_chain_is_linear() {
        // Regression test for issue #42: each level references the previous
        // entity 10 times. Without memoization the recursion check walks
        // 10^30 paths and never finishes; with it, this parses instantly.
        use std::fmt::Write as _;
        let mut src = String::from("<!ENTITY a \"AAAA\">");
        for i in 1..=30u32 {
            let prev = if i == 1 {
                "a".to_string()
            } else {
                format!("e{}", i - 1)
            };
            let refs = format!("&{prev};").repeat(10);
            let _ = write!(src, "<!ENTITY e{i} \"{refs}\">");
        }
        let dtd = parse_dtd(&src).unwrap();
        assert_eq!(dtd.entities.len(), 31);
    }

    #[test]
    fn entity_declaration_chain_does_not_use_the_call_stack() {
        // Declaration depth is independent of element depth. Start explicitly
        // at the chain head so hash-table iteration cannot hide recursive DFS.
        let mut parser = DtdParser::new("");
        for index in 0..8192 {
            let name = format!("e{index}");
            Names::insert(
                &mut parser.dtd.entities,
                name.clone(),
                EntityDecl {
                    name,
                    kind: EntityKind::Internal(if index == 8191 {
                        "leaf".to_owned()
                    } else {
                        format!("&e{};", index + 1)
                    }),
                },
            )
            .unwrap();
        }
        let mut visited = Native.names();
        Names::insert(&mut visited, "e0", ()).unwrap();
        let mut safe = Native.names();
        let EntityKind::Internal(value) = &parser.dtd.entities["e0"].kind else {
            unreachable!()
        };
        parser
            .check_entity_recursion(value, &mut visited, &mut safe)
            .unwrap();
        assert_eq!(safe.len(), 8191);
        assert_eq!(visited.len(), 1);
        assert!(visited.contains_key("e0"));
    }

    #[test]
    fn parameter_declaration_chain_does_not_use_the_call_stack() {
        // Encoded PE references need the same stack safety as general entities;
        // declaration graphs are not constrained by the document element depth.
        let mut parser = DtdParser::new("");
        for index in 0..8192 {
            let name = format!("e{index}");
            Names::insert(
                &mut parser.dtd.param_entities,
                name.clone(),
                EntityDecl {
                    name,
                    kind: EntityKind::Internal(if index == 8191 {
                        "leaf".to_owned()
                    } else {
                        format!("&#37;e{};", index + 1)
                    }),
                },
            )
            .unwrap();
        }
        let mut visited = Native.names();
        Names::insert(&mut visited, "e0", ()).unwrap();
        let mut safe = Native.names();
        parser
            .check_pe_recursion("%e1;", &mut visited, &mut safe)
            .unwrap();
        assert_eq!(safe.len(), 8191);
        assert_eq!(visited.len(), 1);
        assert!(visited.contains_key("e0"));
    }

    #[test]
    fn attribute_default_entity_chain_does_not_use_the_call_stack() {
        // Acyclicity has already been established, but validating the same
        // graph for attribute defaults must not reintroduce native recursion.
        let mut parser = DtdParser::new("");
        for index in 0..8192 {
            let name = format!("e{index}");
            Names::insert(
                &mut parser.dtd.entities,
                name.clone(),
                EntityDecl {
                    name,
                    kind: EntityKind::Internal(if index == 8191 {
                        "leaf".to_owned()
                    } else {
                        format!("&e{};", index + 1)
                    }),
                },
            )
            .unwrap();
        }
        let mut checked = Native.names();
        parser
            .validate_attr_default_entities("&e0;", &mut checked)
            .unwrap();
        assert_eq!(checked.len(), 8192);
    }

    #[test]
    fn test_pe_recursion_direct_cycle_rejected() {
        // %p; encoded as &#37;p; inside the value (XML 1.0 §4.1).
        let err = parse_dtd("<!ENTITY % p \"&#37;p;\">").unwrap_err();
        assert!(
            err.syntax_message()
                .contains("recursive parameter entity reference"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_pe_recursion_indirect_cycle_rejected() {
        let err = parse_dtd("<!ENTITY % p \"&#37;q;\"><!ENTITY % q \"&#37;p;\">").unwrap_err();
        assert!(
            err.syntax_message()
                .contains("recursive parameter entity reference"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    // --- Content-model validation through entity references (§4.4.3) ---

    #[test]
    fn test_validate_entity_supplied_child_matches_model() {
        // The required <x> child arrives via an entity reference; the
        // content model must see through the EntityRef node.
        let dtd = parse_dtd("<!ELEMENT d (x)><!ELEMENT x (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE d [<!ENTITY e \"<x>hi</x>\">]><d>&e;</d>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_entity_supplied_child_violates_model() {
        // An entity-supplied element that violates the content model must
        // still be reported.
        let dtd =
            parse_dtd("<!ELEMENT d (x)><!ELEMENT x (#PCDATA)><!ELEMENT y (#PCDATA)>").unwrap();
        let mut doc = make_doc("<!DOCTYPE d [<!ENTITY e \"<y>hi</y>\">]><d>&e;</d>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid, "expected content-model violation");
    }

    #[test]
    fn test_validate_entity_supplied_element_content_checked() {
        // Elements inside entity expansions are themselves validated: <x>
        // is declared EMPTY but the entity gives it text content.
        let dtd = parse_dtd("<!ELEMENT d (x)><!ELEMENT x EMPTY>").unwrap();
        let mut doc = make_doc("<!DOCTYPE d [<!ENTITY e \"<x>hi</x>\">]><d>&e;</d>");
        let result = validate(&mut doc, &dtd);
        assert!(!result.is_valid, "expected EMPTY-content violation");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("EMPTY") && e.message.contains("has content")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_mixed_content_through_entity() {
        let dtd = parse_dtd("<!ELEMENT p (#PCDATA|em)*><!ELEMENT em (#PCDATA)>").unwrap();
        let mut doc =
            make_doc("<!DOCTYPE p [<!ENTITY e \"text <em>emph</em>\">]><p>before &e; after</p>");
        let result = validate(&mut doc, &dtd);
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }
}
