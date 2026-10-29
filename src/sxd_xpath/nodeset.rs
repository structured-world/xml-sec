//! Support for collections of nodes.

#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
#[cfg(feature = "embedded")]
use alloc::string::ToString;
use alloc::{
    borrow::{Cow, ToOwned},
    format,
    string::String,
    vec::Vec,
};
use core::iter::{FromIterator, IntoIterator};
use core::mem::size_of;
use sxd_document_no_unsafe::NsStr;
use sxd_document_no_unsafe::QName;
use sxd_document_no_unsafe::dom;

#[path = "nodeset/storage.rs"]
pub(crate) mod storage;
use crate::collections::{Set, set};
use storage::Storage;

#[cfg(feature = "no-unsafe")]
use crate::OwnedQName;

#[cfg(not(feature = "no-unsafe"))]
pub type ExpandedName<'d> = QName<'d>;
#[cfg(feature = "no-unsafe")]
pub type ExpandedName<'d> = OwnedQName;

#[cfg(not(feature = "no-unsafe"))]
macro_rules! to_expanded_name {
    ($e:expr) => {
        $e
    };
}

#[cfg(feature = "no-unsafe")]
macro_rules! to_expanded_name {
    ($e:expr) => {
        OwnedQName::from($e)
    };
}

macro_rules! unpack(
    ($enum_name:ident, {
        $($name:ident, $wrapper:ident, dom::$inner:ident),*
    }) => (
        $(
            pub fn $name(&self) -> Option<dom::$inner<'d>> {
                match self {
                    $enum_name::$wrapper(n) => Some(*n),
                    _ => None,
                }
            }
        )*
    )
);

macro_rules! conversion_trait(
    ($res_type:ident, {
        $(dom::$leaf_type:ident => Node::$variant:ident),*
    }) => (
        $(impl<'d> From<dom::$leaf_type<'d>> for $res_type<'d>  {
            fn from(v: dom::$leaf_type<'d>) -> $res_type<'d> {
                Node::$variant(v)
            }
        })*
    )
);

/// Represents a namespace.
///
/// This differs from the DOM, which does not treat namespaces as a
/// separate item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Namespace<'d> {
    pub parent: dom::Element<'d>,
    pub prefix: NsStr<'d>,
    pub uri: NsStr<'d>,
}

#[cfg(not(feature = "no-unsafe"))]
impl<'d> Copy for Namespace<'d> {}

impl<'d> Namespace<'d> {
    #[must_use]
    pub fn document(&self) -> dom::Document<'d> {
        self.parent.document()
    }
    #[must_use]
    pub fn parent(&self) -> dom::Element<'d> {
        self.parent
    }
    #[must_use]
    pub fn prefix(&self) -> &str {
        sxd_document_no_unsafe::as_str!(self.prefix)
    }
    #[must_use]
    pub fn uri(&self) -> &str {
        sxd_document_no_unsafe::as_str!(self.uri)
    }
    #[must_use]
    pub fn expanded_name(&self) -> ExpandedName<'d> {
        to_expanded_name!(QName::new(sxd_document_no_unsafe::as_str!(self.prefix)))
    }
}

#[cfg(feature = "embedded")]
pub(crate) type DeclarationText<'a, 'd> = sxd_document_no_unsafe::string_pool::Label<'a>;
#[cfg(all(feature = "no-unsafe", not(feature = "embedded")))]
pub(crate) type DeclarationText<'a, 'd> = &'a str;
#[cfg(not(feature = "no-unsafe"))]
pub(crate) type DeclarationText<'a, 'd> = &'d str;

fn declaration_str<'a, 'd: 'a>(text: DeclarationText<'a, 'd>) -> &'a str {
    #[cfg(feature = "embedded")]
    {
        text.as_str()
    }
    #[cfg(not(feature = "embedded"))]
    {
        text
    }
}

fn declaration_constant<'a, 'd>(text: &'static str) -> DeclarationText<'a, 'd> {
    #[cfg(feature = "embedded")]
    {
        sxd_document_no_unsafe::string_pool::Label::Static(text)
    }
    #[cfg(not(feature = "embedded"))]
    {
        text
    }
}

/// Enumerate effective bindings without collecting DOM namespaces or cloning their URIs.
/// Nearest declarations win; a callback break or error stops the underlying DOM visitor.
pub(crate) fn visit_namespace_bindings_in<
    'd,
    E: From<crate::function::Error>,
    R: crate::runtime::Runtime,
>(
    owner: dom::Element<'d>,
    context: &crate::context::Evaluation<'_, 'd>,
    runtime: R,
    mut visit: impl FnMut(
        DeclarationText<'_, 'd>,
        DeclarationText<'_, 'd>,
    ) -> Result<core::ops::ControlFlow<()>, E>,
) -> Result<(), E> {
    use crate::runtime::NamespaceSet;
    use core::ops::ControlFlow;
    // XPath 1.0 §5.4 supplies xml independently of declarations. Emit it
    // before allocating shadow state; no ancestor can override this binding.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#namespace-nodes
    let implicit_prefix = declaration_constant("xml");
    let implicit_uri = declaration_constant("http://www.w3.org/XML/1998/namespace");
    context.charge_work(implicit_prefix.len().saturating_add(implicit_uri.len()))?;
    if let ControlFlow::Break(()) = visit(implicit_prefix, implicit_uri)? {
        return Ok(());
    }
    let mut seen = runtime.namespaces();
    let mut emit =
        |prefix: DeclarationText<'_, 'd>, uri: DeclarationText<'_, 'd>| -> Result<(), Option<E>> {
            context
                .charge_work(prefix.len().saturating_add(uri.len()).max(1))
                .map_err(|error| Some(E::from(error)))?;
            if declaration_str(prefix) == "xml" {
                return Ok(());
            }
            if !seen
                .insert(context, prefix)
                .map_err(|error| Some(E::from(error)))?
            {
                return Ok(());
            }
            // XPath 1.0 section 5.4: empty declarations shadow ancestors but are not nodes.
            // https://www.w3.org/TR/xpath/#namespace-nodes
            if uri.is_empty() {
                return Ok(());
            }
            match visit(prefix, uri).map_err(Some)? {
                ControlFlow::Continue(()) => Ok(()),
                ControlFlow::Break(()) => Err(None),
            }
        };
    let mut current = Some(owner);
    while let Some(element) = current {
        match runtime
            .namespace_declarations(element, context, &mut emit)
            .map_err(E::from)?
        {
            Err(None) => return Ok(()),
            Err(Some(error)) => return Err(error),
            Ok(()) => {}
        }
        current = element.parent().and_then(dom::ParentOfChild::element);
    }
    Ok(())
}

/// Any of the various types of nodes found in an XML document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node<'d> {
    Root(dom::Root<'d>),
    Element(dom::Element<'d>),
    Attribute(dom::Attribute<'d>),
    Text(dom::Text<'d>),
    Comment(dom::Comment<'d>),
    Namespace(Namespace<'d>),
    ProcessingInstruction(dom::ProcessingInstruction<'d>),
}

#[cfg(not(feature = "no-unsafe"))]
impl<'d> Copy for Node<'d> {}

#[cfg(feature = "embedded")]
impl structured_asn1::memory::HashWork for Node<'_> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        // Arena handles hash fixed identity words. A namespace additionally
        // hashes its retained prefix/URI; no producer credit pays these bytes.
        let mut units = 32u64;
        if let Self::Namespace(namespace) = self {
            units = units
                .checked_add(namespace.prefix().len() as u64)
                .and_then(|units| units.checked_add(namespace.uri().len() as u64))
                .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)?;
        }
        Ok(units)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum NamePart {
    Local,
    Namespace,
    Qualified,
}

impl<'d> Node<'d> {
    pub(crate) fn name_in<R: crate::runtime::Runtime>(
        &self,
        part: NamePart,
        context: &crate::context::Evaluation<'_, 'd>,
        runtime: R,
    ) -> Result<R::Text, crate::function::Error> {
        let render = |name: QName<'_>, owner: Option<dom::Element<'d>>, preferred: Option<&str>| {
            let text = match part {
                NamePart::Namespace => name.namespace_uri().unwrap_or(""),
                _ => name.local_part(),
            };
            let mut output = runtime.empty_text()?;
            if matches!(part, NamePart::Qualified)
                && let (Some(uri), Some(owner)) = (name.namespace_uri(), owner)
            {
                visit_namespace_bindings_in(owner, context, runtime, |prefix, candidate| {
                    let prefix = declaration_str(prefix);
                    let candidate = declaration_str(candidate);
                    if candidate == uri && (output.is_empty() || preferred == Some(prefix)) {
                        output = runtime.empty_text()?;
                        runtime.append_text(context, &mut output, prefix)?;
                        if preferred.is_none() || preferred == Some(prefix) {
                            return Ok(core::ops::ControlFlow::Break(()));
                        }
                    }
                    Ok::<_, crate::function::Error>(core::ops::ControlFlow::Continue(()))
                })?;
            }
            if !output.is_empty() {
                runtime.append_text(context, &mut output, ":")?;
            }
            runtime.append_text(context, &mut output, text)?;
            Ok(output)
        };
        match self {
            Self::Element(node) => render(
                sxd_document_no_unsafe::as_qname!(node.name()),
                Some(*node),
                sxd_document_no_unsafe::as_opt_str!(node.preferred_prefix()),
            ),
            Self::Attribute(node) => render(
                sxd_document_no_unsafe::as_qname!(node.name()),
                node.parent(),
                sxd_document_no_unsafe::as_opt_str!(node.preferred_prefix()),
            ),
            Self::ProcessingInstruction(node) => render(
                QName::new(sxd_document_no_unsafe::as_str!(node.target())),
                None,
                None,
            ),
            Self::Namespace(node) => render(QName::new(node.prefix()), None, None),
            Self::Root(_) | Self::Text(_) | Self::Comment(_) => runtime.empty_text(),
        }
    }

    /// Copy an identity after accounting for owned namespace payloads in the safe backend.
    ///
    /// # Errors
    /// Returns the resource error before copying unshareable namespace labels.
    pub fn clone_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<Self, crate::function::Error> {
        #[cfg(feature = "embedded")]
        if let Self::Namespace(namespace) = self
            && namespace.prefix.can_share()
            && namespace.uri.can_share()
        {
            return Ok(self.clone());
        }
        if cfg!(feature = "no-unsafe")
            && let Self::Namespace(namespace) = self
        {
            let bytes = namespace
                .prefix()
                .len()
                .saturating_add(namespace.uri().len());
            context.charge_work(bytes)?;
            context.reserve_temporary_allocation(bytes)?;
        }
        Ok(self.clone())
    }

    /// The document to which this node belongs.
    #[must_use]
    pub fn document(&self) -> dom::Document<'d> {
        match self {
            Self::Root(n) => n.document(),
            Self::Element(n) => n.document(),
            Self::Attribute(n) => n.document(),
            Self::Text(n) => n.document(),
            Self::Comment(n) => n.document(),
            Self::ProcessingInstruction(n) => n.document(),
            Self::Namespace(n) => n.document(),
        }
    }

    /// The name of the node, including a prefix that corresponds to the namespace, if any.
    ///
    /// # Panics
    /// Panics for an attribute detached from its owning element.
    #[must_use]
    pub fn prefixed_name(&self) -> Option<String> {
        fn qname_prefixed_name(
            element: dom::Element<'_>,
            name: QName<'_>,
            preferred_prefix: Option<&str>,
        ) -> String {
            if let Some(ns_uri) = name.namespace_uri() {
                if let Some(prefix) = element.prefix_for_namespace_uri(
                    ns_uri,
                    sxd_document_no_unsafe::as_opt_str!(preferred_prefix),
                ) {
                    format!(
                        "{}:{}",
                        sxd_document_no_unsafe::as_str!(prefix),
                        name.local_part()
                    )
                } else {
                    name.local_part().to_owned()
                }
            } else {
                name.local_part().to_owned()
            }
        }

        match self {
            Self::Root(_) | Self::Text(_) | Self::Comment(_) => None,
            Self::Element(n) => Some(qname_prefixed_name(
                *n,
                sxd_document_no_unsafe::as_qname!(n.name()),
                sxd_document_no_unsafe::as_opt_str!(n.preferred_prefix()),
            )),
            Self::Attribute(n) => {
                let parent = n.parent().expect("Cannot process attribute without parent");
                Some(qname_prefixed_name(
                    parent,
                    sxd_document_no_unsafe::as_qname!(n.name()),
                    sxd_document_no_unsafe::as_opt_str!(n.preferred_prefix()),
                ))
            }
            Self::ProcessingInstruction(n) => {
                Some(sxd_document_no_unsafe::as_str!(n.target()).to_owned())
            }
            Self::Namespace(n) => Some(n.prefix().to_owned()),
        }
    }

    /// Returns the [expanded name][] of the node, if any.
    ///
    /// [expanded name]: https://www.w3.org/TR/xpath/#dt-expanded-name
    #[must_use]
    pub fn expanded_name(&self) -> Option<ExpandedName<'d>> {
        match self {
            Self::Root(_) | Self::Text(_) | Self::Comment(_) => None,
            Self::Element(n) => Some(to_expanded_name!(sxd_document_no_unsafe::as_qname!(
                n.name()
            ))),
            Self::Attribute(n) => Some(to_expanded_name!(sxd_document_no_unsafe::as_qname!(
                n.name()
            ))),
            Self::ProcessingInstruction(n) => Some(to_expanded_name!(QName::new(
                sxd_document_no_unsafe::as_str!(n.target())
            ))),
            Self::Namespace(n) => Some(n.expanded_name()),
        }
    }

    /// Returns the parent of the node, if any.
    pub fn parent(&self) -> Option<Node<'d>> {
        match self {
            Self::Root(_) => None,
            Self::Element(n) => n.parent().map(Into::into),
            Self::Attribute(n) => n.parent().map(Into::into),
            Self::Text(n) => n.parent().map(Into::into),
            Self::Comment(n) => n.parent().map(Into::into),
            Self::ProcessingInstruction(n) => n.parent().map(Into::into),
            Self::Namespace(n) => Some(n.parent().into()),
        }
    }

    /// Returns the children of the node, if any.
    pub fn children(&self) -> Vec<Node<'d>> {
        match self {
            Self::Root(n) => n.children().into_iter().map(Into::into).collect(),
            Self::Element(n) => n.children().into_iter().map(Into::into).collect(),
            Self::Attribute(_)
            | Self::Text(_)
            | Self::Comment(_)
            | Self::ProcessingInstruction(_)
            | Self::Namespace(_) => Vec::new(),
        }
    }

    /// Returns the number of children without materializing child handles.
    #[must_use]
    pub fn children_len(&self) -> usize {
        match self {
            Self::Root(node) => node.children_len(),
            Self::Element(node) => node.children_len(),
            Self::Attribute(_)
            | Self::Text(_)
            | Self::Comment(_)
            | Self::ProcessingInstruction(_)
            | Self::Namespace(_) => 0,
        }
    }

    /// Returns one child without allocating a complete child-handle vector.
    pub fn child_at(&self, index: usize) -> Option<Node<'d>> {
        match self {
            Self::Root(node) => node.child_at(index).map(Into::into),
            Self::Element(node) => node.child_at(index).map(Into::into),
            Self::Attribute(_)
            | Self::Text(_)
            | Self::Comment(_)
            | Self::ProcessingInstruction(_)
            | Self::Namespace(_) => None,
        }
    }

    /// Returns the nodes with the same parent that occur before this node.
    pub fn preceding_siblings(&self) -> Vec<Node<'d>> {
        use self::Node::{
            Attribute, Comment, Element, Namespace, ProcessingInstruction, Root, Text,
        };
        match self {
            Root(_) | Attribute(_) | Namespace(_) => Vec::new(),
            Element(n) => n
                .preceding_siblings()
                .into_iter()
                .rev()
                .map(Into::into)
                .collect(),
            Text(n) => n
                .preceding_siblings()
                .into_iter()
                .rev()
                .map(Into::into)
                .collect(),
            Comment(n) => n
                .preceding_siblings()
                .into_iter()
                .rev()
                .map(Into::into)
                .collect(),
            ProcessingInstruction(n) => n
                .preceding_siblings()
                .into_iter()
                .rev()
                .map(Into::into)
                .collect(),
        }
    }

    /// Returns the nodes with the same parent that occur after this node.
    pub fn following_siblings(&self) -> Vec<Node<'d>> {
        use self::Node::{
            Attribute, Comment, Element, Namespace, ProcessingInstruction, Root, Text,
        };
        match self {
            Root(_) | Attribute(_) | Namespace(_) => Vec::new(),
            Element(n) => n.following_siblings().into_iter().map(Into::into).collect(),
            Text(n) => n.following_siblings().into_iter().map(Into::into).collect(),
            Comment(n) => n.following_siblings().into_iter().map(Into::into).collect(),
            ProcessingInstruction(n) => {
                n.following_siblings().into_iter().map(Into::into).collect()
            }
        }
    }

    /// Returns the [string value] of this node.
    ///
    /// [string value]: https://www.w3.org/TR/xpath/#dt-string-value
    #[must_use]
    pub fn string_value(&self) -> String {
        self.string_value_with_capacity(self.string_value_len())
    }

    /// Returns the string value after reserving its exact temporary allocation in the evaluator.
    ///
    /// # Errors
    /// Returns the traversal or allocation error before exceeding the current limits.
    pub fn string_value_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<String, crate::function::Error> {
        self.string_value_with_meter(context, StringValueWork::XPath)
    }

    /// Returns the string value while charging traversal to extension-internal work.
    ///
    /// # Errors
    /// Returns the extension traversal or allocation error before exceeding its limits.
    pub fn string_value_with_extension_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<String, crate::function::Error> {
        self.string_value_with_meter(context, StringValueWork::Extension)
    }

    fn string_value_with_meter(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        work: StringValueWork,
    ) -> Result<String, crate::function::Error> {
        if !matches!(self, Node::Root(_) | Node::Element(_)) {
            let length = self.string_value_len();
            if work == StringValueWork::Extension {
                context.charge_extension_work(length.max(1))?;
            } else {
                context.charge_work(length.max(1))?;
            }
            context.reserve_string_allocation(length)?;
            return Ok(self.string_value_with_capacity(length));
        }
        let mut result = String::new();
        visit_descendant_text_metered(self, context, work, |text| {
            if work == StringValueWork::XPath {
                context.charge_work(text.len())?;
            }
            let required = result.len().checked_add(text.len()).ok_or_else(|| {
                crate::function::Error::Other {
                    what: "XPath string value exceeds addressable memory".into(),
                }
            })?;
            if required > result.capacity() {
                let target_capacity = required.max(result.capacity().saturating_mul(2).max(8));
                let additional = target_capacity - result.len();
                context.reserve_string_allocation(target_capacity - result.capacity())?;
                result.try_reserve_exact(additional).map_err(|_| {
                    crate::function::Error::Other {
                        what: "XPath string value allocation failed".into(),
                    }
                })?;
            }
            result.push_str(text);
            Ok(true)
        })?;
        Ok(result)
    }

    pub(crate) fn string_value_with_capacity(&self, capacity: usize) -> String {
        let mut result = String::with_capacity(capacity);
        self.append_string_value(&mut result);
        result
    }

    /// Returns the UTF-8 byte length of this node's string value without building the value.
    #[must_use]
    pub fn string_value_len(&self) -> usize {
        use self::Node::{
            Attribute, Comment, Element, Namespace, ProcessingInstruction, Root, Text,
        };

        match self {
            Root(_) | Element(_) => {
                let mut length = 0usize;
                visit_descendant_text(self, |text| {
                    // Every visited byte already resides in this finite document, so the sum
                    // cannot exceed the addressable allocation that owns those text nodes.
                    debug_assert!(length.checked_add(text.len()).is_some());
                    length += text.len();
                    true
                });
                length
            }
            Attribute(attribute) => sxd_document_no_unsafe::as_str!(attribute.value()).len(),
            ProcessingInstruction(instruction) => {
                sxd_document_no_unsafe::as_opt_str!(instruction.value())
                    .unwrap_or("")
                    .len()
            }
            Comment(comment) => sxd_document_no_unsafe::as_str!(comment.text()).len(),
            Text(text) => sxd_document_no_unsafe::as_str!(text.text()).len(),
            Namespace(namespace) => namespace.uri().len(),
        }
    }

    /// Compare a node string value while charging traversal and compared bytes as `XPath` work.
    pub(crate) fn string_value_eq_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        expected: &str,
    ) -> Result<bool, crate::function::Error> {
        self.string_value_eq_with_stack(context, expected, &mut Vec::new())
    }

    pub(crate) fn string_value_eq_with_stack(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        expected: &str,
        stack: &mut impl TextStack<'d>,
    ) -> Result<bool, crate::function::Error> {
        fn consume(
            context: &crate::context::Evaluation<'_, '_>,
            actual: &str,
            remaining: &mut &str,
        ) -> Result<bool, crate::function::Error> {
            if actual.len() > remaining.len() {
                return Ok(false);
            }
            for (actual, expected) in actual.bytes().zip(remaining.bytes()) {
                context.charge_work(1)?;
                if actual != expected {
                    return Ok(false);
                }
            }
            *remaining = &remaining[actual.len()..];
            Ok(true)
        }

        let mut remaining = expected;
        let matches = match self {
            Node::Root(_) | Node::Element(_) => {
                let mut matches = true;
                visit_descendant_text_using_stack(
                    self,
                    context,
                    StringValueWork::XPath,
                    stack,
                    |text| {
                        if matches {
                            matches = consume(context, text, &mut remaining)?;
                        }
                        Ok(matches)
                    },
                )?;
                matches
            }
            Node::Attribute(attribute) => consume(
                context,
                sxd_document_no_unsafe::as_str!(attribute.value()),
                &mut remaining,
            )?,
            Node::ProcessingInstruction(instruction) => consume(
                context,
                sxd_document_no_unsafe::as_opt_str!(instruction.value()).unwrap_or(""),
                &mut remaining,
            )?,
            Node::Comment(comment) => consume(
                context,
                sxd_document_no_unsafe::as_str!(comment.text()),
                &mut remaining,
            )?,
            Node::Text(text) => consume(
                context,
                sxd_document_no_unsafe::as_str!(text.text()),
                &mut remaining,
            )?,
            Node::Namespace(namespace) => consume(context, namespace.uri(), &mut remaining)?,
        };
        Ok(matches && remaining.is_empty())
    }

    /// Visit borrowed chunks without materializing a descendant string or child snapshots.
    pub(crate) fn visit_string_value_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        visit: impl FnMut(&str) -> Result<bool, crate::function::Error>,
    ) -> Result<(), crate::function::Error> {
        self.visit_string_value_with_stack(context, &mut Vec::new(), visit)
    }

    pub(crate) fn visit_string_value_with_stack(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        stack: &mut impl TextStack<'d>,
        mut visit: impl FnMut(&str) -> Result<bool, crate::function::Error>,
    ) -> Result<(), crate::function::Error> {
        match self {
            Node::Root(_) | Node::Element(_) => {
                return visit_descendant_text_using_stack(
                    self,
                    context,
                    StringValueWork::XPath,
                    stack,
                    visit,
                );
            }
            Node::Attribute(node) => visit(sxd_document_no_unsafe::as_str!(node.value()))?,
            Node::Text(node) => visit(sxd_document_no_unsafe::as_str!(node.text()))?,
            Node::Comment(node) => visit(sxd_document_no_unsafe::as_str!(node.text()))?,
            Node::ProcessingInstruction(node) => {
                visit(sxd_document_no_unsafe::as_opt_str!(node.value()).unwrap_or(""))?
            }
            Node::Namespace(node) => visit(node.uri())?,
        };
        Ok(())
    }

    /// Returns the number of Unicode code points without an evaluation context.
    #[cfg(test)]
    pub(crate) fn string_value_char_len(&self) -> usize {
        use self::Node::*;

        match self {
            Root(_) | Element(_) => {
                let mut length = 0usize;
                visit_descendant_text(self, |text| {
                    let characters = text.chars().count();
                    debug_assert!(length.checked_add(characters).is_some());
                    length += characters;
                    true
                });
                length
            }
            Attribute(attribute) => sxd_document_no_unsafe::as_str!(attribute.value())
                .chars()
                .count(),
            ProcessingInstruction(instruction) => {
                sxd_document_no_unsafe::as_opt_str!(instruction.value())
                    .unwrap_or("")
                    .chars()
                    .count()
            }
            Comment(comment) => sxd_document_no_unsafe::as_str!(comment.text())
                .chars()
                .count(),
            Text(text) => sxd_document_no_unsafe::as_str!(text.text()).chars().count(),
            Namespace(namespace) => namespace.uri().chars().count(),
        }
    }

    /// Append this node's string value without allocating an intermediate string.
    pub(crate) fn append_string_value(&self, output: &mut String) {
        use self::Node::{
            Attribute, Comment, Element, Namespace, ProcessingInstruction, Root, Text,
        };

        match self {
            Root(_) | Element(_) => {
                visit_descendant_text(self, |text| {
                    output.push_str(text);
                    true
                });
            }
            Attribute(attribute) => {
                output.push_str(sxd_document_no_unsafe::as_str!(attribute.value()));
            }
            ProcessingInstruction(instruction) => output
                .push_str(sxd_document_no_unsafe::as_opt_str!(instruction.value()).unwrap_or("")),
            Comment(comment) => output.push_str(sxd_document_no_unsafe::as_str!(comment.text())),
            Text(text) => output.push_str(sxd_document_no_unsafe::as_str!(text.text())),
            Namespace(namespace) => output.push_str(namespace.uri()),
        }
    }

    unpack!(Node, {
        root, Root, dom::Root,
        element, Element, dom::Element,
        attribute, Attribute, dom::Attribute,
        text, Text, dom::Text,
        comment, Comment, dom::Comment,
        processing_instruction, ProcessingInstruction, dom::ProcessingInstruction
    });

    #[must_use]
    pub fn namespace(&self) -> Option<Namespace<'d>> {
        match self {
            Node::Namespace(n) => Some(n.clone()),
            _ => None,
        }
    }
}

/// Visit descendant text in document order without making source depth native-stack depth.
fn visit_descendant_text(node: &Node<'_>, mut visit: impl FnMut(&str) -> bool) -> bool {
    let mut pending = node.children();
    pending.reverse();
    while let Some(node) = pending.pop() {
        match &node {
            Node::Element(_) => {
                let mut children = node.children();
                children.reverse();
                pending.extend(children);
            }
            Node::Text(text) if !visit(sxd_document_no_unsafe::as_str!(text.text())) => {
                return false;
            }
            _ => {}
        }
    }
    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StringValueWork {
    XPath,
    Extension,
}

pub(crate) trait TextStack<'d> {
    fn push(
        &mut self,
        frame: (Node<'d>, usize),
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<(), crate::function::Error>;
    fn pop(&mut self) -> Option<(Node<'d>, usize)>;
}

impl<'d> TextStack<'d> for Vec<(Node<'d>, usize)> {
    fn push(
        &mut self,
        frame: (Node<'d>, usize),
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<(), crate::function::Error> {
        reserve_metered_vec_slot(self, context)?;
        Vec::push(self, frame);
        Ok(())
    }

    fn pop(&mut self) -> Option<(Node<'d>, usize)> {
        Vec::pop(self)
    }
}

struct TextFrames<'s, 'd, S: TextStack<'d>> {
    stack: &'s mut S,
    lifetime: core::marker::PhantomData<&'d ()>,
}

impl<'d, S: TextStack<'d>> Drop for TextFrames<'_, 'd, S> {
    fn drop(&mut self) {
        // A caller may reuse admitted capacity, but not a stopped traversal's
        // pending ancestors. Cleanup also runs when its visitor unwinds.
        while self.stack.pop().is_some() {}
    }
}

fn visit_descendant_text_metered(
    node: &Node<'_>,
    context: &crate::context::Evaluation<'_, '_>,
    work: StringValueWork,
    visit: impl FnMut(&str) -> Result<bool, crate::function::Error>,
) -> Result<(), crate::function::Error> {
    visit_descendant_text_using_stack(node, context, work, &mut Vec::new(), visit)
}

fn visit_descendant_text_using_stack<'d>(
    node: &Node<'d>,
    context: &crate::context::Evaluation<'_, '_>,
    work: StringValueWork,
    stack: &mut impl TextStack<'d>,
    mut visit: impl FnMut(&str) -> Result<bool, crate::function::Error>,
) -> Result<(), crate::function::Error> {
    let frames = TextFrames {
        stack,
        lifetime: core::marker::PhantomData,
    };
    if work == StringValueWork::Extension {
        context.charge_extension_work(1)?;
    }
    let mut parent = node.clone();
    let mut next_child = 0usize;
    loop {
        let Some(child) = parent.child_at(next_child) else {
            let Some((previous, index)) = frames.stack.pop() else {
                return Ok(());
            };
            parent = previous;
            next_child = index;
            continue;
        };
        next_child += 1;
        let units = if work == StringValueWork::Extension {
            match &child {
                Node::Text(text) => sxd_document_no_unsafe::as_str!(text.text())
                    .len()
                    .saturating_add(1),
                _ => 1,
            }
        } else {
            1
        };
        if work == StringValueWork::Extension {
            context.charge_extension_work(units)?;
        } else {
            context.charge_work(units)?;
        }
        match child {
            Node::Root(_) | Node::Element(_) => {
                frames.stack.push((parent, next_child), context)?;
                parent = child;
                next_child = 0;
            }
            Node::Text(text) if !visit(sxd_document_no_unsafe::as_str!(text.text()))? => {
                return Ok(());
            }
            _ => {}
        }
    }
}

conversion_trait!(Node, {
    dom::Root                  => Node::Root,
    dom::Element               => Node::Element,
    dom::Attribute             => Node::Attribute,
    dom::Text                  => Node::Text,
    dom::Comment               => Node::Comment,
    dom::ProcessingInstruction => Node::ProcessingInstruction
});

impl<'d> From<dom::ChildOfRoot<'d>> for Node<'d> {
    fn from(other: dom::ChildOfRoot<'d>) -> Node<'d> {
        match other {
            dom::ChildOfRoot::Element(n) => Self::Element(n),
            dom::ChildOfRoot::Comment(n) => Self::Comment(n),
            dom::ChildOfRoot::ProcessingInstruction(n) => Self::ProcessingInstruction(n),
        }
    }
}

impl<'d> From<dom::ChildOfElement<'d>> for Node<'d> {
    fn from(other: dom::ChildOfElement<'d>) -> Node<'d> {
        match other {
            dom::ChildOfElement::Element(n) => Self::Element(n),
            dom::ChildOfElement::Text(n) => Self::Text(n),
            dom::ChildOfElement::Comment(n) => Self::Comment(n),
            dom::ChildOfElement::ProcessingInstruction(n) => Self::ProcessingInstruction(n),
        }
    }
}

impl<'d> From<dom::ParentOfChild<'d>> for Node<'d> {
    fn from(other: dom::ParentOfChild<'d>) -> Self {
        match other {
            dom::ParentOfChild::Root(n) => Self::Root(n),
            dom::ParentOfChild::Element(n) => Self::Element(n),
        }
    }
}

/// An unordered collection of unique nodes
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Nodeset<'d> {
    nodes: Storage<'d>,
}

impl<'d> Nodeset<'d> {
    #[must_use]
    pub fn new() -> Nodeset<'d> {
        Self::default()
    }

    /// Checks if the node is present in the set
    pub fn contains<N>(&self, node: N) -> bool
    where
        N: Into<Node<'d>>,
    {
        self.nodes.native().contains(&node.into())
    }

    /// Check an existing identity without copying owned namespace data.
    #[must_use]
    pub fn contains_ref(&self, node: &Node<'d>) -> bool {
        self.nodes.native().contains(node)
    }

    /// Removes and returns whether a node was present.
    pub fn remove(&mut self, node: &Node<'d>) -> bool {
        self.nodes.native_mut().remove(node)
    }

    /// Add the given node to the set
    pub fn add<N>(&mut self, node: N)
    where
        N: Into<Node<'d>>,
    {
        self.nodes.native_mut().insert(node.into());
    }

    /// Add a unique node after reserving its container storage in the evaluation budget.
    ///
    /// # Errors
    /// Returns the resource error before inserting an inadmissible new identity.
    #[expect(
        clippy::mutable_key_type,
        reason = "node equality/hash use immutable arena/slot identity and retained namespace labels"
    )]
    pub fn add_metered(
        &mut self,
        context: &crate::context::Evaluation<'_, 'd>,
        node: Node<'d>,
    ) -> Result<(), crate::function::Error> {
        let nodes = self.nodes.native_mut();
        if !nodes.contains(&node) {
            context.charge_work(1)?;
            // The context counter is the embedding's shared temporary-allocation budget; strings
            // and node containers must consume the same allowance.
            reserve_hashset_slot(nodes, context)?;
            nodes.insert(node);
        }
        Ok(())
    }

    #[must_use]
    pub fn iter<'a>(&'a self) -> Iter<'a, 'd> {
        IntoIterator::into_iter(self)
    }

    /// Borrow identities without cloning namespace strings during iteration.
    pub fn iter_ref(&self) -> impl Iterator<Item = &Node<'d>> {
        self.nodes.native().iter()
    }

    /// Clone identities and their set storage under the current evaluation's limits.
    ///
    /// # Errors
    /// Returns the first container or namespace-label admission error.
    pub fn clone_with_context(
        &self,
        context: &crate::context::Evaluation<'_, 'd>,
    ) -> Result<Self, crate::function::Error> {
        let mut result = Self::new();
        for node in self.nodes.native() {
            result.add_metered(context, node.clone_with_context(context)?)?;
        }
        Ok(result)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node that occurs first in [document order]
    ///
    /// [document order]: https://www.w3.org/TR/xpath/#dt-document-order
    #[must_use]
    pub fn document_order_first(&self) -> Option<Node<'d>> {
        let node = self.nodes.native().iter().next()?;

        if self.nodes.len() == 1 {
            return Some(node.clone());
        }

        self.nodes
            .native()
            .iter()
            .min_by_key(|node| order_path(node))
            .cloned()
    }

    /// Return the first node while charging document-order key storage to the evaluator.
    ///
    /// # Errors
    /// Returns a key-storage, traversal, comparison, or identity-copy resource error.
    pub fn document_order_first_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<Option<Node<'d>>, crate::function::Error> {
        self.document_order_first_in(context, crate::runtime::Native)
    }

    pub(crate) fn document_order_first_in<R: crate::runtime::Runtime>(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        runtime: R,
    ) -> Result<Option<Node<'d>>, crate::function::Error> {
        let mut nodes = runtime.nodes(self)?;
        if self.size() <= 1 {
            return nodes
                .next()
                .map(|node| runtime.clone_node(context, node))
                .transpose();
        }
        let mut first: Option<(&Node<'d>, R::List<OrderStep<'_>>)> = None;
        for node in nodes {
            let path = order_path_in(node, Some(context), runtime)?;
            context.charge_work(order_path_work(&path))?;
            if first
                .as_ref()
                .is_none_or(|(_, current)| path[..] < current[..])
            {
                first = Some((node, path));
            }
        }
        first
            .map(|(node, _)| runtime.clone_node(context, node))
            .transpose()
    }

    #[must_use]
    pub fn document_order(&self) -> Vec<Node<'d>> {
        let mut keyed: Vec<_> = self
            .iter_ref()
            .map(|node| (node, order_path(node)))
            .collect();
        keyed.sort_unstable_by(|(_, left), (_, right)| left.cmp(right));
        keyed.into_iter().map(|(node, _)| node.clone()).collect()
    }

    /// Return nodes in document order while charging all temporary key storage.
    ///
    /// # Errors
    /// Returns a key-storage, comparison, result-storage, or identity-copy resource error.
    pub fn document_order_with_context(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
    ) -> Result<Vec<Node<'d>>, crate::function::Error> {
        self.document_order_in(context, crate::runtime::Native)
    }

    pub(crate) fn document_order_in<R: crate::runtime::Runtime>(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        runtime: R,
    ) -> Result<R::List<Node<'d>>, crate::function::Error> {
        use crate::runtime::List;
        let mut ordered = runtime.list();
        if self.size() <= 1 {
            runtime.reserve(context, &mut ordered, self.size())?;
            for node in runtime.nodes(self)? {
                ordered.push(runtime.clone_node(context, node)?)?;
            }
            return Ok(ordered);
        }
        let keyed = self.sorted_document_order_in(context, runtime)?;
        runtime.reserve(context, &mut ordered, self.size())?;
        for (node, _) in keyed.iter() {
            ordered.push(runtime.clone_node(context, node)?)?;
        }
        Ok(ordered)
    }

    pub(crate) fn visit_document_order_in<R: crate::runtime::Runtime>(
        &self,
        context: &crate::context::Evaluation<'_, '_>,
        runtime: R,
        mut visit: impl FnMut(&Node<'d>) -> Result<(), crate::function::Error>,
    ) -> Result<(), crate::function::Error> {
        if self.size() <= 1 {
            for node in runtime.nodes(self)? {
                visit(node)?;
            }
            return Ok(());
        }
        let sorted = self.sorted_document_order_in(context, runtime)?;
        for (node, _) in sorted.iter() {
            visit(node)?;
        }
        Ok(())
    }

    fn sorted_document_order_in<'a, R: crate::runtime::Runtime>(
        &'a self,
        context: &crate::context::Evaluation<'_, '_>,
        runtime: R,
    ) -> Result<OrderKeys<'a, 'd, R>, crate::function::Error> {
        use crate::runtime::List;
        let mut keyed = runtime.list();
        runtime.reserve(context, &mut keyed, self.size())?;
        for node in runtime.nodes(self)? {
            let path = order_path_in(node, Some(context), runtime)?;
            keyed.push((node, path))?;
        }
        let comparison_bytes = keyed
            .iter()
            .map(|(_, path)| order_path_work(path))
            .max()
            .unwrap_or(0);
        let leading_zeros = keyed.len().leading_zeros();
        let levels = (usize::BITS - leading_zeros) as usize;
        context.charge_work(
            keyed
                .len()
                .saturating_mul(levels)
                .saturating_mul(2)
                .saturating_mul(comparison_bytes),
        )?;
        // Unique node identities have a total order; unstable sort avoids an extra merge buffer.
        keyed.sort_unstable_by(|(_, left), (_, right)| left[..].cmp(&right[..]));
        Ok(keyed)
    }
}

type OrderKeys<'a, 'd, R> = <R as crate::runtime::Runtime>::List<(
    &'a Node<'d>,
    <R as crate::runtime::Runtime>::List<OrderStep<'a>>,
)>;

impl<'d> Extend<Node<'d>> for Nodeset<'d> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Node<'d>>,
    {
        self.nodes.native_mut().extend(iter);
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum OrderStep<'a> {
    Namespace(&'a str),
    Attribute(usize),
    Child(usize),
}

fn order_path_work(path: &[OrderStep<'_>]) -> usize {
    path.iter().fold(1usize, |work, step| {
        work.saturating_add(match step {
            OrderStep::Namespace(prefix) => prefix.len().max(1),
            _ => 1,
        })
    })
}

fn order_path<'a>(node: &'a Node<'_>) -> Vec<OrderStep<'a>> {
    order_path_with_context(node, None).expect("unmetered document ordering cannot fail")
}

fn order_path_with_context<'a>(
    node: &'a Node<'_>,
    context: Option<&crate::context::Evaluation<'_, '_>>,
) -> Result<Vec<OrderStep<'a>>, crate::function::Error> {
    order_path_in(node, context, crate::runtime::Native)
}

fn order_path_in<'a, R: crate::runtime::Runtime>(
    node: &'a Node<'_>,
    context: Option<&crate::context::Evaluation<'_, '_>>,
    runtime: R,
) -> Result<R::List<OrderStep<'a>>, crate::function::Error> {
    use crate::runtime::List;
    let mut path = runtime.list();
    // Borrow the starting identity: safe-backend namespace handles own strings.
    // Ancestor identities are fixed-size element/root handles, not namespace copies.
    let mut current = Cow::Borrowed(node);
    while let Some(parent) = current.parent() {
        if let Some(context) = context {
            context.charge_work(1)?;
        }
        let step = match (node, current.as_ref()) {
            (Node::Namespace(namespace), Node::Namespace(_)) => {
                OrderStep::Namespace(namespace.prefix())
            }
            (_, Node::Attribute(attribute)) => {
                if let Some(context) = context {
                    context.charge_work(
                        parent
                            .element()
                            .map_or(0, |element| element.attributes_len()),
                    )?;
                }
                let index = attribute.parent().map_or(0, |element| {
                    (0..element.attributes_len())
                        .position(|index| element.attribute_at(index).as_ref() == Some(attribute))
                        .unwrap_or(element.attributes_len())
                });
                OrderStep::Attribute(index)
            }
            _ => {
                if let Some(context) = context {
                    context.charge_work(parent.children_len())?;
                }
                OrderStep::Child(
                    (0..parent.children_len())
                        .position(|index| parent.child_at(index).as_ref() == Some(current.as_ref()))
                        .unwrap_or(usize::MAX),
                )
            }
        };
        if let Some(context) = context {
            runtime.push(context, &mut path, step)?;
        } else {
            path.reserve(1)?;
            path.push(step)?;
        }
        current = Cow::Owned(parent);
    }
    path.reverse();
    Ok(path)
}

#[cfg(any(feature = "std", not(feature = "embedded")))]
pub(crate) fn reserve_hashset_slot<T: Eq + ::core::hash::Hash>(
    values: &mut Set<T>,
    context: &crate::context::Evaluation<'_, '_>,
) -> Result<(), crate::function::Error> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    context.reserve_temporary_allocation(set_slot_bytes::<T>(values.len())?)?;
    values
        .try_reserve(1)
        .map_err(|_| crate::function::Error::Other {
            what: "XPath set allocation failed".into(),
        })
}

/// Charges one insertion into the ordered set used without std. A tree
/// allocates nodes as it grows instead of reserving.
#[cfg(all(feature = "embedded", not(feature = "std")))]
pub(crate) fn reserve_hashset_slot<T: Ord>(
    values: &mut Set<T>,
    context: &crate::context::Evaluation<'_, '_>,
) -> Result<(), crate::function::Error> {
    context.reserve_temporary_allocation(set_slot_bytes::<T>(values.len())?)?;
    Ok(())
}

/// Bytes charged for the next insertion into the ordered set used without
/// std: its share of an internal node at the minimum occupancy of five keys.
#[cfg(all(feature = "embedded", not(feature = "std")))]
pub(crate) fn set_slot_bytes<T>(_current_len: usize) -> Result<usize, crate::function::Error> {
    // std's B-tree: 11 keys and 12 edges per internal node, plus the parent link.
    size_of::<T>()
        .checked_mul(11)
        .and_then(|keys| keys.checked_add(14 * size_of::<usize>()))
        .map(|node| node.div_ceil(5))
        .ok_or_else(|| crate::function::Error::Other {
            what: "XPath set capacity overflow".into(),
        })
}

/// Bytes charged for the next insertion into the hash set used with std.
#[cfg(any(feature = "std", not(feature = "embedded")))]
pub(crate) fn set_slot_bytes<T>(current_len: usize) -> Result<usize, crate::function::Error> {
    // std's SwissTable uses power-of-two buckets at at most 7/8 occupancy, plus
    // a control byte per bucket and a SIMD control group. Charge the whole new
    // allocation: the old table remains live during rehash, not just its delta.
    current_len
        .checked_add(1)
        .and_then(|entries| entries.checked_mul(8))
        .and_then(|scaled| scaled.checked_add(6))
        .and_then(|scaled| (scaled / 7).checked_next_power_of_two())
        .map(|buckets| buckets.max(4))
        .and_then(|buckets| buckets.checked_mul(size_of::<T>().saturating_add(1)))
        .and_then(|bytes| bytes.checked_add(16))
        .ok_or_else(|| crate::function::Error::Other {
            what: "XPath set capacity overflow".into(),
        })
}

fn reserve_metered_vec_slot<T>(
    values: &mut Vec<T>,
    context: &crate::context::Evaluation<'_, '_>,
) -> Result<(), crate::function::Error> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    let additional = values.capacity().max(4);
    context.reserve_temporary_allocation(additional.saturating_mul(size_of::<T>()))?;
    values
        .try_reserve_exact(additional)
        .map_err(|_| crate::function::Error::Other {
            what: "XPath traversal workspace allocation failed".into(),
        })
}

impl<'a, 'd: 'a> IntoIterator for &'a Nodeset<'d> {
    type Item = Node<'d>;
    type IntoIter = Iter<'a, 'd>;

    fn into_iter(self) -> Iter<'a, 'd> {
        Iter {
            iter: self.nodes.native().iter(),
        }
    }
}

impl<'d> IntoIterator for Nodeset<'d> {
    type Item = Node<'d>;
    type IntoIter = IntoIter<'d>;

    fn into_iter(self) -> IntoIter<'d> {
        IntoIter {
            iter: self.nodes.into_native().into_iter(),
        }
    }
}

impl<'d> From<OrderedNodes<'d>> for Nodeset<'d> {
    fn from(other: OrderedNodes<'d>) -> Self {
        other.0.into_iter().collect()
    }
}

impl<'d> FromIterator<Node<'d>> for Nodeset<'d> {
    fn from_iter<I>(iterator: I) -> Nodeset<'d>
    where
        I: IntoIterator<Item = Node<'d>>,
    {
        Nodeset {
            nodes: Storage::Native(iterator.into_iter().collect()),
        }
    }
}

pub struct Iter<'a, 'd> {
    iter: set::Iter<'a, Node<'d>>,
}

impl<'a, 'd: 'a> Iterator for Iter<'a, 'd> {
    type Item = Node<'d>;
    fn next(&mut self) -> Option<Node<'d>> {
        self.iter.next().cloned()
    }
}

pub struct IntoIter<'d> {
    iter: set::IntoIter<Node<'d>>,
}

impl<'d> Iterator for IntoIter<'d> {
    type Item = Node<'d>;
    fn next(&mut self) -> Option<Node<'d>> {
        self.iter.next()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OrderedNodes<'d>(Vec<Node<'d>>);

impl<'d> OrderedNodes<'d> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn add(&mut self, node: Node<'d>) {
        self.0.push(node);
    }

    #[cfg(test)]
    pub(crate) fn add_metered(
        &mut self,
        context: &crate::context::Evaluation<'_, 'd>,
        node: Node<'d>,
    ) -> Result<(), crate::function::Error> {
        context.charge_work(1)?;
        reserve_metered_vec_slot(&mut self.0, context)?;
        self.0.push(node);
        Ok(())
    }
}

impl<'d> From<Vec<Node<'d>>> for OrderedNodes<'d> {
    fn from(other: Vec<Node<'d>>) -> Self {
        OrderedNodes(other)
    }
}

impl<'d> From<OrderedNodes<'d>> for Vec<Node<'d>> {
    fn from(other: OrderedNodes<'d>) -> Self {
        other.0
    }
}

impl<'d> FromIterator<Node<'d>> for OrderedNodes<'d> {
    fn from_iter<I>(iterator: I) -> OrderedNodes<'d>
    where
        I: IntoIterator<Item = Node<'d>>,
    {
        OrderedNodes(iterator.into_iter().collect())
    }
}

#[cfg(test)]
mod test {
    use std::borrow::ToOwned;

    #[cfg(feature = "embedded")]
    use super::sxd_document_no_unsafe;
    use sxd_document_no_unsafe::Package;

    use super::Node::*;
    use super::{Node, Nodeset};

    fn into_node<'d, T: Into<Node<'d>>>(n: T) -> Node<'d> {
        n.into()
    }

    #[test]
    fn nodeset_can_include_all_node_types() {
        let package = Package::new();
        let doc = package.as_document();
        let mut nodes = Nodeset::new();

        let root = doc.root();
        let element = doc.create_element("element");
        let attribute = element.set_attribute_value("name", "value");
        let text = doc.create_text("text");
        let comment = doc.create_comment("comment");
        let instruction = doc.create_processing_instruction("pi", None);

        nodes.add(root);
        nodes.add(element);
        nodes.add(attribute);
        nodes.add(text);
        nodes.add(comment);
        nodes.add(instruction);

        assert_eq!(6, nodes.size());
        assert!(nodes.contains(Root(root)));
        assert!(nodes.contains(Element(element)));
        assert!(nodes.contains(Attribute(attribute)));
        assert!(nodes.contains(Text(text)));
        assert!(nodes.contains(Comment(comment)));
        assert!(nodes.contains(ProcessingInstruction(instruction)));
    }

    #[test]
    fn nodesets_can_be_combined() {
        let package = Package::new();
        let doc = package.as_document();

        let mut all_nodes = Nodeset::new();
        let mut nodes1 = Nodeset::new();
        let mut nodes2 = Nodeset::new();

        let e1 = doc.create_element("element1");
        let e2 = doc.create_element("element2");

        all_nodes.add(e1);
        all_nodes.add(e2);

        nodes1.add(e1);
        nodes2.add(e2);

        nodes1.extend(nodes2);

        assert_eq!(all_nodes, nodes1);
    }

    #[test]
    fn ordering_obeys_work_budget_before_sibling_scans() {
        // Ordering must not scan a wide parent before checking the evaluation allowance.
        let package = Package::new();
        let doc = package.as_document();
        let first = doc.create_element("first");
        let last = doc.create_element("last");
        doc.root().append_child(first);
        doc.root().append_child(last);
        let nodes = nodeset![last, first];
        let mut context = crate::Context::new();
        context.set_evaluation_work_limit(0);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());
        assert!(nodes.document_order_with_context(&evaluation).is_err());
        assert!(
            nodes
                .document_order_first_with_context(&evaluation)
                .is_err()
        );
    }

    #[test]
    #[cfg(feature = "no-unsafe")]
    fn first_namespace_identity_reserves_its_returned_copy() {
        // Even a singleton namespace set owns strings in the safe DOM backend.
        let package = Package::new();
        let doc = package.as_document();
        let owner = doc.create_element("root");
        doc.root().append_child(owner);
        let nodes = nodeset![Node::Namespace(super::Namespace {
            parent: owner,
            prefix: "p".into(),
            uri: "urn:test".into(),
        })];
        let mut context = crate::Context::new();
        context.set_string_allocation_limit(0);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());
        assert!(
            nodes
                .document_order_first_with_context(&evaluation)
                .is_err()
        );
    }

    #[test]
    fn nodeset_knows_first_node_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let c1 = doc.create_comment("1");
        let c2 = doc.create_comment("2");
        doc.root().append_child(c1);
        doc.root().append_child(c2);

        let nodes = nodeset![c2, c1];

        assert_eq!(Some(into_node(c1)), nodes.document_order_first());
    }

    #[test]
    fn attributes_come_before_children_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let parent = doc.create_element("parent");
        let attr = parent.set_attribute_value("a", "v");
        let child = doc.create_element("child");

        doc.root().append_child(parent);
        parent.append_child(child);

        let nodes = nodeset![child, attr];

        assert_eq!(Some(attr.into()), nodes.document_order_first());
    }

    #[test]
    fn prefixed_name_of_element_with_preferred_prefix() {
        let package = Package::new();
        let doc = package.as_document();

        let e = doc.create_element(("uri", "wow"));
        e.set_preferred_prefix(Some("prefix"));
        e.register_prefix("prefix", "uri");
        let node: Node<'_> = e.into();

        assert_eq!(Some("prefix:wow".to_owned()), node.prefixed_name());
    }

    #[test]
    fn prefixed_name_of_element_with_prefix() {
        let package = Package::new();
        let doc = package.as_document();

        let e = doc.create_element(("uri", "wow"));
        e.register_prefix("prefix", "uri");
        let node: Node<'_> = e.into();

        assert_eq!(Some("prefix:wow".to_owned()), node.prefixed_name());
    }

    #[test]
    fn prefixed_name_of_element_without_prefix() {
        // See library-level doc about missing prefixes
        let package = Package::new();
        let doc = package.as_document();

        let e = doc.create_element(("uri", "wow"));
        let node: Node<'_> = e.into();

        assert_eq!(Some("wow".to_owned()), node.prefixed_name());
    }

    #[test]
    fn prefixed_name_of_attribute_with_preferred_prefix() {
        let package = Package::new();
        let doc = package.as_document();

        let e = doc.create_element("element");
        let a = e.set_attribute_value(("uri", "attr"), "value");
        a.set_preferred_prefix(Some("prefix"));
        e.register_prefix("prefix", "uri");
        let node: Node<'_> = a.into();

        assert_eq!(Some("prefix:attr".to_owned()), node.prefixed_name());
    }

    #[test]
    fn prefixed_name_of_attribute_with_prefix() {
        let package = Package::new();
        let doc = package.as_document();

        let e = doc.create_element("element");
        let a = e.set_attribute_value(("uri", "attr"), "value");
        e.register_prefix("prefix", "uri");
        let node: Node<'_> = a.into();

        assert_eq!(Some("prefix:attr".to_owned()), node.prefixed_name());
    }

    #[test]
    fn prefixed_name_of_processing_instruction() {
        let package = Package::new();
        let doc = package.as_document();

        let pi = doc.create_processing_instruction("target", Some("value"));
        let node: Node<'_> = pi.into();

        assert_eq!(Some("target".to_owned()), node.prefixed_name());
    }

    #[test]
    fn string_value_of_element_node_is_concatenation_of_descendant_text_nodes() {
        let package = Package::new();
        let doc = package.as_document();

        let element = doc.create_element("hello");
        let child = doc.create_element("world");
        let text1 = doc.create_text("Presenting: ");
        let text2 = doc.create_text("Earth");
        let text3 = doc.create_text("!");

        element.append_child(text1);
        element.append_child(child);
        child.append_child(text2);
        element.append_child(text3);

        assert_eq!("Presenting: Earth!", into_node(element).string_value());
    }

    #[test]
    fn deep_string_value_operations_do_not_use_the_native_stack() {
        // Source depth is attacker-controlled. Every string-value operation must use the same
        // iterative traversal and preserve document-order text concatenation.
        let package = Package::new();
        let doc = package.as_document();
        let root = doc.create_element("root");
        doc.root().append_child(root.clone());
        let mut parent = root.clone();
        for _ in 0..16_384 {
            let child = doc.create_element("node");
            parent.append_child(child.clone());
            parent = child;
        }
        parent.append_child(doc.create_text("deep"));
        let node = into_node(root);
        let mut context = crate::context::Context::new();
        context.set_evaluation_work_limit(32_768);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());

        assert_eq!(node.string_value_len(), 4);
        assert_eq!(node.string_value_char_len(), 4);
        assert_eq!(
            node.string_value_eq_with_context(&evaluation, "deep"),
            Ok(true)
        );
        assert_eq!(node.string_value(), "deep");
    }

    #[test]
    fn string_value_mismatch_stops_before_unrelated_descendants() {
        let package = Package::new();
        let doc = package.as_document();
        let root = doc.create_element("root");
        doc.root().append_child(root.clone());
        root.append_child(doc.create_text(&"x".repeat(1_024)));
        for _ in 0..1_024 {
            root.append_child(doc.create_element("unrelated"));
        }
        let mut context = crate::context::Context::new();
        context.set_evaluation_work_limit(2);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());

        assert_eq!(
            into_node(root).string_value_eq_with_context(&evaluation, "y"),
            Ok(false)
        );
    }

    #[test]
    fn reusable_text_stack_is_empty_after_early_stop_or_error() {
        // A borrowed traversal stack outlives one visit. Returning from inside
        // nested text must discard pending frames without discarding capacity.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        let child = document.create_element("child");
        child.append_child(document.create_text("nested"));
        root.append_child(child);
        root.append_child(document.create_text("tail"));
        document.root().append_child(root);
        let context = crate::context::Context::new();
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        let node = into_node(root);
        for fail in [false, true] {
            let mut stack = Vec::new();
            let result = node.visit_string_value_with_stack(&evaluation, &mut stack, |_| {
                if fail {
                    Err(crate::function::Error::ProcessingStopped)
                } else {
                    Ok(false)
                }
            });
            assert_eq!(result.is_err(), fail);
            assert!(
                stack.is_empty(),
                "pending frames must not escape a stopped visit"
            );
            let capacity = stack.capacity();
            let mut text = String::new();
            node.visit_string_value_with_stack(&evaluation, &mut stack, |chunk| {
                text.push_str(chunk);
                Ok(true)
            })
            .expect("second traversal must restart at its own root");
            assert_eq!(text, "nestedtail");
            assert_eq!(stack, []);
            assert_eq!(stack.capacity(), capacity);
        }
    }

    #[test]
    fn wide_empty_string_value_traversal_uses_depth_bounded_workspace() {
        // Width must not control traversal allocation: child_at() keeps only the ancestor path.
        let package = Package::new();
        let doc = package.as_document();
        let root = doc.create_element("root");
        doc.root().append_child(root.clone());
        for _ in 0..1_024 {
            root.append_child(doc.create_element("empty"));
        }
        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(4 * size_of::<(Node<'_>, usize)>());
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());

        assert_eq!(
            into_node(root).string_value_with_context(&evaluation),
            Ok(String::new())
        );
        assert_eq!(context.string_allocation_exceeded(), None);
    }

    #[test]
    fn string_value_growth_accounts_capacity_and_reserves_from_length() {
        let package = Package::new();
        let doc = package.as_document();
        let root = doc.create_element("root");
        doc.root().append_child(root.clone());
        root.append_child(doc.create_text("x"));
        root.append_child(doc.create_text(&"y".repeat(1_024)));
        let mut context = crate::context::Context::new();
        // Charge capacity growth (8 + 1,017), but pass 1,024 to reserve_exact relative
        // to len=1. Confusing these quantities either overcharges or misses a growth.
        context.set_string_allocation_limit(1_024);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());

        assert!(
            into_node(root)
                .string_value_with_context(&evaluation)
                .is_err()
        );
        assert!(context.string_allocation_exceeded().is_some());

        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(1_025);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());
        let result = into_node(doc.root().children()[0].element().unwrap())
            .string_value_with_context(&evaluation)
            .unwrap();
        assert_eq!(result, format!("x{}", "y".repeat(1_024)));
        assert_eq!(result.capacity(), 1_025);
        assert_eq!(context.string_allocation_exceeded(), None);
    }

    #[test]
    fn metered_containers_charge_capacity_not_only_live_entries() {
        // First insertion allocates spare slots and hash control storage, not just one Node.
        let package = Package::new();
        let document = package.as_document();
        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(size_of::<Node<'_>>());
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        assert!(
            Nodeset::new()
                .add_metered(&evaluation, document.root().into())
                .is_err()
        );

        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(size_of::<Node<'_>>());
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        assert!(
            super::OrderedNodes::new()
                .add_metered(&evaluation, document.root().into())
                .is_err()
        );
    }

    #[test]
    fn document_order_charges_cached_paths_before_sorting() {
        let package = Package::new();
        let doc = package.as_document();
        let parent = doc.create_element("parent");
        let child = doc.create_element("child");
        doc.root().append_child(parent);
        parent.append_child(child);
        let nodes = nodeset![parent, child];
        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(0);
        let evaluation = crate::context::Evaluation::new(&context, doc.root().into());

        assert!(nodes.document_order_with_context(&evaluation).is_err());
        assert!(context.string_allocation_exceeded().is_some());
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn current_document_order_retains_only_funded_result_storage() {
        // Keys and ancestor paths must use the current owner, even when the
        // legacy allocation allowance is zero; dropping the result releases it.
        use std::{cell::Cell, sync::Arc};
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let package = Package::new();
        let document = package.as_document();
        let parent = document.create_element("parent");
        let first = document.create_element("first");
        let last = document.create_element("last");
        document.root().append_child(parent);
        parent.append_child(first);
        parent.append_child(last);
        let nodes = nodeset![last, parent, first];
        let mut context = crate::context::Context::new();
        context.set_string_allocation_limit(0);
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        for bytes in [0, 65536] {
            let work = Memory::new(Arc::new(MemoryAccount::new(bytes, 65536)));
            let failure = Cell::new(None);
            let ordered = nodes.document_order_in(
                &evaluation,
                crate::runtime::Accounted {
                    work: &work,
                    failure: &failure,
                },
            );
            if bytes == 0 {
                assert!(ordered.is_err());
                assert_eq!(failure.get(), Some(MemoryError::LimitExceeded));
            } else {
                let ordered = ordered.expect("funded document order");
                assert_eq!(&ordered[..], &[parent.into(), first.into(), last.into()]);
                assert!(work.used() >= ordered.len() * size_of::<Node<'_>>());
                drop(ordered);
            }
            assert_eq!(work.used(), 0);
        }
        assert_eq!(context.string_allocation_exceeded(), None);
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn current_singleton_order_needs_only_its_output_slot() {
        // A singleton has no ordering comparison. Its minimum live storage is
        // one returned node, not an ancestor path plus a sorting-key array.
        use std::{cell::Cell, sync::Arc};
        use structured_asn1::memory::{Memory, MemoryAccount};
        let package = Package::new();
        let document = package.as_document();
        let element = document.create_element("root");
        document.root().append_child(element);
        let nodes = nodeset![element];
        let context = crate::context::Context::new();
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        let bytes = size_of::<Node<'_>>();
        let work = Memory::new(Arc::new(MemoryAccount::new(bytes, 65536)));
        let failure = Cell::new(None);
        let ordered = nodes
            .document_order_in(
                &evaluation,
                crate::runtime::Accounted {
                    work: &work,
                    failure: &failure,
                },
            )
            .expect("a singleton must need no sorting scratch");
        assert_eq!(&ordered[..], &[element.into()]);
        assert_eq!(work.used(), bytes);
        assert_eq!(failure.get(), None);
        drop(ordered);
        assert_eq!(work.used(), 0);
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn current_document_order_preserves_local_work_refusal() {
        // Spare aggregate memory cannot bypass an exhausted query's local
        // execution ceiling or turn its refusal into an allocation error.
        use std::{cell::Cell, sync::Arc};
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError, Work as _},
        };
        let package = Package::new();
        let document = package.as_document();
        let element = document.create_element("root");
        document.root().append_child(element);
        let nodes = nodeset![document.root(), element];
        let context = crate::context::Context::new();
        let evaluation = crate::context::Evaluation::new(&context, document.root().into());
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 64,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).expect("query reader");
        let work = reader.execution();
        for shift in (0..=6).rev() {
            while work.charge_work(1 << shift).is_ok() {}
        }
        let failure = Cell::new(None);
        let result = nodes.document_order_in(
            &evaluation,
            crate::runtime::Accounted {
                work: &work,
                failure: &failure,
            },
        );
        assert!(result.is_err());
        assert_eq!(failure.get(), Some(MemoryError::WorkExceeded));
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn string_value_of_attribute_node_is_value() {
        let package = Package::new();
        let doc = package.as_document();
        let element = doc.create_element("hello");
        let attribute: Node<'_> = element.set_attribute_value("world", "Earth").into();
        assert_eq!("Earth", attribute.string_value());
    }

    #[test]
    fn string_value_of_pi_node_is_empty_when_no_value() {
        let package = Package::new();
        let doc = package.as_document();
        let pi: Node<'_> = doc.create_processing_instruction("hello", None).into();
        assert_eq!("", pi.string_value());
    }

    #[test]
    fn string_value_of_pi_node_is_the_value_when_value() {
        let package = Package::new();
        let doc = package.as_document();
        let pi: Node<'_> = doc
            .create_processing_instruction("hello", Some("world"))
            .into();
        assert_eq!("world", pi.string_value());
    }

    #[test]
    fn string_value_of_comment_node_is_the_text() {
        let package = Package::new();
        let doc = package.as_document();
        let comment: Node<'_> = doc.create_comment("hello world").into();
        assert_eq!("hello world", comment.string_value());
    }

    #[test]
    fn string_value_of_text_node_is_the_text() {
        let package = Package::new();
        let doc = package.as_document();
        let text: Node<'_> = doc.create_text("hello world").into();
        assert_eq!("hello world", text.string_value());
    }
}
