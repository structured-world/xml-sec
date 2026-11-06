//! Where a new unsigned signature property goes, and how it is inserted.
//!
//! EN 319 132-1 §4.3: `UnsignedSignatureProperties` precedes
//! `UnsignedDataObjectProperties` inside `UnsignedProperties`, which follows
//! `SignedProperties`; a new property is appended after the existing ones,
//! and missing containers are created around it. Nothing the signature
//! already holds changes.

use alloc::{format, string::String, vec::Vec};
use structured_asn1::memory::{MemoryError, Work};
use xml_sec::IdAttributeRegistration;
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument, XmlDocumentError};
use xml_sec::xmldsig::extension::{self, InspectionError, NodeView, ScalarError, TreeError};

pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// Why a signature's qualifying properties could not be located.
#[derive(Debug)]
pub(crate) enum PlacementError {
    /// No `Signature` element has the ID.
    UnknownSignature(String),
    /// The signature has no `QualifyingProperties` targeting it.
    NotXades(String),
    /// The document could not be read.
    Tree(TreeError),
    /// An attribute could not be read.
    Scalar(ScalarError),
    /// The current execution refused work.
    Resource(MemoryError),
}

impl From<TreeError> for PlacementError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error)
    }
}

impl From<ScalarError> for PlacementError {
    fn from(error: ScalarError) -> Self {
        Self::Scalar(error)
    }
}

impl From<MemoryError> for PlacementError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

/// Where a new unsigned signature property goes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Unsigned {
    /// The existing `UnsignedSignatureProperties`.
    Signature(NodeIdentity),
    /// `UnsignedProperties` holding only `UnsignedDataObjectProperties`,
    /// which the new signature properties must precede.
    Data(NodeIdentity),
    /// `UnsignedProperties` without children.
    Empty(NodeIdentity),
    /// `QualifyingProperties` without `UnsignedProperties`.
    Absent(NodeIdentity),
}

impl Unsigned {
    /// The existing `UnsignedSignatureProperties`, when there is one.
    pub(crate) fn signature_properties(self) -> Option<NodeIdentity> {
        match self {
            Self::Signature(node) => Some(node),
            Self::Data(_) | Self::Empty(_) | Self::Absent(_) => None,
        }
    }

    /// Insert `property`, one complete element, after the existing unsigned
    /// signature properties, creating the containers it needs.
    pub(crate) fn insert(
        self,
        document: &mut XmlDocument,
        property: &str,
    ) -> Result<(), XmlDocumentError> {
        let wrapped = || {
            format!(
                "<xades:UnsignedSignatureProperties xmlns:xades=\"{XADES}\">{property}</xades:UnsignedSignatureProperties>"
            )
        };
        match self {
            Self::Signature(properties) => document.append_child(properties, property),
            Self::Data(data) => document.insert_before(data, &wrapped()),
            Self::Empty(properties) => document.append_child(properties, &wrapped()),
            Self::Absent(qualifying) => document.append_child(
                qualifying,
                &format!(
                    "<xades:UnsignedProperties xmlns:xades=\"{XADES}\"><xades:UnsignedSignatureProperties>{property}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
                ),
            ),
        }
    }
}

/// One `XAdES` signature, located by ID.
pub(crate) struct Located {
    pub(crate) signature: NodeIdentity,
    pub(crate) unsigned: Unsigned,
}

/// The `Signature` with ID `id` and where its next unsigned property goes.
pub(crate) fn locate<W: Work>(
    view: DocumentView<'_>,
    id: &str,
    registrations: &[IdAttributeRegistration],
    work: &W,
) -> Result<Located, PlacementError> {
    let unknown = || PlacementError::UnknownSignature(id.into());
    let signature = view.node_for_id(id, registrations).ok_or_else(unknown)?;
    if !is_element(view, signature, DS, "Signature", work)? {
        return Err(unknown());
    }
    let target = format!("#{id}");
    let mut qualifying = None;
    for object in children(view, signature, work)? {
        if !is_element(view, object, DS, "Object", work)? {
            continue;
        }
        for candidate in children(view, object, work)? {
            if is_element(view, candidate, XADES, "QualifyingProperties", work)?
                && attribute(view, candidate, "Target", work)?
                    .is_some_and(|value| value.trim() == target)
            {
                qualifying = Some(candidate);
            }
        }
    }
    let qualifying = qualifying.ok_or_else(|| PlacementError::NotXades(id.into()))?;
    let unsigned = match child(view, qualifying, XADES, "UnsignedProperties", work)? {
        None => Unsigned::Absent(qualifying),
        Some(properties) => {
            match child(view, properties, XADES, "UnsignedSignatureProperties", work)? {
                Some(signature_properties) => Unsigned::Signature(signature_properties),
                None => match child(
                    view,
                    properties,
                    XADES,
                    "UnsignedDataObjectProperties",
                    work,
                )? {
                    Some(data) => Unsigned::Data(data),
                    None => Unsigned::Empty(properties),
                },
            }
        }
    };
    Ok(Located {
        signature,
        unsigned,
    })
}

pub(crate) fn children<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    work: &W,
) -> Result<Vec<NodeIdentity>, PlacementError> {
    let mut nodes = Vec::new();
    let mut next = extension::first_child(view, parent, work)?;
    while let Some(node) = next {
        work.charge_work(1)?;
        nodes.push(node);
        next = extension::next_sibling(view, parent, node, work)?;
    }
    Ok(nodes)
}

pub(crate) fn child<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    namespace: &str,
    local: &str,
    work: &W,
) -> Result<Option<NodeIdentity>, PlacementError> {
    for node in children(view, parent, work)? {
        if is_element(view, node, namespace, local, work)? {
            return Ok(Some(node));
        }
    }
    Ok(None)
}

pub(crate) fn is_element<W: Work>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    namespace: &str,
    local: &str,
    work: &W,
) -> Result<bool, PlacementError> {
    Ok(extension::inspect_node(
        view,
        node,
        work,
        |node| matches!(node, NodeView::Element { namespace: Some(actual), local_name } if actual == namespace && local_name == local),
    )?)
}

/// An unqualified attribute's value.
pub(crate) fn attribute<W: Work>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    local: &str,
    work: &W,
) -> Result<Option<String>, PlacementError> {
    let mut found = None;
    let visited = extension::visit_direct_attributes(view, node, work, |attribute| {
        if attribute.namespace.is_none() && attribute.local_name == local {
            found = Some(String::from(attribute.value));
            // Attribute names are unique on an element.
            return Err(());
        }
        Ok(())
    });
    match visited {
        Ok(()) | Err(InspectionError::Visitor(())) => Ok(found),
        Err(InspectionError::Processing(error)) => Err(error.into()),
    }
}
