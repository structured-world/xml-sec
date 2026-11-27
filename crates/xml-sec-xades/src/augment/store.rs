//! A `SignaturePolicyStore` added to an existing signature (EN 319 132-1
//! §5.2.10): the document of the explicit policy the signature signed, or a
//! local URI of it, as an unsigned property.

use super::{AugmentError, Publication, publish};
use crate::create::Assessment;
use crate::draft::Draft;
use crate::level::Inputs;
use crate::placement::{self, PlacementError, XADES};
use crate::properties::{
    Bound, ExplicitPolicy, Fragment, PolicyStore, PolicyTransforms, PropertyDraft, PropertyError,
    SignedPlan, SignedPolicy, SpecifiedDigest,
};
use alloc::{boxed::Box, string::String, vec::Vec};
use structured_asn1::memory::Work;
use xml_sec::IdAttributeRegistration;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize};
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument};
use xml_sec::policy::SigningPolicy;
use xml_sec::provider::CryptoProvider;
use xml_sec::xmldsig::extension::{self, NodeView};
use xml_sec::{XmlDomDocument, XmlDomNode};

/// `http://uri.etsi.org/01903/v1.4.1#`, the namespace of the store.
const XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// The transform naming a digest a technical specification defines
/// (EN 319 132-1 §5.2.9.2).
const SPECIFICATION_TRANSFORM: &str =
    "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

/// The policy store to add to one signature.
pub struct PolicyStoreRequest<'a, 'inputs> {
    /// ID of the `Signature` whose explicit policy is stored.
    pub signature: &'a str,
    /// The explicit policy the signature signed, with its document; its
    /// version, digest method and the digest of the document under its plan
    /// must equal the signed ones.
    pub policy: &'a ExplicitPolicy<'a, Fragment>,
    /// The document's specification and how the store carries it.
    pub store: PolicyStore<'a>,
    /// The digest rule of the specification the policy names with
    /// `PolicyTransform::InSpecification`.
    pub specified: Option<SpecifiedDigest<'a>>,
    /// Provider of the policy digest.
    pub provider: &'a dyn CryptoProvider,
    /// Policy of the digest's transforms and of the written property.
    pub signing: &'a SigningPolicy,
    /// The verification that assesses the document before and after the
    /// store is added.
    pub assessment: &'a Assessment<'a, 'inputs>,
    /// The level the new generation must still meet, with its evidence.
    pub inputs: &'a Inputs<'a>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// Add a `SignaturePolicyStore` of `request.policy` to `request.signature`
/// and publish it as one new generation of `document`, after that generation
/// still meets `request.inputs.requirements`.
///
/// Only an explicit policy the signature signed can be stored, once
/// (EN 319 132-1 §5.2.10, §6.3(m)); the store goes after the existing unsigned
/// signature properties, so earlier archive timestamps keep covering what
/// they covered.
///
/// # Errors
/// Returns the original cause and leaves the document unchanged:
/// [`AugmentError::NoExplicitPolicy`] when the signature signed none,
/// [`AugmentError::PolicyStored`] when it already has a store, and
/// [`AugmentError::Store`] when the policy is not the signed one.
///
/// # Examples
///
/// ```no_run
/// use xml_sec_xades::properties::{ExplicitPolicy, Fragment, PolicyDocument, PolicyStore};
/// use xml_sec_xades::{PolicyStoreRequest, add_policy_store};
/// # fn store(
/// #     document: &mut xml_sec::XmlDocument,
/// #     policy: &ExplicitPolicy<'_, Fragment>,
/// #     specification: xml_sec_xades::properties::Identifier<'_>,
/// #     signing: &xml_sec::policy::SigningPolicy,
/// #     assessment: &xml_sec_xades::Assessment<'_, '_>,
/// #     inputs: &xml_sec_xades::Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// add_policy_store(
///     document,
///     &PolicyStoreRequest {
///         signature: "sig",
///         policy,
///         store: PolicyStore { specification, document: PolicyDocument::Embedded },
///         specified: None,
///         provider: xml_sec::provider::default_provider(),
///         signing,
///         assessment,
///         inputs,
///         id_attributes: &[],
///     },
///     work,
/// )
/// # }
/// ```
pub fn add_policy_store<W: Work>(
    document: &mut XmlDocument,
    request: &PolicyStoreRequest<'_, '_>,
    work: &W,
) -> Result<(), AugmentError> {
    let (located, signed) = document.with_view(|view| {
        let located = placement::locate(view, request.signature, request.id_attributes, work)?;
        let signed = signed_policy(
            view,
            located.qualifying,
            request.signature,
            request.signing,
            work,
        )?;
        if let Some(properties) = located.unsigned.signature_properties()
            && placement::child(view, properties, XADES_141, "SignaturePolicyStore", work)?
                .is_some()
        {
            return Err(AugmentError::PolicyStored(request.signature.into()));
        }
        Ok::<_, AugmentError>((located, signed))
    })?;
    let mut writer = PropertyDraft {
        draft: Draft::new(),
        plan: &[],
        provider: request.provider,
        policy: request.signing,
        bound: Bound::Signed(signed),
        specified: request.specified,
        content: None,
    };
    request
        .policy
        .write_store(&request.store, &mut writer, work)
        .map_err(|error| AugmentError::Store(Box::new(error)))?;
    let (property, _) = writer.draft.finish()?;
    publish(
        document,
        &Publication {
            assessment: request.assessment,
            inputs: request.inputs,
            signature: request.signature,
            id_attributes: request.id_attributes,
            unsigned: located.unsigned,
        },
        Some(&property),
        work,
    )
}

/// The explicit `SignaturePolicyId` signature `id` signed, below its
/// `qualifying` properties, with the digest plan that same element states.
fn signed_policy<W: Work>(
    view: DocumentView<'_>,
    qualifying: NodeIdentity,
    id: &str,
    signing: &SigningPolicy,
    work: &W,
) -> Result<SignedPolicy, AugmentError> {
    let missing = || AugmentError::NoExplicitPolicy(id.into());
    let mut node = qualifying;
    for local in [
        "SignedProperties",
        "SignedSignatureProperties",
        "SignaturePolicyIdentifier",
        "SignaturePolicyId",
    ] {
        node = placement::child(view, node, XADES, local, work)?.ok_or_else(missing)?;
    }
    let identifier = placement::child(view, node, XADES, "SigPolicyId", work)?
        .and_then(|parent| placement::child(view, parent, XADES, "Identifier", work).transpose())
        .transpose()?
        .ok_or_else(missing)?;
    let hash = placement::child(view, node, XADES, "SigPolicyHash", work)?.ok_or_else(missing)?;
    let method =
        placement::child(view, hash, placement::DS, "DigestMethod", work)?.ok_or_else(missing)?;
    let value =
        placement::child(view, hash, placement::DS, "DigestValue", work)?.ok_or_else(missing)?;
    Ok(SignedPolicy {
        identifier: crate::properties::collapse(&text(view, identifier, work)?),
        method: placement::attribute(view, method, "Algorithm", work)?
            .ok_or_else(missing)?
            .trim()
            .into(),
        digest: Vec::from(&extension::base64_owned(view, value, work)?[..]),
        plan: match placement::child(view, node, placement::DS, "Transforms", work)? {
            Some(transforms) => signed_plan(view, transforms, id, signing, work)?,
            None => SignedPlan::None,
        },
    })
}

/// The policy digest plan of the signed `ds:Transforms` `transforms`: the one
/// `SPDocDigestAsInSpecification` transform (EN 319 132-1 §5.2.9.2) with the
/// specifications the policy's `SPDocSpecification` qualifiers name, or the
/// transforms as self-contained markup, the subtree in inclusive Canonical
/// XML 1.0, which carries every namespace in scope so an `XPath` expression
/// keeps its prefixes. Each walk and the markup are charged to `work` first.
fn signed_plan<W: Work>(
    view: DocumentView<'_>,
    transforms: NodeIdentity,
    id: &str,
    signing: &SigningPolicy,
    work: &W,
) -> Result<SignedPlan, AugmentError> {
    fn is(node: XmlDomNode<'_, '_>, namespace: &str, local: &str) -> bool {
        node.is_element()
            && node.tag_name().namespace() == Some(namespace)
            && node.tag_name().name() == local
    }
    let unreadable = || AugmentError::NoExplicitPolicy(id.into());
    // The element located in this view, read in the same tree: its document
    // order is its position in a preorder walk from the root.
    let parsed: &XmlDomDocument<'_> = view.document();
    let order = view.document_order(transforms).map_err(|_| unreadable())?;
    work.charge_work(order as u64 + 1)?;
    let transforms = parsed
        .root()
        .descendants()
        .nth(order)
        .filter(|node| {
            view.identity_of(*node)
                .is_ok_and(|found| found == transforms)
        })
        .ok_or_else(unreadable)?;
    let mut steps = transforms.children().filter(XmlDomNode::is_element);
    if let (Some(step), None) = (steps.next(), steps.next())
        && is(step, placement::DS, "Transform")
        && step.attribute("Algorithm") == Some(SPECIFICATION_TRANSFORM)
    {
        return signed_specifications(transforms, work).map(SignedPlan::InSpecification);
    }
    let within = |node: XmlDomNode<'_, '_>| {
        node.id() == transforms.id()
            || node
                .ancestors()
                .any(|ancestor| ancestor.id() == transforms.id())
    };
    // The canonical walk visits every node; its output is the subtree's
    // markup with the namespaces in scope.
    work.charge_work(view.node_count() as u64)?;
    work.charge_work(transforms.range().len() as u64)?;
    let mut markup = Vec::new();
    canonicalize(
        parsed,
        Some(&within),
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
        &mut markup,
    )
    .map_err(|_| unreadable())?;
    work.charge_work(markup.len() as u64)?;
    let markup = String::from_utf8(markup).map_err(|_| unreadable())?;
    PolicyTransforms::parse(markup, signing)
        .map(SignedPlan::Transforms)
        .map_err(|error| {
            AugmentError::Store(Box::new(structured_xades::produce::Error::Writer(
                PropertyError::from(error),
            )))
        })
}

/// The identifiers of the `SPDocSpecification` qualifiers of the
/// `SignaturePolicyId` that holds `transforms`, as collapsed anyURIs: the
/// specifications whose digest rule the signed hash follows (EN 319 132-1
/// §5.2.9.2).
fn signed_specifications<W: Work>(
    transforms: XmlDomNode<'_, '_>,
    work: &W,
) -> Result<Vec<String>, AugmentError> {
    let mut specifications = Vec::new();
    let Some(policy) = transforms.parent() else {
        return Ok(specifications);
    };
    let named = |node: &XmlDomNode<'_, '_>, namespace: &str, local: &str| {
        node.is_element()
            && node.tag_name().namespace() == Some(namespace)
            && node.tag_name().name() == local
    };
    for qualifiers in policy
        .children()
        .filter(|node| named(node, XADES, "SigPolicyQualifiers"))
    {
        for qualifier in qualifiers.children() {
            for specification in qualifier
                .children()
                .filter(|node| named(node, XADES_141, "SPDocSpecification"))
            {
                for identifier in specification
                    .children()
                    .filter(|node| named(node, XADES, "Identifier"))
                {
                    // Character data only: a comment is not part of it.
                    let value: String = identifier
                        .children()
                        .filter(XmlDomNode::is_text)
                        .filter_map(XmlDomNode::text)
                        .collect();
                    work.charge_work(value.len() as u64 + 1)?;
                    specifications.push(crate::properties::collapse(&value));
                }
            }
        }
    }
    Ok(specifications)
}

/// The character data of `node`'s children, in order.
fn text<W: Work>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    work: &W,
) -> Result<String, PlacementError> {
    let mut text = String::new();
    for child in placement::children(view, node, work)? {
        extension::inspect_node(view, child, work, |node| {
            if let NodeView::Text(value) = node {
                text.push_str(value);
            }
        })?;
    }
    Ok(text)
}
