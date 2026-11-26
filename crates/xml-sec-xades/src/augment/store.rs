//! A `SignaturePolicyStore` added to an existing signature (EN 319 132-1
//! §5.2.10): the document of the explicit policy the signature signed, or a
//! local URI of it, as an unsigned property.

use super::{AugmentError, Publication, publish};
use crate::create::Assessment;
use crate::draft::Draft;
use crate::level::Inputs;
use crate::placement::{self, PlacementError, XADES};
use crate::properties::{
    Bound, ExplicitPolicy, Fragment, PolicyStore, PropertyDraft, SignedPolicy, SpecifiedDigest,
};
use alloc::{boxed::Box, string::String, vec::Vec};
use structured_asn1::memory::Work;
use xml_sec::IdAttributeRegistration;
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument};
use xml_sec::policy::SigningPolicy;
use xml_sec::provider::CryptoProvider;
use xml_sec::xmldsig::extension::{self, NodeView};

/// `http://uri.etsi.org/01903/v1.4.1#`, the namespace of the store.
const XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

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
        let signed = signed_policy(view, located.qualifying, request.signature, work)?;
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
/// `qualifying` properties.
fn signed_policy<W: Work>(
    view: DocumentView<'_>,
    qualifying: NodeIdentity,
    id: &str,
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
        // XML Schema 1.0 §3.2.17: anyURI collapses whitespace.
        identifier: text(view, identifier, work)?.trim().into(),
        method: placement::attribute(view, method, "Algorithm", work)?
            .ok_or_else(missing)?
            .trim()
            .into(),
        digest: Vec::from(&extension::base64_owned(view, value, work)?[..]),
    })
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
