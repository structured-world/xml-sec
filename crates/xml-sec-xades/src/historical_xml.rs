//! The timestamp inputs of the ETSI TS 101 903 V1.1.1 and V1.2.2
//! vocabularies over the verified document: `Include` and `HashDataInfo`
//! targets, their transforms, and the default canonicalization.

use crate::signature::any_uri;
use crate::{Document, Error, Snapshot};
use structured_asn1::memory::Work;
use structured_cms::stream::Receiver;
use structured_xades::container::XADES_111;
use structured_xades::legacy::timestamp::{HashDataInfo, HashDataTarget, HashDataXml, LegacyXml};
use structured_xades::reference::{ReplayOutcome, Resolution};
use structured_xades::xml::Name;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::{BareNameTarget, CatalogueError, ReplayError};

impl<W: Work> Document<'_, '_, '_, '_, W> {
    /// The element a same-document bare-name `uri` attribute of `node` names.
    fn bare_name_target<Q: Work>(
        &self,
        node: NodeIdentity,
        attribute: Name<'_>,
        work: &Q,
    ) -> Result<Resolution<NodeIdentity>, Error> {
        self.with_attribute(node, attribute, work, |value| {
            let Some(value) = value else {
                return Ok(Resolution::Missing);
            };
            Ok(
                match self.session.resolve_bare_name_in(any_uri(value), work)? {
                    BareNameTarget::Element(node) => Resolution::Resolved(node),
                    BareNameTarget::Unresolved => Resolution::Unresolved,
                    // Only a same-document element is an input these
                    // vocabularies define here (V1.2.2 §7.1.4).
                    BareNameTarget::NotBareName => Resolution::Unsupported,
                },
            )
        })?
    }
}

impl<W: Work> LegacyXml for Document<'_, '_, '_, '_, W> {
    fn resolve_legacy_element<Q: Work>(
        &self,
        snapshot: Snapshot,
        include: NodeIdentity,
        work: &Q,
    ) -> Result<Resolution<NodeIdentity>, Error> {
        self.check(snapshot)?;
        self.bare_name_target(
            include,
            Name {
                namespace: "",
                local: "URI",
            },
            work,
        )
    }

    fn canonicalize_legacy_default<Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        receiver: &mut impl Receiver,
        work: &Q,
    ) -> Result<(), Error> {
        self.check(snapshot)?;
        // TS 101 903 V1.2.2 §7.1.4: without CanonicalizationMethod the input
        // is canonicalized with the XMLDSig default, Canonical XML 1.0
        // without comments.
        self.session
            .canonicalize_element_as(
                node,
                &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
                work,
                &mut |bytes| receiver.write(bytes),
            )
            .map_err(|error| match error {
                ReplayError::Processing(error) => error.into(),
                ReplayError::Receiver(_) => Error::ReceiverRefused,
            })
    }
}

impl<W: Work> HashDataXml for Document<'_, '_, '_, '_, W> {
    fn resolve_hash_data<Q: Work>(
        &self,
        snapshot: Snapshot,
        _signature: NodeIdentity,
        data: HashDataInfo<NodeIdentity>,
        work: &Q,
    ) -> Result<Resolution<HashDataTarget<NodeIdentity>>, Error> {
        self.check(snapshot)?;
        // A `HashDataInfo` naming a SignedInfo data object would have to
        // prove the same raw source (TS 101 903 V1.1.1 §7.7.1); this adapter
        // replays element targets only, which the signature timestamp uses.
        Ok(
            match self.bare_name_target(data.node, data.uri_attribute, work)? {
                Resolution::Resolved(node) => Resolution::Resolved(HashDataTarget::Element(node)),
                Resolution::Missing => Resolution::Missing,
                Resolution::Unresolved => Resolution::Unresolved,
                Resolution::Unauthenticated => Resolution::Unauthenticated,
                Resolution::Unsupported => Resolution::Unsupported,
            },
        )
    }

    fn replay_hash_data<Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        data: HashDataInfo<NodeIdentity>,
        expected: HashDataTarget<NodeIdentity>,
        receiver: &mut impl Receiver,
        work: &Q,
    ) -> Result<ReplayOutcome<Error>, Error> {
        self.check(snapshot)?;
        let HashDataTarget::Element(target) = expected else {
            return Err(Error::MalformedUri);
        };
        if self.bare_name_target(data.node, data.uri_attribute, work)?
            != Resolution::Resolved(target)
        {
            return Err(Error::Changed);
        }
        let uri = self.with_attribute(data.node, data.uri_attribute, work, |value| {
            value.map(|value| alloc::string::String::from(any_uri(value)))
        })?;
        let uri = uri.ok_or(Error::MalformedUri)?;
        // TS 101 903 V1.1.1 Annex A: HashDataInfo's Transforms element is
        // declared in the V1.1.1 namespace, its Transform children in XMLDSig.
        let transforms = data.transforms.map(|node| (node, XADES_111));
        self.session
            .with_query(signature, work, |selected| {
                match selected.replay_transforms(data.node, &uri, transforms, &mut |bytes| {
                    receiver.write(bytes)
                }) {
                    Ok(xml_sec::xmldsig::ReplayOutcome::Complete) => Ok(ReplayOutcome::Complete),
                    Ok(xml_sec::xmldsig::ReplayOutcome::Unavailable(missing)) => {
                        Ok(ReplayOutcome::Unavailable(Error::Unavailable {
                            reference: missing.reference,
                        }))
                    }
                    Err(ReplayError::Processing(error)) => Err(error.into()),
                    Err(ReplayError::Receiver(_)) => Err(Error::ReceiverRefused),
                }
            })
            .map_err(|error| match error {
                CatalogueError::Processing(error) => error.into(),
                CatalogueError::Visitor(error) => error,
            })
    }
}
