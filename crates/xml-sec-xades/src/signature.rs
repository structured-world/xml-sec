//! Verified XMLDSig evidence projected onto the structured-xades contracts.

use crate::{Document, Error, Snapshot};
use structured_asn1::memory::Work;
use structured_cms::stream::Receiver;
use structured_pkix::Certificate;
use structured_pkix::path::WorkingKey;
use structured_xades::binding::{Coverage, Reference, SignatureXml, Status, Target};
use structured_xades::certificate::{CertificateXml, KeyAssociation};
use structured_xades::hashes::{
    HashClass, HashCompleteness, HashOrigin, HashUse, HashUseState, HashXml,
};
use structured_xades::reference::{
    Boolean, Completeness, Descriptor, LexicalSource, ObjectLocation, Parent, ReferenceXml, Replay,
    ReplayOutcome, Resolution, VisitError,
};
use structured_xades::xml::Name;
use xml_sec::document::NodeIdentity;
use xml_sec::provider;
use xml_sec::xmldsig::extension::{self, BooleanAttribute};
use xml_sec::xmldsig::{
    AuthenticatedReference, BareNameTarget, CatalogueCompleteness, CatalogueError, DigestAlgorithm,
    DsigStatus, HashUseAlgorithm, HashUseCompleteness, HashUseRole, ReferenceCoverage,
    ReferenceLocation, ReferenceParent, ReferenceResolution, ReplayError, ReplayMode, VerifyResult,
};

/// RFC 9231 §2.1.1 digest identifier; EN 319 132-1 §6.2.1 forbids MD5.
pub(crate) const MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";

pub(crate) fn hash_class(algorithm: DigestAlgorithm) -> HashClass {
    if algorithm.uri() == MD5 {
        HashClass::Md5
    } else {
        HashClass::OtherKnown
    }
}

fn status(status: DsigStatus) -> Status {
    if status == DsigStatus::Valid {
        Status::Valid
    } else {
        Status::Invalid
    }
}

// Enveloped element coverage excludes the owning Signature subtree, which
// is not complete original-element coverage of its target. Only unqualified
// element content is promoted; the conservative class is never widened.
fn coverage(coverage: ReferenceCoverage) -> Coverage {
    if coverage == ReferenceCoverage::ElementContent {
        Coverage::ElementContent
    } else {
        Coverage::Transformed
    }
}

fn parent(parent: ReferenceParent) -> Parent<NodeIdentity> {
    match parent {
        ReferenceParent::SignedInfo(node) => Parent::SignedInfo(node),
        ReferenceParent::Manifest(node) => Parent::Manifest(node),
    }
}

fn descriptor<'a>(reference: &AuthenticatedReference<'a>) -> Descriptor<'a, NodeIdentity> {
    Descriptor {
        reference: Reference {
            node: reference.identity,
            target: reference.result.and_then(|result| result.target_identity),
            kind: reference.reference_type,
            status: reference
                .result
                .map_or(Status::Unchecked, |result| status(result.status)),
            coverage: reference
                .result
                .map_or(Coverage::Transformed, |result| coverage(result.coverage)),
        },
        parent: parent(reference.parent),
        object_location: match reference.location {
            ReferenceLocation::SameDocument(_) => ObjectLocation::SameDocument,
            ReferenceLocation::Detached(_) => ObjectLocation::Detached,
            ReferenceLocation::Unchecked => ObjectLocation::Unknown,
        },
    }
}

fn flatten<T, E>(
    result: Result<T, CatalogueError<CatalogueError<E>>>,
) -> Result<T, VisitError<Error, E>> {
    result.map_err(|error| match error {
        CatalogueError::Processing(error)
        | CatalogueError::Visitor(CatalogueError::Processing(error)) => {
            VisitError::Processing(error.into())
        }
        CatalogueError::Visitor(CatalogueError::Visitor(error)) => VisitError::Visitor(error),
    })
}

impl<W: Work> Document<'_, '_, '_, '_, W> {
    /// The verified outcome of one Signature of this request; `None` when its
    /// pipeline failed before an outcome was produced.
    fn outcome(
        &self,
        signature: NodeIdentity,
        execution: &impl Work,
    ) -> Result<Option<&VerifyResult>, Error> {
        for entry in self.session.evidence().signatures() {
            execution.charge_work(1)?;
            if entry.identity() == signature {
                return Ok(entry.result().as_ref().ok());
            }
        }
        Err(Error::UnknownSignature)
    }
}

impl<W: Work> SignatureXml for Document<'_, '_, '_, '_, W> {
    fn signature_status<Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        execution: &Q,
    ) -> Result<Status, Error> {
        self.check(snapshot)?;
        Ok(self
            .outcome(signature, execution)?
            .map_or(Status::Unchecked, |result| status(result.status)))
    }

    fn reference_count<Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        execution: &Q,
    ) -> Result<usize, Error> {
        self.check(snapshot)?;
        Ok(self
            .outcome(signature, execution)?
            .map_or(0, |result| result.signed_info_references.len()))
    }

    fn reference<R, Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        ordinal: usize,
        execution: &Q,
        visitor: impl for<'view> FnOnce(Reference<'view, NodeIdentity>) -> R,
    ) -> Result<R, Error> {
        self.check(snapshot)?;
        let reference = self
            .outcome(signature, execution)?
            .and_then(|result| result.signed_info_references.get(ordinal))
            .ok_or(Error::ReferenceOrdinal)?;
        let node = reference
            .reference_identity
            .ok_or(Error::ReferenceIdentity)?;
        let (target, status, coverage) = (
            reference.target_identity,
            status(reference.status),
            coverage(reference.coverage),
        );
        self.with_attribute(
            node,
            Name {
                namespace: "",
                local: "Type",
            },
            execution,
            |kind| {
                visitor(Reference {
                    node,
                    target,
                    kind,
                    status,
                    coverage,
                })
            },
        )
    }

    fn qualifying_target<Q: Work>(
        &self,
        snapshot: Snapshot,
        qualifying: NodeIdentity,
        execution: &Q,
    ) -> Result<Target<NodeIdentity>, Error> {
        self.check(snapshot)?;
        self.with_attribute(
            qualifying,
            Name {
                namespace: "",
                local: "Target",
            },
            execution,
            |value| {
                let Some(value) = value else {
                    return Ok(Target::Missing);
                };
                Ok(match self.session.resolve_bare_name_in(value, execution)? {
                    BareNameTarget::Element(node) => Target::LocalBareName(node),
                    BareNameTarget::NotBareName | BareNameTarget::Unresolved => Target::Other,
                })
            },
        )?
    }
}

impl<W: Work> ReferenceXml for Document<'_, '_, '_, '_, W> {
    fn visit_authenticated_references<VE, Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        execution: &Q,
        mut visitor: impl for<'view> FnMut(Descriptor<'view, NodeIdentity>) -> Result<(), VE>,
    ) -> Result<Completeness<NodeIdentity>, VisitError<Error, VE>> {
        self.check(snapshot).map_err(VisitError::Processing)?;
        let completeness = flatten(self.session.with_query(signature, execution, |selected| {
            selected.visit_authenticated_references(|reference| visitor(descriptor(&reference)))
        }))?;
        Ok(match completeness {
            CatalogueCompleteness::Complete => Completeness::Complete,
            CatalogueCompleteness::Unchecked(node) => Completeness::Unchecked(node),
            CatalogueCompleteness::Incomplete(node) => Completeness::Incomplete(node),
        })
    }

    fn resolve_reference<R, Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        property: NodeIdentity,
        source: LexicalSource<'_>,
        execution: &Q,
        visitor: impl for<'view> FnOnce(Descriptor<'view, NodeIdentity>) -> R,
    ) -> Result<Resolution<R>, Error> {
        self.check(snapshot)?;
        self.session
            .with_query(signature, execution, |selected| {
                Ok(
                    match selected.resolve_reference(property, crate::source(source))? {
                        ReferenceResolution::Absent => Resolution::Missing,
                        ReferenceResolution::Malformed => return Err(Error::MalformedUri),
                        ReferenceResolution::Unsupported => Resolution::Unsupported,
                        // A caller-owned external resource is not an original
                        // XML Reference, and no other node answers this URI.
                        ReferenceResolution::Detached
                        | ReferenceResolution::Unresolved
                        | ReferenceResolution::NotReference(_) => Resolution::Unresolved,
                        ReferenceResolution::Unauthenticated(_) => Resolution::Unauthenticated,
                        ReferenceResolution::Reference(reference) => {
                            Resolution::Resolved(visitor(descriptor(&reference)))
                        }
                    },
                )
            })
            .map_err(|error| match error {
                CatalogueError::Processing(error) => error.into(),
                CatalogueError::Visitor(error) => error,
            })
    }

    fn boolean_attribute<Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        attribute: Name<'_>,
        execution: &Q,
    ) -> Result<Boolean, Error> {
        self.check(snapshot)?;
        Ok(
            match extension::boolean_attribute(
                self.session.view(),
                node,
                (!attribute.namespace.is_empty()).then_some(attribute.namespace),
                attribute.local,
                execution,
            )? {
                BooleanAttribute::Absent => Boolean::Absent,
                BooleanAttribute::Value(value) => Boolean::Value(value),
                BooleanAttribute::Malformed => Boolean::Malformed,
            },
        )
    }

    fn replay_reference<Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        reference: NodeIdentity,
        mode: Replay<NodeIdentity>,
        receiver: &mut impl Receiver,
        execution: &Q,
    ) -> Result<ReplayOutcome<Error>, Error> {
        self.check(snapshot)?;
        let mode = match mode {
            Replay::ReferenceOutput => ReplayMode::ReferenceOutput,
            Replay::Timestamp(method) => ReplayMode::Timestamp(method),
        };
        self.session
            .with_query(signature, execution, |selected| {
                match selected.replay_reference(reference, mode, &mut |bytes| receiver.write(bytes))
                {
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

impl<W: Work> CertificateXml for Document<'_, '_, '_, '_, W> {
    fn key_association<Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        _certificate: &Certificate<'_>,
        key: WorkingKey<'_>,
        execution: &Q,
    ) -> Result<KeyAssociation, Error> {
        self.check(snapshot)?;
        // The effective working key already carries the certificate's SPKI and
        // any inherited parameters; the provider compares exactly that key.
        self.session
            .with_key_association_in(signature, key, execution, |association| {
                Ok::<_, core::convert::Infallible>(match association {
                    provider::KeyAssociation::Same => KeyAssociation::Same,
                    provider::KeyAssociation::Mismatch => KeyAssociation::Differs,
                    provider::KeyAssociation::Unproven => KeyAssociation::Unproven,
                })
            })
            .map_err(|error| match error {
                CatalogueError::Processing(error) => error.into(),
                CatalogueError::Visitor(never) => match never {},
            })
    }
}

impl<W: Work> HashXml for Document<'_, '_, '_, '_, W> {
    fn visit_hash_uses<VE, Q: Work>(
        &self,
        snapshot: Snapshot,
        signature: NodeIdentity,
        execution: &Q,
        mut visitor: impl FnMut(HashUse<NodeIdentity>) -> Result<(), VE>,
    ) -> Result<HashCompleteness<NodeIdentity>, VisitError<Error, VE>> {
        self.check(snapshot).map_err(VisitError::Processing)?;
        let completeness = flatten(self.session.with_query(signature, execution, |selected| {
            selected.visit_hash_uses(|actual| {
                let origin = match actual.role {
                    HashUseRole::SignatureMessage => HashOrigin::SignatureMessage {
                        instruction: actual.instruction,
                        method: actual.method,
                    },
                    HashUseRole::MaskGeneration => HashOrigin::MaskGeneration {
                        instruction: actual.instruction,
                        method: actual.method,
                    },
                    HashUseRole::Reference(owner) => HashOrigin::Reference {
                        instruction: actual.instruction,
                        method: actual.method,
                        parent: parent(owner),
                    },
                };
                let state = match (actual.state, actual.algorithm) {
                    (
                        xml_sec::xmldsig::HashUseState::Complete,
                        HashUseAlgorithm::Digest(digest),
                    ) => HashUseState::Complete(hash_class(digest)),
                    // RFC 8032 §5.2: Ed448ph's SHAKE256 prehash is a known
                    // external digest other than MD5.
                    (xml_sec::xmldsig::HashUseState::Complete, HashUseAlgorithm::Shake256_512) => {
                        HashUseState::Complete(HashClass::OtherKnown)
                    }
                    (xml_sec::xmldsig::HashUseState::Complete, HashUseAlgorithm::Intrinsic(_)) => {
                        HashUseState::Complete(HashClass::Intrinsic)
                    }
                    (
                        xml_sec::xmldsig::HashUseState::Complete,
                        HashUseAlgorithm::Unsupported(_),
                    )
                    | (xml_sec::xmldsig::HashUseState::Unsupported, _) => HashUseState::Unsupported,
                    (xml_sec::xmldsig::HashUseState::Unprocessed, _) => HashUseState::Unprocessed,
                };
                visitor(HashUse {
                    signature: actual.signature,
                    origin,
                    state,
                })
            })
        }))?;
        Ok(match completeness {
            HashUseCompleteness::Complete => HashCompleteness::Complete,
            HashUseCompleteness::Unsupported(node) => HashCompleteness::Unsupported(node),
            HashUseCompleteness::Unprocessed(node) => HashCompleteness::Unprocessed(node),
        })
    }
}
