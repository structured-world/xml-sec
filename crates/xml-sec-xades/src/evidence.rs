//! RFC 6283 evidence records of ETSI TS 119 132-3 over the verified document.

use crate::signature::any_uri;
use crate::{Document, Error, Snapshot};
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_cms::stream::Receiver;
use structured_pkix::algorithm::digest::Algorithm;
use structured_xades::evidence::XML_ERS;
use structured_xades::evidence::xmlers::{CanonicalInput, XmlRecordXml};
use structured_xades::xml::Name;
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::extension::{self, NodeView};
use xml_sec::xmldsig::{DigestMethodResolution, ReplayError};

impl<W: Work> XmlRecordXml for Document<'_, '_, '_, '_, W> {
    fn evidence_digest<Q: Work>(
        &self,
        snapshot: Snapshot,
        method: NodeIdentity,
        work: &Q,
    ) -> Result<Resolution<Algorithm>, Error> {
        self.check(snapshot)?;
        self.with_attribute(
            method,
            Name {
                namespace: "",
                local: "Algorithm",
            },
            work,
            |value| {
                let Some(value) = value else {
                    return Ok(Resolution::Malformed);
                };
                // RFC 6283 Appendix A types Algorithm as anyURI, whose
                // whiteSpace is collapse (XSD 1.0 §4.3.6); the operation's
                // digest policy decides it as for any XMLDSig digest.
                Ok(
                    match self.session.resolve_digest_uri_in(any_uri(value), work)? {
                        DigestMethodResolution::Supported(algorithm) => algorithm
                            .to_pkix()
                            .map_or(Resolution::Unsupported, Resolution::Supported),
                        DigestMethodResolution::Unsupported => Resolution::Unsupported,
                        DigestMethodResolution::Malformed => Resolution::Malformed,
                    },
                )
            },
        )?
    }

    fn canonicalize_evidence<Q: Work>(
        &self,
        snapshot: Snapshot,
        method: NodeIdentity,
        input: CanonicalInput<'_, NodeIdentity>,
        receiver: &mut impl Receiver,
        work: &Q,
    ) -> Result<(), Error> {
        self.check(snapshot)?;
        let mut excluded = work.vector();
        if let CanonicalInput::Sequence { node, chains } = input {
            // RFC 6283 §4.2.2: the sequence holds its earlier chains in
            // ascending Order. A document subset keeps document order, so the
            // kept chains must already stand in that order.
            let view = self.session.view();
            let mut kept = chains.iter();
            let mut child = extension::first_child(view, node, work)?;
            while let Some(current) = child {
                let is_chain = extension::inspect_node(view, current, work, |value| {
                    matches!(
                        value,
                        NodeView::Element {
                            namespace: Some(XML_ERS),
                            local_name: "ArchiveTimeStampChain"
                        }
                    )
                })?;
                if is_chain {
                    if chains.iter().any(|chain| chain.chain.node == current) {
                        if kept.next().map(|chain| chain.chain.node) != Some(current) {
                            return Err(Error::ChainOrder);
                        }
                    } else {
                        excluded.try_push(current)?;
                    }
                }
                child = extension::next_sibling(view, node, current, work)?;
            }
            if kept.next().is_some() {
                return Err(Error::ChainOrder);
            }
        }
        self.session
            .canonicalize_element_without(input.node(), &excluded, method, work, &mut |bytes| {
                receiver.write(bytes)
            })
            .map_err(|error| match error {
                ReplayError::Processing(error) => error.into(),
                ReplayError::Receiver(_) => Error::ReceiverRefused,
            })
    }
}

#[cfg(feature = "produce")]
pub(crate) use draft::{Kind, Sealing};

#[cfg(feature = "produce")]
mod draft {
    use crate::{Document, Error, Snapshot};
    use structured_asn1::memory::Work;
    use structured_xades::evidence::{Placement, SealingDraft, Transition};
    use structured_xades::xml::Xml;
    use xml_sec::document::{DocumentIdentity, NodeIdentity};
    use xml_sec::xmldsig::VerifiedSession;

    /// Where the drafted record went.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Kind {
        /// A new `SealingEvidenceRecords` appended to the unsigned signature
        /// properties.
        Serial,
        /// A new record appended to the last `SealingEvidenceRecords`.
        Parallel,
    }

    /// The one change of a transaction that added a drafted evidence record,
    /// established by the document itself (`XmlDocument::appended_child`).
    ///
    /// It is built only after the starting generation met B-LT, which holds
    /// the validation data ETSI TS 119 132-3 §5.1.2 requires before a first
    /// seal.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Sealing {
        /// The generation the transaction started from.
        pub(crate) base: Snapshot,
        pub(crate) kind: Kind,
        /// The sealed signature in the starting generation, then in this one.
        pub(crate) signature: [NodeIdentity; 2],
        /// The element the record was appended to, in the starting generation.
        pub(crate) parent: NodeIdentity,
        /// The appended element, in this generation.
        pub(crate) appended: NodeIdentity,
    }

    impl<'s, 'view, 'scope, 'inputs, W: Work> Document<'s, 'view, 'scope, 'inputs, W> {
        /// The adapter over a generation staged with the one change `sealing`.
        pub(crate) fn sealed(
            session: &'s VerifiedSession<'view, 'scope, 'inputs, W>,
            sealing: Sealing,
        ) -> Self {
            Self {
                session,
                sealing: Some(sealing),
            }
        }
    }

    impl<W: Work> SealingDraft for Document<'_, '_, '_, '_, W> {
        fn check_sealing_transition<Q: Work>(
            &self,
            transition: Transition<NodeIdentity, DocumentIdentity, u64>,
            work: &Q,
        ) -> Result<bool, Error> {
            work.charge_work(1)?;
            let Some(sealing) = self.sealing else {
                return Ok(false);
            };
            if transition.base != sealing.base
                || transition.staged != self.snapshot()
                || transition.original_signature != sealing.signature[0]
                || transition.staged_signature != sealing.signature[1]
            {
                return Ok(false);
            }
            Ok(match (transition.placement, sealing.kind) {
                // A later serial seal first closes the previous group's tail
                // validation data (ETSI TS 119 132-3 §5.1.2), which this
                // crate does not draft; only the first seal is checked here.
                (Placement::Serial(Some(parent)), Kind::Serial) => {
                    parent == sealing.parent
                        && transition.first_seal
                        && transition.preceding_group.is_none()
                        && self.parent(transition.staged_member, work)? == Some(sealing.appended)
                }
                (Placement::Parallel(group), Kind::Parallel) => {
                    group == sealing.parent && transition.staged_member == sealing.appended
                }
                _ => false,
            })
        }
    }
}
