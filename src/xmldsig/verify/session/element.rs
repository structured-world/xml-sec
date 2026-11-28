//! Canonical output of one original element under an original method node.

use super::{
    BTreeSet, DsigError, NodeIdentity, ReplayError, ReplayWriter, String, VerifiedSession, Work,
    enforce_current_transform_allowed, replay_parse_failure,
};

impl<W: Work> VerifiedSession<'_, '_, '_, W> {
    /// The timestamp's canonicalization method, after its URI passes the
    /// operation's transform permission.
    pub(super) fn timestamp_method<Q: Work, E>(
        &self,
        method: NodeIdentity,
        allowed: Option<&BTreeSet<String>>,
        work: &Q,
    ) -> Result<(crate::c14n::C14nAlgorithm, Option<&str>), ReplayError<E>> {
        let processing = ReplayError::Processing;
        let method = self
            .view
            .resolve_node(method)
            .map_err(|error| processing(error.into()))?;
        let uri = method.attribute("Algorithm").ok_or_else(|| {
            processing(DsigError::InvalidStructure {
                reason: "timestamp method has no Algorithm",
            })
        })?;
        work.charge_work(uri.len() as u64)
            .map_err(|error| processing(error.into()))?;
        enforce_current_transform_allowed(allowed, uri, work).map_err(processing)?;
        super::super::super::parse::parse_replay_canonicalization_method(
            method,
            &crate::c14n::scratch::Accounted(work),
        )
        .map_err(replay_parse_failure)
    }

    /// Stream the canonical form of `element`'s whole subtree under the original
    /// `CanonicalizationMethod` node `method`, including its parameters. Ancestor
    /// namespace and `xml:*` context is the C14N algorithm's own. Output and
    /// scratch spend `work`; the operation's transform policy and cumulative
    /// C14N allowance still apply. This reads the node unauthenticated: the
    /// caller establishes why the element belongs to its input.
    ///
    /// # Errors
    /// Returns a processing error for a foreign/stale identity, a non-element
    /// `element`, an invalid or forbidden method, or resource refusal. Preserves
    /// receiver errors separately.
    pub fn canonicalize_element<Q: Work, E>(
        &self,
        element: NodeIdentity,
        method: NodeIdentity,
        work: &Q,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ReplayError<E>> {
        self.canonicalize_element_without(element, &[], method, work, receiver)
    }

    /// [`Self::canonicalize_element`] with the subtrees of the `excluded`
    /// descendant elements left out, as RFC 6283 §4.2.2 hash-tree renewal
    /// canonicalizes an `ArchiveTimeStampSequence` with only its earlier
    /// chains. The selection is a document subset (C14N 1.0 §2.1), so the
    /// remaining nodes keep their document order.
    ///
    /// # Errors
    /// As [`Self::canonicalize_element`], and a processing error for an
    /// excluded identity that is not a descendant element of `element`.
    pub fn canonicalize_element_without<Q: Work, E>(
        &self,
        element: NodeIdentity,
        excluded: &[NodeIdentity],
        method: NodeIdentity,
        work: &Q,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ReplayError<E>> {
        let processing = ReplayError::Processing;
        work.charge_work(1)
            .map_err(|error| processing(error.into()))?;
        let allowed = self.context.policy.transforms.allowed_algorithms.as_ref();
        let (algorithm, prefixes) = self.timestamp_method(method, allowed, work)?;
        self.canonicalize_subset(element, excluded, &algorithm, prefixes, work, receiver)
    }

    /// The canonical form of `element`'s whole subtree under `algorithm`,
    /// for an input whose canonicalization no element names, such as a
    /// TS 101 903 V1.2.2 timestamp without `CanonicalizationMethod`, which
    /// uses the `XMLDSig` default (§7.1.4). The algorithm passes the
    /// operation's transform permission.
    ///
    /// # Errors
    /// As [`Self::canonicalize_element`].
    pub fn canonicalize_element_as<Q: Work, E>(
        &self,
        element: NodeIdentity,
        algorithm: &crate::c14n::C14nAlgorithm,
        work: &Q,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ReplayError<E>> {
        let processing = ReplayError::Processing;
        work.charge_work(1)
            .map_err(|error| processing(error.into()))?;
        let allowed = self.context.policy.transforms.allowed_algorithms.as_ref();
        enforce_current_transform_allowed(allowed, algorithm.uri(), work).map_err(processing)?;
        self.canonicalize_subset(element, &[], algorithm, None, work, receiver)
    }

    /// The canonical form of `element` without the `excluded` subtrees.
    fn canonicalize_subset<Q: Work, E>(
        &self,
        element: NodeIdentity,
        excluded: &[NodeIdentity],
        algorithm: &crate::c14n::C14nAlgorithm,
        prefixes: Option<&str>,
        work: &Q,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ReplayError<E>> {
        let processing = ReplayError::Processing;
        let node = self
            .view
            .resolve_node(element)
            .map_err(|error| processing(error.into()))?;
        if !node.is_element() {
            return Err(processing(DsigError::InvalidRequest {
                reason: "canonicalization input is not an element",
            }));
        }
        let mut pruned = work.vector();
        if !excluded.is_empty() {
            // Each visited node is tested against every excluded subtree.
            (self.view.node_count() as u64)
                .checked_mul(excluded.len() as u64)
                .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
                .and_then(|tests| work.charge_work(tests))
                .map_err(|error| processing(error.into()))?;
            pruned
                .try_reserve_exact(excluded.len())
                .map_err(|error| processing(error.into()))?;
            for identity in excluded {
                let child = self
                    .view
                    .resolve_node(*identity)
                    .map_err(|error| processing(error.into()))?;
                if !child.is_element()
                    || child.id() == node.id()
                    || !node.subtree_contains_id(child.id())
                {
                    return Err(processing(DsigError::InvalidRequest {
                        reason: "an excluded node is not a descendant element of the input",
                    }));
                }
                pruned
                    .try_push(child)
                    .map_err(|error| processing(error.into()))?;
            }
        }
        let subtree = crate::c14n::SubtreeVisibility { apex: node };
        let without = crate::c14n::PrunedSubtreeVisibility {
            apex: node,
            excluded: &pruned,
        };
        let visibility: &dyn crate::c14n::NodeVisibility<_> = if pruned.is_empty() {
            &subtree
        } else {
            &without
        };
        let budget = &self.budgets.transforms;
        let mut output = ReplayWriter {
            work,
            budget,
            canonicalizing: true,
            receiver,
            failure: None,
        };
        let result = crate::c14n::canonicalize_visible_to_writer_accounted(
            node.document(),
            Some(visibility),
            algorithm,
            super::super::super::transforms::replay_output_limit(budget),
            budget.xml_base_resolution(),
            &mut output,
            work,
            prefixes,
        );
        if let Some(error) = output.failure {
            return Err(error);
        }
        result.map_err(|error| match error {
            crate::c14n::C14nError::SharedExecution(error) => ReplayError::Processing(error.into()),
            error => super::super::super::transforms::replay_c14n_error(error, budget).into(),
        })
    }
}
