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
        let processing = ReplayError::Processing;
        work.charge_work(1)
            .map_err(|error| processing(error.into()))?;
        let allowed = self.context.policy.transforms.allowed_algorithms.as_ref();
        let (algorithm, prefixes) = self.timestamp_method(method, allowed, work)?;
        let node = self
            .view
            .resolve_node(element)
            .map_err(|error| processing(error.into()))?;
        if !node.is_element() {
            return Err(processing(DsigError::InvalidRequest {
                reason: "canonicalization input is not an element",
            }));
        }
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
            Some(&crate::c14n::SubtreeVisibility { apex: node }),
            &algorithm,
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
