//! Shared compilation and execution state for one XML Security operation.

#[cfg(not(feature = "xmldsig-sign"))]
use std::marker::PhantomData;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashSet},
};

#[cfg(feature = "xmldsig")]
use crate::NodeIdentity;
#[cfg(feature = "xmldsig-sign")]
use crate::XmlDocument;
use crate::{DocumentIdentity, DocumentView};

/// Stable identifier assigned in deterministic discovery order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OperationNodeId(usize);

impl OperationNodeId {
    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// Ordered operation phases. Dependencies may stay within a phase, but may
/// never point from a later phase back into an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OperationStage {
    Parse,
    Resolve,
    // Signing digests References before SignedInfo exists; verification
    // digests them as authenticated dependencies after the signature.
    #[cfg(feature = "xmldsig-sign")]
    Digest,
    #[cfg(feature = "xmldsig")]
    Canonicalization,
    Crypto,
    #[cfg(feature = "xmldsig")]
    AuthenticatedDependency,
    Evidence,
    #[cfg(feature = "xmldsig-sign")]
    Mutation,
}

/// Semantic role of a node in a compiled operation plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OperationNodeKind {
    Document,
    #[cfg(feature = "xmlenc")]
    Ciphertext,
    #[cfg(feature = "xmldsig")]
    Manifest {
        index: usize,
    },
    Key {
        index: usize,
    },
    #[cfg(feature = "xmldsig")]
    Digest {
        index: usize,
    },
    #[cfg(feature = "xmldsig")]
    Canonicalization,
    Crypto,
    Evidence,
    #[cfg(feature = "xmldsig-sign")]
    Mutation,
}

/// Identity whose provenance must remain stable for the complete operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OperationResourceIdentity {
    /// Original immutable DOM node, valid only while its operation borrows the
    /// document. Never used as a cross-parse or persistent cache identity.
    #[cfg(feature = "xmlenc")]
    BorrowedDocumentNode {
        document: usize,
        node: crate::NodeId,
    },
    #[cfg(feature = "xmldsig")]
    DocumentNode(NodeIdentity),
    External {
        uri: String,
        fingerprint: [u8; 32],
    },
    #[cfg(feature = "xmldsig")]
    // Absence has no bytes to cache. The originating graph Reference retains
    // provenance; cloning absence must not clone an unaccounted URI string.
    MissingExternal,
    #[cfg(feature = "xmldsig")]
    Generated(&'static str, usize),
}

impl OperationResourceIdentity {
    pub(crate) fn external(uri: impl Into<String>, bytes: &[u8]) -> Self {
        use sha2::Digest;

        Self::External {
            uri: uri.into(),
            fingerprint: sha2::Sha256::digest(bytes).into(),
        }
    }
}

#[derive(Clone, Debug)]
struct OperationNode {
    kind: OperationNodeKind,
    stage: OperationStage,
    resource: Option<OperationResourceIdentity>,
}

/// A dependency edge from `requires` to `dependent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct OperationEdge {
    requires: OperationNodeId,
    dependent: OperationNodeId,
}

/// Structural compilation failures detected before execution.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum OperationPlanError {
    #[error("operation dependency references an unknown node")]
    UnknownNode,
    #[error("operation dependency points from {requires:?} back to {dependent:?}")]
    StageRegression {
        requires: OperationStage,
        dependent: OperationStage,
    },
    #[error("operation dependency graph contains a cycle")]
    Cycle,
    #[error("operation plan is bound to a different document")]
    ForeignDocument,
    #[error(
        "operation plan is bound to stale document generation {planned}; current generation is {current}"
    )]
    StaleGeneration { planned: u64, current: u64 },
    #[error("operation resource identity changed after plan compilation")]
    StaleResourceIdentity,
    #[cfg(feature = "xmldsig-sign")]
    #[error("operation mutation did not advance the document by exactly one generation")]
    InvalidGenerationTransition,
    #[error("operation node {node:?} executed before dependency {requires:?}")]
    DependencyNotExecuted {
        node: OperationNodeId,
        requires: OperationNodeId,
    },
    #[error("operation node executed more than once")]
    AlreadyExecuted,
}

/// Builder used while parsing and resolving operation inputs.
#[derive(Clone, Default)]
pub(crate) struct OperationPlanBuilder {
    nodes: Vec<OperationNode>,
    edges: HashSet<OperationEdge>,
}

impl OperationPlanBuilder {
    pub(crate) fn add_node(
        &mut self,
        kind: OperationNodeKind,
        stage: OperationStage,
        resource: Option<OperationResourceIdentity>,
    ) -> OperationNodeId {
        let id = OperationNodeId(self.nodes.len());
        self.nodes.push(OperationNode {
            kind,
            stage,
            resource,
        });
        id
    }

    pub(crate) fn add_dependency(
        &mut self,
        dependent: OperationNodeId,
        requires: OperationNodeId,
    ) -> Result<(), OperationPlanError> {
        let dependent_stage = self
            .nodes
            .get(dependent.index())
            .ok_or(OperationPlanError::UnknownNode)?
            .stage;
        let required_stage = self
            .nodes
            .get(requires.index())
            .ok_or(OperationPlanError::UnknownNode)?
            .stage;
        if required_stage > dependent_stage {
            return Err(OperationPlanError::StageRegression {
                requires: required_stage,
                dependent: dependent_stage,
            });
        }
        self.edges.insert(OperationEdge {
            requires,
            dependent,
        });
        Ok(())
    }

    pub(crate) fn compile(self) -> Result<CompiledOperationPlan, OperationPlanError> {
        let mut incoming = vec![0usize; self.nodes.len()];
        let mut outgoing = vec![Vec::new(); self.nodes.len()];
        for edge in &self.edges {
            *incoming
                .get_mut(edge.dependent.index())
                .ok_or(OperationPlanError::UnknownNode)? += 1;
            outgoing
                .get_mut(edge.requires.index())
                .ok_or(OperationPlanError::UnknownNode)?
                .push(edge.dependent);
        }
        for dependents in &mut outgoing {
            dependents.sort_unstable();
        }
        let mut ready = incoming
            .iter()
            .enumerate()
            .filter_map(|(index, count)| (*count == 0).then_some(OperationNodeId(index)))
            .collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(self.nodes.len());
        while let Some(id) = ready.pop_first() {
            order.push(id);
            for dependent in &outgoing[id.index()] {
                incoming[dependent.index()] -= 1;
                if incoming[dependent.index()] == 0 {
                    ready.insert(*dependent);
                }
            }
        }
        if order.len() != self.nodes.len() {
            return Err(OperationPlanError::Cycle);
        }
        Ok(CompiledOperationPlan {
            nodes: self.nodes,
            edges: self.edges,
            #[cfg(test)]
            order,
        })
    }
}

/// Immutable, validated dependency plan.
#[derive(Debug)]
pub(crate) struct CompiledOperationPlan {
    nodes: Vec<OperationNode>,
    edges: HashSet<OperationEdge>,
    #[cfg(test)]
    order: Vec<OperationNodeId>,
}

impl CompiledOperationPlan {
    #[cfg(test)]
    pub(crate) fn order(&self) -> &[OperationNodeId] {
        &self.order
    }

    pub(crate) fn kind(&self, id: OperationNodeId) -> &OperationNodeKind {
        &self.nodes[id.index()].kind
    }

    pub(crate) fn resource(&self, id: OperationNodeId) -> Option<&OperationResourceIdentity> {
        self.nodes[id.index()].resource.as_ref()
    }

    #[cfg(feature = "xmldsig")]
    fn builder(&self) -> OperationPlanBuilder {
        OperationPlanBuilder {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationDecisionReason {
    Completed,
    #[cfg(feature = "xmlenc")]
    CiphertextResolved,
    #[cfg(feature = "xmldsig")]
    ReferenceDigestVerified,
    #[cfg(feature = "xmldsig")]
    ReferenceDigestRejected,
    KeyResolved,
    #[cfg(feature = "xmldsig")]
    KeyUnavailable,
    SignatureVerified,
    #[cfg(feature = "xmldsig")]
    SignatureRejected,
    EvidenceFinalized,
    #[cfg(feature = "xmldsig-sign")]
    MutationCommitted,
    ActionRejected,
}

/// Typed internal record used to preserve deterministic first-failure state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationDecision {
    pub(crate) node: OperationNodeId,
    pub(crate) kind: OperationNodeKind,
    pub(crate) resource: Option<OperationResourceIdentity>,
    pub(crate) accepted: bool,
    pub(crate) reason: OperationDecisionReason,
}

/// Single owner of immutable policy, cumulative budgets, identity state and
/// execution evidence for one operation.
pub(crate) struct OperationExecutionContext<P, B> {
    // Only mutating operations read the bound policy back from the context.
    #[cfg(feature = "xmldsig-sign")]
    policy: P,
    #[cfg(not(feature = "xmldsig-sign"))]
    _policy: PhantomData<P>,
    budgets: B,
    builder: Option<OperationPlanBuilder>,
    plan: RefCell<Option<CompiledOperationPlan>>,
    document: Option<(DocumentIdentity, Cell<u64>)>,
    executed: RefCell<HashSet<OperationNodeId>>,
    #[cfg(feature = "xmldsig")]
    authenticated_nodes: RefCell<HashSet<NodeIdentity>>,
    decisions: RefCell<Vec<OperationDecision>>,
    first_failure: RefCell<Option<OperationDecision>>,
}

impl<P, B> OperationExecutionContext<P, B> {
    pub(crate) fn new(policy: P, budgets: B, document: Option<(DocumentIdentity, u64)>) -> Self {
        #[cfg(not(feature = "xmldsig-sign"))]
        drop(policy);
        Self {
            #[cfg(feature = "xmldsig-sign")]
            policy,
            #[cfg(not(feature = "xmldsig-sign"))]
            _policy: PhantomData,
            budgets,
            builder: Some(OperationPlanBuilder::default()),
            plan: RefCell::new(None),
            document: document.map(|(identity, generation)| (identity, Cell::new(generation))),
            executed: RefCell::new(HashSet::new()),
            #[cfg(feature = "xmldsig")]
            authenticated_nodes: RefCell::new(HashSet::new()),
            decisions: RefCell::new(Vec::new()),
            first_failure: RefCell::new(None),
        }
    }

    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn policy(&self) -> &P {
        &self.policy
    }

    pub(crate) fn budgets(&self) -> &B {
        &self.budgets
    }

    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn budgets_mut(&mut self) -> &mut B {
        &mut self.budgets
    }

    pub(crate) fn plan(&self) -> std::cell::Ref<'_, CompiledOperationPlan> {
        std::cell::Ref::map(self.plan.borrow(), |plan| {
            plan.as_ref()
                .expect("operation plan must be compiled before execution")
        })
    }

    pub(crate) fn add_node(
        &mut self,
        kind: OperationNodeKind,
        stage: OperationStage,
        resource: Option<OperationResourceIdentity>,
    ) -> OperationNodeId {
        self.builder
            .as_mut()
            .expect("operation plan cannot change after compilation")
            .add_node(kind, stage, resource)
    }

    pub(crate) fn add_dependency(
        &mut self,
        dependent: OperationNodeId,
        requires: OperationNodeId,
    ) -> Result<(), OperationPlanError> {
        self.builder
            .as_mut()
            .expect("operation plan cannot change after compilation")
            .add_dependency(dependent, requires)
    }

    pub(crate) fn compile(&mut self) -> Result<(), OperationPlanError> {
        let builder = self
            .builder
            .take()
            .expect("operation plan cannot be compiled more than once");
        *self.plan.get_mut() = Some(builder.compile()?);
        Ok(())
    }

    /// Reopens a compiled plan so authenticated structure discovered after a
    /// successful cryptographic gate can be added without replacing operation
    /// policy, budgets, identity bindings, or accumulated evidence.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn extend(&mut self) {
        let plan = self
            .plan
            .get_mut()
            .take()
            .expect("operation plan must be compiled before it can be extended");
        self.builder = Some(plan.builder());
    }

    /// Add a resource discovered after parsing without cloning/recompiling the
    /// graph or resetting its budgets. New edges cannot cycle: the prerequisite
    /// is already complete and the dependent has not completed yet.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn run_discovered_resource<T, E>(
        &self,
        requires: OperationNodeId,
        dependent: OperationNodeId,
        identity: &OperationResourceIdentity,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        let resource = {
            let mut captured_plan = self.plan.borrow_mut();
            let plan = captured_plan.as_mut().expect("compiled operation plan");
            let prerequisite = plan
                .nodes
                .get(requires.index())
                .ok_or(OperationPlanError::UnknownNode)
                .map_err(E::from)?;
            let consumer = plan
                .nodes
                .get(dependent.index())
                .ok_or(OperationPlanError::UnknownNode)
                .map_err(E::from)?;
            if !self.is_executed(requires) {
                return Err(E::from(OperationPlanError::DependencyNotExecuted {
                    node: dependent,
                    requires,
                }));
            }
            if self.is_executed(dependent) {
                return Err(E::from(OperationPlanError::AlreadyExecuted));
            }
            if prerequisite.stage > consumer.stage {
                return Err(E::from(OperationPlanError::StageRegression {
                    requires: prerequisite.stage,
                    dependent: consumer.stage,
                }));
            }
            let stage = consumer.stage;
            let resource = OperationNodeId(plan.nodes.len());
            plan.nodes.push(OperationNode {
                kind: OperationNodeKind::Ciphertext,
                stage,
                resource: Some(identity.clone()),
            });
            plan.edges.insert(OperationEdge {
                requires,
                dependent: resource,
            });
            plan.edges.insert(OperationEdge {
                requires: resource,
                dependent,
            });
            #[cfg(test)]
            plan.order.insert(
                plan.order
                    .iter()
                    .position(|node| *node == dependent)
                    .unwrap_or(plan.order.len()),
                resource,
            );
            resource
        };
        self.run_with_resource(resource, identity, action)
    }

    pub(crate) fn validate_document_view(
        &self,
        view: DocumentView<'_>,
    ) -> Result<(), OperationPlanError> {
        let Some((identity, generation)) = &self.document else {
            return Ok(());
        };
        if view.identity() != *identity {
            return Err(OperationPlanError::ForeignDocument);
        }
        if view.generation() != generation.get() {
            return Err(OperationPlanError::StaleGeneration {
                planned: generation.get(),
                current: view.generation(),
            });
        }
        Ok(())
    }

    fn validate_ready(
        &self,
        node: OperationNodeId,
        observed: Option<&OperationResourceIdentity>,
    ) -> Result<(), OperationPlanError> {
        if node.index() >= self.plan().nodes.len() {
            return Err(OperationPlanError::UnknownNode);
        }
        if self.plan().resource(node) != observed {
            return Err(OperationPlanError::StaleResourceIdentity);
        }
        if self.executed.borrow().contains(&node) {
            return Err(OperationPlanError::AlreadyExecuted);
        }
        if let Some(requires) = self
            .plan()
            .edges
            .iter()
            .filter(|edge| edge.dependent == node)
            .filter_map(|edge| {
                (!self.executed.borrow().contains(&edge.requires)).then_some(edge.requires)
            })
            .min()
        {
            return Err(OperationPlanError::DependencyNotExecuted { node, requires });
        }
        Ok(())
    }

    fn completion_reason(&self, node: OperationNodeId) -> OperationDecisionReason {
        match self.plan().kind(node) {
            #[cfg(feature = "xmlenc")]
            OperationNodeKind::Ciphertext => OperationDecisionReason::CiphertextResolved,
            OperationNodeKind::Key { .. } => OperationDecisionReason::KeyResolved,
            #[cfg(feature = "xmldsig")]
            OperationNodeKind::Digest { .. } => OperationDecisionReason::ReferenceDigestVerified,
            OperationNodeKind::Crypto => OperationDecisionReason::SignatureVerified,
            OperationNodeKind::Evidence => OperationDecisionReason::EvidenceFinalized,
            #[cfg(feature = "xmldsig-sign")]
            OperationNodeKind::Mutation => OperationDecisionReason::MutationCommitted,
            OperationNodeKind::Document => OperationDecisionReason::Completed,
            #[cfg(feature = "xmldsig")]
            OperationNodeKind::Manifest { .. } => OperationDecisionReason::Completed,
            #[cfg(feature = "xmldsig")]
            OperationNodeKind::Canonicalization => OperationDecisionReason::Completed,
        }
    }

    pub(crate) fn run<T, E>(
        &self,
        node: OperationNodeId,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.validate_ready(node, None).map_err(E::from)?;
        self.run_ready(node, action)
    }

    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn run_with_budgets<T, E>(
        &mut self,
        node: OperationNodeId,
        action: impl FnOnce(&mut B) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.validate_ready(node, None).map_err(E::from)?;
        match action(&mut self.budgets) {
            Ok(value) => {
                self.executed.borrow_mut().insert(node);
                self.record(node, true, self.completion_reason(node));
                Ok(value)
            }
            Err(error) => {
                self.record(node, false, OperationDecisionReason::ActionRejected);
                Err(error)
            }
        }
    }

    /// Run several ready nodes as one read of the planned document generation.
    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn run_document_batch_with_budgets<T, E>(
        &mut self,
        nodes: &[OperationNodeId],
        document: &XmlDocument,
        action: impl FnOnce(&XmlDocument, &mut B) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        document
            .with_view(|view| self.validate_document_view(view))
            .map_err(E::from)?;
        for node in nodes {
            self.validate_ready(*node, None).map_err(E::from)?;
        }
        match action(document, &mut self.budgets) {
            Ok(value) => {
                for node in nodes {
                    self.executed.borrow_mut().insert(*node);
                    self.record(*node, true, self.completion_reason(*node));
                }
                Ok(value)
            }
            Err(error) => {
                for node in nodes {
                    self.record(*node, false, OperationDecisionReason::ActionRejected);
                }
                Err(error)
            }
        }
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn run_batch<T, E>(
        &self,
        nodes: &[OperationNodeId],
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        for node in nodes {
            self.validate_ready(*node, None).map_err(E::from)?;
        }
        match action() {
            Ok(value) => {
                for node in nodes {
                    self.executed.borrow_mut().insert(*node);
                    self.record(*node, true, self.completion_reason(*node));
                }
                Ok(value)
            }
            Err(error) => {
                for node in nodes {
                    self.record(*node, false, OperationDecisionReason::ActionRejected);
                }
                Err(error)
            }
        }
    }

    pub(crate) fn run_with_resource<T, E>(
        &self,
        node: OperationNodeId,
        observed: &OperationResourceIdentity,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.validate_ready(node, Some(observed)).map_err(E::from)?;
        self.run_ready(node, action)
    }

    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn run_document_transition<T, E>(
        &mut self,
        node: OperationNodeId,
        document: &mut XmlDocument,
        action: impl FnOnce(&mut XmlDocument, &mut B) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.run_document_transition_nodes(&[node], document, action)
    }

    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn run_document_transition_batch_with_budgets<T, E>(
        &mut self,
        nodes: &[OperationNodeId],
        document: &mut XmlDocument,
        action: impl FnOnce(&mut XmlDocument, &mut B) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.run_document_transition_nodes(nodes, document, action)
    }

    #[cfg(feature = "xmldsig-sign")]
    fn run_document_transition_nodes<T, E>(
        &mut self,
        nodes: &[OperationNodeId],
        document: &mut XmlDocument,
        action: impl FnOnce(&mut XmlDocument, &mut B) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        document
            .with_view(|view| self.validate_document_view(view))
            .map_err(E::from)?;
        for node in nodes {
            self.validate_ready(*node, None).map_err(E::from)?;
        }
        let generation = document.generation();
        let value = match action(document, &mut self.budgets) {
            Ok(value) => value,
            Err(error) => {
                for node in nodes {
                    self.record(*node, false, OperationDecisionReason::ActionRejected);
                }
                return Err(error);
            }
        };
        if document.generation() != generation.saturating_add(1) {
            for node in nodes {
                self.record(*node, false, OperationDecisionReason::ActionRejected);
            }
            return Err(E::from(OperationPlanError::InvalidGenerationTransition));
        }
        if let Some((_, expected)) = &self.document {
            expected.set(document.generation());
        }
        for node in nodes {
            self.executed.borrow_mut().insert(*node);
            self.record(*node, true, self.completion_reason(*node));
        }
        Ok(value)
    }

    /// Run a mutation whose next generation is handed to the caller as its
    /// serialization instead of being committed to `document`.
    #[cfg(feature = "xmldsig-sign")]
    pub(crate) fn run_document_projection<T, E>(
        &self,
        node: OperationNodeId,
        document: &XmlDocument,
        action: impl FnOnce(&XmlDocument) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        document
            .with_view(|view| self.validate_document_view(view))
            .map_err(E::from)?;
        self.validate_ready(node, None).map_err(E::from)?;
        self.run_ready(node, || action(document))
    }

    fn run_ready<T, E>(
        &self,
        node: OperationNodeId,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        let edges_before = self.plan().edges.len();
        match action() {
            Ok(value) => {
                if self.plan().edges.len() != edges_before {
                    let plan = self.plan();
                    self.validate_ready(node, plan.resource(node))
                        .map_err(E::from)?;
                }
                self.executed.borrow_mut().insert(node);
                self.record(node, true, self.completion_reason(node));
                Ok(value)
            }
            Err(error) => {
                self.record(node, false, OperationDecisionReason::ActionRejected);
                Err(error)
            }
        }
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn authenticate(&self, node: NodeIdentity) {
        self.authenticated_nodes.borrow_mut().insert(node);
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn is_authenticated(&self, node: NodeIdentity) -> bool {
        self.authenticated_nodes.borrow().contains(&node)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn decision_count(&self) -> usize {
        self.decisions.borrow().len()
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn accepted_signature(&self) -> Option<OperationNodeId> {
        self.decisions.borrow().iter().find_map(|decision| {
            (decision.accepted && decision.reason == OperationDecisionReason::SignatureVerified)
                .then_some(decision.node)
        })
    }

    /// Gate a scoped replay on the original graph's accepted crypto dependency.
    /// The scoped caller records each invocation in its accounted continuation
    /// storage; the completed original digest node is never executed twice.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn run_reference_replay<T, E>(
        &self,
        view: DocumentView<'_>,
        reference: NodeIdentity,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        self.validate_document_view(view).map_err(E::from)?;
        let requires = self
            .accepted_signature()
            .ok_or(OperationPlanError::UnknownNode)
            .map_err(E::from)?;
        if !self.is_executed(requires) {
            return Err(E::from(OperationPlanError::UnknownNode));
        }
        view.resolve_node(reference)
            .map_err(|_| E::from(OperationPlanError::StaleResourceIdentity))?;
        action()
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn is_executed(&self, node: OperationNodeId) -> bool {
        self.executed.borrow().contains(&node)
    }

    pub(crate) fn record(
        &self,
        node: OperationNodeId,
        accepted: bool,
        reason: OperationDecisionReason,
    ) {
        let decision = OperationDecision {
            node,
            kind: self.plan().kind(node).clone(),
            resource: self.plan().resource(node).cloned(),
            accepted,
            reason,
        };
        if !accepted && self.first_failure.borrow().is_none() {
            *self.first_failure.borrow_mut() = Some(decision.clone());
        }
        self.decisions.borrow_mut().push(decision);
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn set_outcome(
        &self,
        node: OperationNodeId,
        accepted: bool,
        reason: OperationDecisionReason,
    ) {
        let mut decisions = self.decisions.borrow_mut();
        let decision = decisions
            .iter_mut()
            .rev()
            .find(|decision| decision.node == node)
            .expect("operation outcome requires an executed node");
        decision.accepted = accepted;
        decision.reason = reason;
        if !accepted && self.first_failure.borrow().is_none() {
            *self.first_failure.borrow_mut() = Some(decision.clone());
        }
    }

    #[cfg(all(test, feature = "xmldsig"))]
    pub(crate) fn first_failure(&self) -> Option<OperationDecision> {
        self.first_failure.borrow().clone()
    }
}

#[cfg(test)]
mod tests;
