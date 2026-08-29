//! Shared compilation and execution state for one XML Security operation.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashSet},
};

use crate::{DocumentIdentity, DocumentView, NodeIdentity, XmlDocument};

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
    Digest,
    Canonicalization,
    Crypto,
    AuthenticatedDependency,
    Evidence,
    Mutation,
}

/// Semantic role of a node in a compiled operation plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OperationNodeKind {
    Document,
    Manifest { index: usize },
    Key { index: usize },
    Digest { index: usize },
    Canonicalization,
    Crypto,
    Evidence,
    Mutation,
}

/// Identity whose provenance must remain stable for the complete operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OperationResourceIdentity {
    DocumentNode(NodeIdentity),
    External { uri: String, fingerprint: [u8; 32] },
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
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
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
    ReferenceDigestVerified,
    ReferenceDigestRejected,
    KeyResolved,
    KeyUnavailable,
    SignatureVerified,
    SignatureRejected,
    EvidenceFinalized,
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
    policy: P,
    budgets: B,
    builder: Option<OperationPlanBuilder>,
    plan: Option<CompiledOperationPlan>,
    document: Option<(DocumentIdentity, Cell<u64>)>,
    executed: RefCell<HashSet<OperationNodeId>>,
    authenticated_nodes: RefCell<HashSet<NodeIdentity>>,
    decisions: RefCell<Vec<OperationDecision>>,
    first_failure: RefCell<Option<OperationDecision>>,
}

impl<P, B> OperationExecutionContext<P, B> {
    pub(crate) fn new(policy: P, budgets: B, document: Option<(DocumentIdentity, u64)>) -> Self {
        Self {
            policy,
            budgets,
            builder: Some(OperationPlanBuilder::default()),
            plan: None,
            document: document.map(|(identity, generation)| (identity, Cell::new(generation))),
            executed: RefCell::new(HashSet::new()),
            authenticated_nodes: RefCell::new(HashSet::new()),
            decisions: RefCell::new(Vec::new()),
            first_failure: RefCell::new(None),
        }
    }

    pub(crate) fn policy(&self) -> &P {
        &self.policy
    }

    pub(crate) fn budgets(&self) -> &B {
        &self.budgets
    }

    pub(crate) fn budgets_mut(&mut self) -> &mut B {
        &mut self.budgets
    }

    pub(crate) fn plan(&self) -> &CompiledOperationPlan {
        self.plan
            .as_ref()
            .expect("operation plan must be compiled before execution")
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
        self.plan = Some(builder.compile()?);
        Ok(())
    }

    /// Reopens a compiled plan so authenticated structure discovered after a
    /// successful cryptographic gate can be added without replacing operation
    /// policy, budgets, identity bindings, or accumulated evidence.
    pub(crate) fn extend(&mut self) {
        let plan = self
            .plan
            .take()
            .expect("operation plan must be compiled before it can be extended");
        self.builder = Some(plan.builder());
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
            OperationNodeKind::Key { .. } => OperationDecisionReason::KeyResolved,
            OperationNodeKind::Digest { .. } => OperationDecisionReason::ReferenceDigestVerified,
            OperationNodeKind::Crypto => OperationDecisionReason::SignatureVerified,
            OperationNodeKind::Evidence => OperationDecisionReason::EvidenceFinalized,
            OperationNodeKind::Mutation => OperationDecisionReason::MutationCommitted,
            OperationNodeKind::Document | OperationNodeKind::Manifest { .. } => {
                OperationDecisionReason::Completed
            }
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

    pub(crate) fn run_batch_with_resources<T, E>(
        &self,
        nodes: &[(OperationNodeId, OperationResourceIdentity)],
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<OperationPlanError>,
    {
        for (node, observed) in nodes {
            self.validate_ready(*node, Some(observed))
                .map_err(E::from)?;
        }
        match action() {
            Ok(value) => {
                for (node, _) in nodes {
                    self.executed.borrow_mut().insert(*node);
                    self.record(*node, true, self.completion_reason(*node));
                }
                Ok(value)
            }
            Err(error) => {
                for (node, _) in nodes {
                    self.record(*node, false, OperationDecisionReason::ActionRejected);
                }
                Err(error)
            }
        }
    }

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

    fn run_ready<T, E>(
        &self,
        node: OperationNodeId,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        match action() {
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

    pub(crate) fn authenticate(&self, node: NodeIdentity) {
        self.authenticated_nodes.borrow_mut().insert(node);
    }

    pub(crate) fn is_authenticated(&self, node: NodeIdentity) -> bool {
        self.authenticated_nodes.borrow().contains(&node)
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

    pub(crate) fn first_failure(&self) -> Option<OperationDecision> {
        self.first_failure.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(builder: &mut OperationPlanBuilder, stage: OperationStage) -> OperationNodeId {
        builder.add_node(OperationNodeKind::Document, stage, None)
    }

    #[test]
    fn compile_is_deterministic_and_rejects_cycles() {
        // Stable discovery order makes equal-priority nodes deterministic while
        // a cycle is rejected before any operation stage can execute.
        let mut builder = OperationPlanBuilder::default();
        let first = node(&mut builder, OperationStage::Digest);
        let second = node(&mut builder, OperationStage::Digest);
        let final_node = node(&mut builder, OperationStage::Crypto);
        builder
            .add_dependency(final_node, second)
            .expect("valid edge");
        builder
            .add_dependency(final_node, first)
            .expect("valid edge");
        let plan = builder.compile().expect("acyclic plan");
        assert_eq!(plan.order(), &[first, second, final_node]);

        let mut cyclic = OperationPlanBuilder::default();
        let left = node(&mut cyclic, OperationStage::Digest);
        let right = node(&mut cyclic, OperationStage::Digest);
        cyclic.add_dependency(left, right).expect("same-stage edge");
        cyclic.add_dependency(right, left).expect("same-stage edge");
        assert_eq!(
            cyclic.compile().expect_err("cycle must be rejected"),
            OperationPlanError::Cycle
        );
    }

    #[test]
    fn execution_requires_dependencies_and_preserves_first_failure() {
        // Out-of-order execution and later failures cannot replace the first
        // deterministic failure selected by the compiled plan.
        let mut builder = OperationPlanBuilder::default();
        let parse = node(&mut builder, OperationStage::Parse);
        let crypto = node(&mut builder, OperationStage::Crypto);
        builder.add_dependency(crypto, parse).expect("valid edge");
        let plan = builder.compile().expect("valid plan");
        let mut context = OperationExecutionContext::new((), (), None);
        context.builder = None;
        context.plan = Some(plan);
        let ran = Cell::new(false);
        assert_eq!(
            context.run(crypto, || {
                ran.set(true);
                Ok::<_, OperationPlanError>(())
            }),
            Err(OperationPlanError::DependencyNotExecuted {
                node: crypto,
                requires: parse,
            })
        );
        assert!(!ran.get(), "dependency checks must gate the action itself");
        context.record(parse, false, OperationDecisionReason::ActionRejected);
        context.record(crypto, false, OperationDecisionReason::ActionRejected);
        assert_eq!(
            context.first_failure().map(|item| item.reason),
            Some(OperationDecisionReason::ActionRejected)
        );
    }

    #[test]
    fn document_generation_binding_rejects_stale_plans() {
        // Mutation invalidates every plan compiled against the prior document
        // generation, preventing stale resolver or transform-cache reuse.
        let mut document = crate::XmlDocument::parse("<root><value/></root>").expect("document");
        let mut builder = OperationPlanBuilder::default();
        node(&mut builder, OperationStage::Parse);
        let plan = builder.compile().expect("plan");
        let mut context = OperationExecutionContext::new(
            (),
            (),
            Some((document.identity(), document.generation())),
        );
        context.builder = None;
        context.plan = Some(plan);
        let target = document.with_view(|view| view.root_element());
        document
            .replace_element(target, "<changed/>")
            .expect("mutation");
        assert_eq!(
            document.with_view(|view| context.validate_document_view(view)),
            Err(OperationPlanError::StaleGeneration {
                planned: 0,
                current: 1,
            })
        );
    }

    #[test]
    fn authenticated_extension_preserves_state_and_rejects_cycles() {
        // Authenticated nested structures extend the original plan only after
        // its crypto gate. Existing execution and first-failure evidence stay
        // attached to the same operation, and cyclic extensions fail compile.
        let mut context = OperationExecutionContext::new((), 7_u8, None);
        let parse = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
        let crypto = context.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
        context
            .add_dependency(crypto, parse)
            .expect("valid base edge");
        context.compile().expect("base plan");
        context
            .run(parse, || Ok::<_, OperationPlanError>(()))
            .expect("parse");
        context
            .run(crypto, || Ok::<_, OperationPlanError>(()))
            .expect("crypto");

        context.extend();
        let left = context.add_node(
            OperationNodeKind::Manifest { index: 0 },
            OperationStage::AuthenticatedDependency,
            None,
        );
        let right = context.add_node(
            OperationNodeKind::Manifest { index: 1 },
            OperationStage::AuthenticatedDependency,
            None,
        );
        context.add_dependency(left, crypto).expect("crypto gate");
        context.add_dependency(right, left).expect("nested edge");
        context.add_dependency(left, right).expect("cycle edge");
        assert_eq!(context.compile(), Err(OperationPlanError::Cycle));
        assert_eq!(*context.budgets(), 7);
        assert_eq!(context.first_failure(), None);
    }

    #[test]
    fn missing_dependency_error_uses_discovery_order() {
        // Hash iteration must not choose a different first prerequisite across
        // runs, platforms, or process hash seeds.
        let mut context = OperationExecutionContext::new((), (), None);
        let first = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
        let second = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
        let crypto = context.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
        context.add_dependency(crypto, second).expect("valid edge");
        context.add_dependency(crypto, first).expect("valid edge");
        context.compile().expect("plan");
        assert_eq!(
            context.run(crypto, || Ok::<_, OperationPlanError>(())),
            Err(OperationPlanError::DependencyNotExecuted {
                node: crypto,
                requires: first,
            })
        );
    }

    #[test]
    fn stage_regression_and_repeat_execution_are_rejected() {
        let mut builder = OperationPlanBuilder::default();
        let parse = node(&mut builder, OperationStage::Parse);
        let crypto = node(&mut builder, OperationStage::Crypto);
        assert_eq!(
            builder.add_dependency(parse, crypto),
            Err(OperationPlanError::StageRegression {
                requires: OperationStage::Crypto,
                dependent: OperationStage::Parse,
            })
        );

        let mut context = OperationExecutionContext::new((), (), None);
        let only = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
        context.compile().expect("plan");
        context
            .run(only, || Ok::<_, OperationPlanError>(()))
            .expect("first execution");
        assert_eq!(
            context.run(only, || Ok::<_, OperationPlanError>(())),
            Err(OperationPlanError::AlreadyExecuted)
        );
    }

    #[test]
    fn resource_identity_is_checked_before_the_action_runs() {
        let expected = OperationResourceIdentity::external("urn:test", b"expected");
        let observed = OperationResourceIdentity::external("urn:test", b"changed");
        let mut context = OperationExecutionContext::new((), (), None);
        let node = context.add_node(
            OperationNodeKind::Digest { index: 0 },
            OperationStage::Digest,
            Some(expected),
        );
        context.compile().expect("plan");
        let ran = Cell::new(false);

        assert_eq!(
            context.run_with_resource(node, &observed, || {
                ran.set(true);
                Ok::<_, OperationPlanError>(())
            }),
            Err(OperationPlanError::StaleResourceIdentity),
        );
        assert!(!ran.get(), "stale resource identity must gate the action");
    }

    #[test]
    fn resource_bound_node_requires_an_observed_identity() {
        // A caller cannot accidentally bypass provenance validation by using the
        // generic execution entry point for a resource-bound operation node.
        let expected = OperationResourceIdentity::external("urn:test", b"expected");
        let mut context = OperationExecutionContext::new((), (), None);
        let node = context.add_node(
            OperationNodeKind::Digest { index: 0 },
            OperationStage::Digest,
            Some(expected),
        );
        context.compile().expect("plan");
        let ran = Cell::new(false);

        assert_eq!(
            context.run(node, || {
                ran.set(true);
                Ok::<_, OperationPlanError>(())
            }),
            Err(OperationPlanError::StaleResourceIdentity)
        );
        assert!(
            !ran.get(),
            "missing resource observation must gate the action"
        );
    }

    #[test]
    fn controlled_mutations_advance_the_expected_generation() {
        let mut document = XmlDocument::parse("<root/>").expect("document");
        let mut context = OperationExecutionContext::new(
            (),
            (),
            Some((document.identity(), document.generation())),
        );
        let first = context.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
        let second = context.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
        context
            .add_dependency(second, first)
            .expect("mutation order");
        context.compile().expect("plan");

        context
            .run_document_transition(first, &mut document, |document, _| {
                let root = document.with_view(|view| view.root_element());
                document
                    .replace_element(root, "<first/>")
                    .expect("first mutation");
                Ok::<_, OperationPlanError>(())
            })
            .expect("first transition");
        context
            .run_document_transition(second, &mut document, |document, _| {
                let root = document.with_view(|view| view.root_element());
                document
                    .replace_element(root, "<second/>")
                    .expect("second mutation");
                Ok::<_, OperationPlanError>(())
            })
            .expect("second transition");

        assert_eq!(document.generation(), 2);
        document
            .with_view(|view| context.validate_document_view(view))
            .expect("context must track the controlled generation");
    }
}
