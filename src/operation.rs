//! Shared compilation and execution state for one XML Security operation.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
};

use crate::{DocumentIdentity, DocumentView, NodeIdentity, XmlDocument, XmlDocumentError};

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
    DependencyGraph,
    Transform,
    Digest,
    Crypto,
    AuthenticatedDependency,
    Evidence,
    Mutation,
}

/// Semantic role of a node in a compiled operation plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OperationNodeKind {
    Document,
    Reference { index: usize, manifest: bool },
    Manifest { index: usize },
    Key { index: usize },
    Transform { index: usize },
    Digest { index: usize },
    Crypto,
    Evidence,
    Mutation,
}

/// Identity whose provenance must remain stable for the complete operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OperationResourceIdentity {
    DocumentNode(NodeIdentity),
    External(String),
    Generated(&'static str, usize),
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
            order,
        })
    }
}

/// Immutable, validated dependency plan.
#[derive(Debug)]
pub(crate) struct CompiledOperationPlan {
    nodes: Vec<OperationNode>,
    edges: HashSet<OperationEdge>,
    order: Vec<OperationNodeId>,
}

impl CompiledOperationPlan {
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

/// Typed internal record used to preserve deterministic first-failure state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationDecision {
    pub(crate) node: OperationNodeId,
    pub(crate) accepted: bool,
    pub(crate) reason: &'static str,
}

/// Single owner of immutable policy, cumulative budgets, identity state and
/// execution evidence for one operation.
pub(crate) struct OperationExecutionContext<P, B> {
    policy: P,
    budgets: B,
    builder: Option<OperationPlanBuilder>,
    plan: Option<CompiledOperationPlan>,
    document: Option<(DocumentIdentity, u64)>,
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
            document,
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

    pub(crate) fn validate_document(
        &self,
        document: &XmlDocument,
    ) -> Result<(), OperationPlanError> {
        let Some((identity, generation)) = self.document else {
            return Ok(());
        };
        if document.identity() != identity {
            return Err(OperationPlanError::ForeignDocument);
        }
        if document.generation() != generation {
            return Err(OperationPlanError::StaleGeneration {
                planned: generation,
                current: document.generation(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_document_view(
        &self,
        view: DocumentView<'_>,
    ) -> Result<(), OperationPlanError> {
        let Some((identity, generation)) = self.document else {
            return Ok(());
        };
        if view.identity() != identity {
            return Err(OperationPlanError::ForeignDocument);
        }
        if view.generation() != generation {
            return Err(OperationPlanError::StaleGeneration {
                planned: generation,
                current: view.generation(),
            });
        }
        Ok(())
    }

    pub(crate) fn execute(&self, node: OperationNodeId) -> Result<(), OperationPlanError> {
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
        let _resource_identity = self.plan().resource(node);
        self.executed.borrow_mut().insert(node);
        Ok(())
    }

    pub(crate) fn authenticate(&self, node: NodeIdentity) {
        self.authenticated_nodes.borrow_mut().insert(node);
    }

    pub(crate) fn is_authenticated(&self, node: NodeIdentity) -> bool {
        self.authenticated_nodes.borrow().contains(&node)
    }

    pub(crate) fn record(&self, node: OperationNodeId, accepted: bool, reason: &'static str) {
        let decision = OperationDecision {
            node,
            accepted,
            reason,
        };
        if !accepted && self.first_failure.borrow().is_none() {
            *self.first_failure.borrow_mut() = Some(decision.clone());
        }
        self.decisions.borrow_mut().push(decision);
    }

    pub(crate) fn first_failure(&self) -> Option<OperationDecision> {
        self.first_failure.borrow().clone()
    }
}

impl From<OperationPlanError> for XmlDocumentError {
    fn from(error: OperationPlanError) -> Self {
        Self::InvalidReplacement(error.to_string())
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
        assert_eq!(
            context.execute(crypto),
            Err(OperationPlanError::DependencyNotExecuted {
                node: crypto,
                requires: parse,
            })
        );
        context.record(parse, false, "parse");
        context.record(crypto, false, "crypto");
        assert_eq!(
            context.first_failure().map(|item| item.reason),
            Some("parse")
        );
    }

    #[test]
    fn document_generation_binding_rejects_stale_plans() {
        // Mutation invalidates every plan compiled against the prior document
        // generation, preventing stale resolver or transform-cache reuse.
        let mut document = XmlDocument::parse("<root><value/></root>").expect("document");
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
            context.validate_document(&document),
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
        context.execute(parse).expect("parse");
        context.execute(crypto).expect("crypto");
        context.record(crypto, true, "authenticated");

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
            context.execute(crypto),
            Err(OperationPlanError::DependencyNotExecuted {
                node: crypto,
                requires: first,
            })
        );
    }
}
