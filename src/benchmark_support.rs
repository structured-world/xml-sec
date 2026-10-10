//! Opt-in measurement hooks. Not a stable application API.
//!
//! These use the production implementations without disabling security checks.

use crate::operation::{
    OperationExecutionContext, OperationNodeId, OperationNodeKind, OperationPlanError,
    OperationStage,
};

/// A pre-parsed backend tree; construction is excluded from projection timing.
pub struct Projection<'a>(crate::xml::dom::benchmark::Projection<'a>);

impl<'a> Projection<'a> {
    /// Prepare lexical positions and one backend DOM outside measurement.
    pub fn new(
        input: &'a str,
        backend: crate::XmlBackend,
    ) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self(crate::xml::dom::benchmark::Projection::new(
            input, backend,
        )?))
    }

    /// Build the real normalized arena, retaining it until the caller drops it.
    pub fn project(&self) -> Result<crate::xml::dom::Document<'a>, crate::xml::dom::ParseError> {
        self.0.project()
    }
}

/// A dependency fan-out representative of reference digest admission.
pub struct Plan {
    context: OperationExecutionContext<(), ()>,
    order: Vec<OperationNodeId>,
}

impl Plan {
    /// Build a document -> parallel references -> crypto -> evidence graph.
    pub fn new(references: usize) -> Self {
        assert!((1..=64).contains(&references), "bounded benchmark graph");
        let mut context = OperationExecutionContext::new((), (), None);
        let root = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
        let mut order = vec![root];
        for index in 0..references {
            let node = context.add_node(
                OperationNodeKind::Digest { index },
                OperationStage::Digest,
                None,
            );
            context
                .add_dependency(node, root)
                .expect("forward dependency");
            order.push(node);
        }
        let crypto = context.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
        for &node in &order[1..] {
            context
                .add_dependency(crypto, node)
                .expect("forward dependency");
        }
        order.push(crypto);
        let evidence =
            context.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
        context
            .add_dependency(evidence, crypto)
            .expect("forward dependency");
        order.push(evidence);
        Self { context, order }
    }

    /// Compile only: builder construction is excluded by the benchmark setup.
    pub fn compile(&mut self) {
        self.context.compile().expect("valid benchmark plan");
    }

    /// Execute admission, completion and decision recording, without crypto work.
    pub fn execute(&self) {
        for &node in &self.order {
            self.context
                .run(node, || Ok::<_, OperationPlanError>(()))
                .expect("dependency order");
        }
    }
}
