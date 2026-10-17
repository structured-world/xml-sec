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

/// XMLDSig node sets over one prepared document, canonicalized after selection.
pub struct NodeSets<'a> {
    document: crate::xml::dom::Document<'a>,
}

impl<'a> NodeSets<'a> {
    /// Parse once outside measurement.
    pub fn new(input: &'a str) -> Result<Self, crate::xml::dom::ParseError> {
        Ok(Self {
            document: crate::xml::dom::Document::parse(input)?,
        })
    }

    /// `URI=""` minus the document element's last child, as an enveloped
    /// signature, then inclusive C14N. Returns the canonical length.
    pub fn enveloped(&self) -> usize {
        let mut nodes = crate::xmldsig::NodeSet::entire_document_without_comments(&self.document)
            .expect("benchmark document fits node-set limits");
        let signature = self
            .document
            .root_element()
            .last_element_child()
            .expect("benchmark document has an enveloped child");
        nodes.exclude_subtree(signature);
        self.canonicalize(&nodes)
    }

    /// Every `stride`-th element with its attribute and namespace nodes,
    /// stored as a bitset or a sorted vector, then inclusive C14N.
    pub fn selection(&self, stride: usize, dense: bool) -> usize {
        use crate::xmldsig::types::projection::{NativeKeys, Projection};
        let budget = crate::xmldsig::types::NodeSetMaterializationBudget::default();
        let mut nodes = Projection::empty(&self.document, NativeKeys);
        for element in self
            .document
            .descendants()
            .filter(|node| node.is_element())
            .step_by(stride)
        {
            nodes
                .insert_tree(element, Some(&budget))
                .expect("selection fits");
            for ordinal in 0..element.attributes().len() {
                nodes
                    .insert_attribute_at(element, ordinal, &budget)
                    .expect("selection fits");
            }
            for ordinal in 0..element.namespaces().len() {
                nodes
                    .insert_namespace_at(element, ordinal, &budget)
                    .expect("selection fits");
            }
        }
        nodes
            .force_representation(dense)
            .expect("native storage is infallible");
        self.canonicalize(&nodes)
    }

    fn canonicalize(&self, nodes: &dyn crate::c14n::NodeVisibility) -> usize {
        let algorithm = crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Inclusive1_0, false);
        let mut output = Vec::new();
        crate::c14n::canonicalize_with_visibility(
            &self.document,
            Some(nodes),
            &algorithm,
            &mut output,
        )
        .expect("benchmark canonicalization");
        output.len()
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
