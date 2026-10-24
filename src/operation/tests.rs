use super::*;

// A free function keeps the scoped document lifetime late-bound.
fn document_root(view: DocumentView<'_>) -> crate::NodeIdentity {
    view.root_element()
}

#[cfg(feature = "xmlenc")]
#[test]
fn discovered_resources_gate_work_and_join_the_original_graph() {
    // Resources discovered by metadata parsing retain the same budget and
    // evidence owner. No resource action runs before document completion.
    let mut context = OperationExecutionContext::new((), 7_u8, None);
    let document = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
    let cipher = context.add_node(OperationNodeKind::Ciphertext, OperationStage::Resolve, None);
    context
        .add_dependency(cipher, document)
        .expect("document dependency");
    context.compile().expect("base plan");
    let identity =
        OperationResourceIdentity::external("https://example.test/cipher", b"cipher bytes");
    let called = Cell::new(0);
    let action = || {
        called.set(called.get() + 1);
        Ok::<_, OperationPlanError>(())
    };
    assert!(matches!(
        context.run_discovered_resource(document, cipher, &identity, action),
        Err(OperationPlanError::DependencyNotExecuted { .. })
    ));
    assert_eq!(called.get(), 0);
    context
        .run(document, || Ok::<_, OperationPlanError>(()))
        .expect("document");
    context
        .run(cipher, || {
            context.run_discovered_resource(document, cipher, &identity, action)
        })
        .expect("resource inside ciphertext gate");
    assert_eq!(called.get(), 1);
    assert_eq!(*context.budgets(), 7);
    assert_eq!(
        context
            .decisions
            .borrow()
            .iter()
            .filter(|decision| decision.resource.as_ref() == Some(&identity) && decision.accepted)
            .count(),
        1
    );
    assert_eq!(
        context.run_discovered_resource(document, cipher, &identity, action),
        Err(OperationPlanError::AlreadyExecuted)
    );
    assert_eq!(called.get(), 1);
}

#[cfg(feature = "xmlenc")]
#[test]
fn failed_discovered_resource_prevents_consumer_completion() {
    // A failed scoped action cannot be hidden by returning success from
    // the enclosing closure; its dynamic dependency remains incomplete.
    let mut context = OperationExecutionContext::new((), (), None);
    let document = context.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
    let cipher = context.add_node(OperationNodeKind::Ciphertext, OperationStage::Resolve, None);
    context
        .add_dependency(cipher, document)
        .expect("document dependency");
    context.compile().expect("plan");
    context
        .run(document, || Ok::<_, OperationPlanError>(()))
        .expect("document");
    let identity = OperationResourceIdentity::external("resource", b"bytes");
    let result = context.run(cipher, || {
        assert_eq!(
            context.run_discovered_resource(document, cipher, &identity, || Err::<(), _>(
                OperationPlanError::StaleResourceIdentity
            )),
            Err(OperationPlanError::StaleResourceIdentity)
        );
        Ok::<_, OperationPlanError>(())
    });
    assert!(matches!(
        result,
        Err(OperationPlanError::DependencyNotExecuted { .. })
    ));
    assert!(!context.is_executed(cipher));
    assert!(context.first_failure.borrow().is_some());
}

#[cfg(feature = "xmlenc")]
#[test]
fn xml_encryption_operation_retains_its_policy_snapshot() {
    let context = OperationExecutionContext::new("xmlenc-policy", (), None);

    assert_eq!(*context.policy(), "xmlenc-policy");
}

fn node(builder: &mut OperationPlanBuilder, stage: OperationStage) -> OperationNodeId {
    builder.add_node(OperationNodeKind::Document, stage, None)
}

#[cfg(feature = "xmldsig")]
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

#[cfg(feature = "xmldsig")]
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
    *context.plan.get_mut() = Some(plan);
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
    let mut context =
        OperationExecutionContext::new((), (), Some((document.identity(), document.generation())));
    context.builder = None;
    *context.plan.get_mut() = Some(plan);
    let target = document.with_view(document_root);
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

#[cfg(feature = "xmldsig")]
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

#[cfg(feature = "xmldsig")]
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

#[cfg(feature = "xmldsig")]
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
    let mut context =
        OperationExecutionContext::new((), (), Some((document.identity(), document.generation())));
    let first = context.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
    let second = context.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
    context
        .add_dependency(second, first)
        .expect("mutation order");
    context.compile().expect("plan");

    context
        .run_document_transition(first, &mut document, |document, ()| {
            let root = document.with_view(document_root);
            document
                .replace_element(root, "<first/>")
                .expect("first mutation");
            Ok::<_, OperationPlanError>(())
        })
        .expect("first transition");
    context
        .run_document_transition(second, &mut document, |document, ()| {
            let root = document.with_view(document_root);
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
