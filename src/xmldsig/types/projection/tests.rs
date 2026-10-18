use super::*;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};

#[test]
fn set_algebra_reads_retained_keys_only_with_current_execution() {
    // The right-hand set may outlive an exhausted producer. Its storage
    // remains retained there; filtering, membership and insertion use the
    // left-hand current query, including attributes and namespace axes.
    use structured_asn1::{Encoding, Limits, Parser};
    let document =
        Document::parse("<root xmlns:p='urn:p'><left p:a='v'/><right/></root>").expect("fixed XML");
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let producer = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 4096,
            ..Default::default()
        },
        memory.clone(),
    );
    let producer_reader = producer.read(&[], 0).expect("empty producer input");
    let producer_work = producer_reader.execution();
    let query = Parser::new(Encoding::Der, Limits::default(), memory.clone());
    let reader = query.read(&[], 0).expect("empty query input");
    let work = reader.execution();
    let budget = NodeSetMaterializationBudget::default();
    let child = document
        .root_element()
        .first_element_child()
        .expect("left child");
    let retained = Projection::accounted_subtree(child, true, &budget, &producer_work)
        .expect("producer projection fits");
    for shift in (0..=12).rev() {
        while producer_work.charge_work(1 << shift).is_ok() {}
    }
    let mut selected = Projection::accounted_subtree(document.root(), true, &budget, &work)
        .expect("current projection fits");
    selected.intersect(&retained).expect("current intersection");
    assert!(selected.contains_tree(child).expect("current lookup"));
    assert!(
        selected
            .contains_attribute_at(child, 0)
            .expect("current attribute lookup")
    );
    assert!(
        !selected
            .contains_tree(document.root_element())
            .expect("excluded root lookup")
    );
    selected.subtract(&retained).expect("current subtraction");
    assert_eq!(selected.len(), 0);
    selected.union(&retained, &budget).expect("current union");
    assert_eq!(selected.len(), retained.len());
    selected.exclude_subtree(child).expect("current exclusion");
    assert_eq!(selected.len(), 0);
    assert!(producer_work.charge_work(1).is_err());
    drop(selected);
    drop(retained);
    assert_eq!(memory.used(), 0);
}

#[test]
fn failed_filter_is_sticky_and_cannot_be_observed_as_successful_subset() {
    // Even when a sparse-table scan refuses before its first predicate,
    // subsequent membership and serialization must retain that refusal.
    let document = Document::parse("<root><child/></root>").expect("fixed source XML");
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 4096)));
    let mut nodes = Projection::accounted_subtree(
        document.root(),
        true,
        &NodeSetMaterializationBudget::default(),
        &memory,
    )
    .expect("initial projection fits");
    memory
        .charge_work(memory.work_remaining() as u64)
        .expect("spend exactly remaining work");
    assert!(matches!(
        nodes.exclude_subtree(document.root_element()),
        Err(C14nError::SharedExecution(MemoryError::WorkExceeded))
    ));
    assert!(matches!(
        nodes.contains_tree(document.root()),
        Err(C14nError::SharedExecution(MemoryError::WorkExceeded))
    ));
    let mut output = Vec::new();
    let algorithm = crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Inclusive1_0, false);
    assert!(
        crate::c14n::canonicalize_with_visibility(&document, Some(&nodes), &algorithm, &mut output)
            .is_err()
    );
    assert!(output.is_empty());
    drop(nodes);
    assert_eq!(memory.used(), 0);
}

#[test]
fn compact_projection_matches_original_axes_and_canonical_bytes() {
    // Private axis ordinals must preserve owner-specific namespace identity
    // and subset inheritance on both storage strategies and every C14N mode.
    let document = crate::xml::dom::Document::parse(
        r#"<outer xmlns="urn:default" xmlns:p="urn:a" xml:lang="en"><child p:a="v"><!--kept--><p:leaf xmlns:p="urn:b"/></child></outer>"#,
    ).expect("fixed namespace source XML");
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    for root in [
        document.root(),
        document
            .root_element()
            .first_element_child()
            .expect("fixed child subtree"),
    ] {
        let budget = super::super::NodeSetMaterializationBudget::default();
        let original = super::super::NodeSet::subtree(root).expect("collecting projection");
        let native =
            Projection::subtree(root, true, &budget, NativeKeys).expect("native projection");
        let paid =
            Projection::accounted_subtree(root, true, &budget, &memory).expect("paid projection");
        assert!(paid.with_comments());
        assert!(std::ptr::eq(paid.document(), &document));
        for mode in [
            crate::c14n::C14nMode::Inclusive1_0,
            crate::c14n::C14nMode::Inclusive1_1,
            crate::c14n::C14nMode::Exclusive1_0,
        ] {
            for comments in [false, true] {
                let algorithm = crate::c14n::C14nAlgorithm::new(mode, comments);
                let mut expected = Vec::new();
                crate::c14n::canonicalize_with_visibility(
                    &document,
                    Some(&original),
                    &algorithm,
                    &mut expected,
                )
                .expect("collecting canonical output");
                for visibility in [&native as &dyn NodeVisibility, &paid] {
                    let mut actual = Vec::new();
                    crate::c14n::canonicalize_with_visibility(
                        &document,
                        Some(visibility),
                        &algorithm,
                        &mut actual,
                    )
                    .expect("storage-specialized canonical output");
                    assert_eq!(actual, expected);
                }
            }
        }
    }
    assert_eq!(memory.used(), 0);
}

#[test]
fn inserting_present_members_keeps_semantic_projection_unmaterialized() {
    // A Filter 2.0 union into the whole document adds nothing; it must not
    // copy the semantic projection into explicit storage, which an account
    // too small for one index per XPath node would refuse.
    let xml = format!("<root>{}</root>", "<a p='v'/>".repeat(16 * 1024));
    let document = crate::xml::dom::Document::parse(&xml).expect("fixed wide source XML");
    let budget = super::super::NodeSetMaterializationBudget::default();
    let small = Memory::new(Arc::new(MemoryAccount::new(1024, 1 << 24)));
    let mut whole = Projection::accounted_subtree(document.root(), true, &budget, &small)
        .expect("a semantic projection allocates no node storage");
    let entries = whole.len();
    let child = document
        .root_element()
        .first_element_child()
        .expect("first child");
    let part = Projection::accounted_subtree(child, true, &budget, &small)
        .expect("a semantic child projection allocates no node storage");
    whole
        .union(&part, &budget)
        .expect("a union of present members needs no storage");
    whole
        .insert_tree(document.root_element(), Some(&budget))
        .expect("a present tree node needs no storage");
    whole
        .insert_attribute_at(child, 0, &budget)
        .expect("a present attribute needs no storage");
    assert_eq!(whole.len(), entries);
    assert_eq!(small.used(), 0);
}

#[test]
fn semantic_members_pay_work_for_every_emitted_index() {
    // Attribute and namespace nodes of one element are emitted individually
    // when a semantic projection becomes explicit; each costs execution work.
    let attributes = (0..4096)
        .map(|index| format!(" a{index}='v'"))
        .collect::<String>();
    let xml = format!("<root{attributes}/>");
    let document = crate::xml::dom::Document::parse(&xml).expect("fixed wide element");
    let budget = super::super::NodeSetMaterializationBudget::default();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let mut whole = Projection::accounted_subtree(document.root(), true, &budget, &memory)
        .expect("semantic projection fits");
    let before = memory.work_remaining();
    whole.materialize().expect("explicit copy fits");
    let spent = before - memory.work_remaining();
    assert!(
        spent >= whole.len(),
        "materializing {} members spent {spent} work units",
        whole.len()
    );
    drop(whole);
    assert_eq!(memory.used(), 0);
}

#[test]
fn semantic_projection_stores_no_nodes_and_explicit_sets_pay_capacity() {
    // A whole-document projection is an arena range: it needs no per-node
    // storage even in an account too small for one index per XPath node. An
    // explicit copy pays its actual capacity, is refused by the small account
    // and releases everything on failure and on drop.
    let xml = format!("<root>{}</root>", "<a p='v'/>".repeat(16 * 1024));
    let document = crate::xml::dom::Document::parse(&xml).expect("fixed wide source XML");
    let budget = super::super::NodeSetMaterializationBudget::default();
    let small = Memory::new(Arc::new(MemoryAccount::new(1024, 1 << 24)));
    let whole = Projection::accounted_subtree(document.root(), true, &budget, &small)
        .expect("a semantic projection allocates no node storage");
    assert_eq!(small.used(), 0);
    let mut refused = Projection::empty(&document, PaidKeys::new(&small));
    assert!(refused.union(&whole, &budget).is_err());
    drop(refused);
    assert_eq!(small.used(), 0);
    let large = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let mut explicit = Projection::empty(&document, PaidKeys::new(&large));
    explicit
        .union(&whole, &budget)
        .expect("larger account admits the explicit copy");
    assert!(large.used() > 1024);
    assert_eq!(explicit.len(), whole.len());
    assert!(
        explicit
            .contains_tree(document.root_element())
            .expect("admitted membership lookup")
    );
    drop(explicit);
    drop(whole);
    assert_eq!(large.used(), 0);
}

/// The previous representation: one hashed key per tree, attribute and
/// namespace node, with the same comment-flag rules.
#[derive(Default)]
struct Reference {
    keys: std::collections::HashSet<(u8, u32, usize)>,
    with_comments: bool,
}

const TREE: u8 = 0;
const ATTRIBUTE: u8 = 1;
const NAMESPACE: u8 = 2;

impl Reference {
    fn subtree(root: Node<'_, '_>, comments: bool) -> Self {
        let mut reference = Self {
            with_comments: comments,
            ..Self::default()
        };
        for node in root.descendants() {
            if node.is_comment() && !comments {
                continue;
            }
            reference.keys.insert((TREE, node.id().get(), 0));
            for ordinal in 0..node.attributes().len() {
                reference.keys.insert((ATTRIBUTE, node.id().get(), ordinal));
            }
            for ordinal in 0..node.namespaces().len() {
                reference.keys.insert((NAMESPACE, node.id().get(), ordinal));
            }
        }
        reference
    }
    fn insert_tree(&mut self, node: Node<'_, '_>) {
        self.keys.insert((TREE, node.id().get(), 0));
        self.with_comments |= node.is_comment();
    }
    fn exclude_subtree(&mut self, node: Node<'_, '_>) {
        let range = subtree_ids(node);
        self.keys.retain(|key| !range.contains(&key.1));
    }
    fn intersect(&mut self, other: &Self) {
        self.keys.retain(|key| other.keys.contains(key));
        self.with_comments &= other.with_comments;
    }
    fn subtract(&mut self, other: &Self) {
        self.keys.retain(|key| !other.keys.contains(key));
    }
    fn union(&mut self, other: &Self) {
        self.keys.extend(other.keys.iter().copied());
        self.with_comments |= other.with_comments;
    }
}

impl NodeVisibility for Reference {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, C14nError> {
        Ok(self.keys.contains(&(TREE, node.id().get(), 0)))
    }
    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local: &str,
    ) -> Result<bool, C14nError> {
        Ok(owner
            .attributes()
            .position(|attribute| attribute.name() == local && attribute.namespace() == namespace)
            .is_some_and(|ordinal| self.keys.contains(&(ATTRIBUTE, owner.id().get(), ordinal))))
    }
    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        prefix: &str,
        uri: &str,
    ) -> Result<bool, C14nError> {
        Ok(owner
            .namespaces()
            .position(|namespace| {
                namespace.name().unwrap_or("") == prefix && namespace.uri() == uri
            })
            .is_some_and(|ordinal| self.keys.contains(&(NAMESPACE, owner.id().get(), ordinal))))
    }
    fn contains_attribute_at(
        &self,
        owner: Node<'_, '_>,
        ordinal: usize,
        _: crate::xml::dom::Attribute<'_>,
    ) -> Result<bool, C14nError> {
        Ok(self.keys.contains(&(ATTRIBUTE, owner.id().get(), ordinal)))
    }
    fn contains_namespace_at(
        &self,
        owner: Node<'_, '_>,
        ordinal: usize,
        _: crate::xml::dom::Namespace<'_>,
    ) -> Result<bool, C14nError> {
        Ok(self.keys.contains(&(NAMESPACE, owner.id().get(), ordinal)))
    }
}

/// Deterministic SplitMix64 test generator; reproducible from the printed seed.
struct Choices(u64);
impl Choices {
    fn below(&mut self, bound: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^= mixed >> 31;
        (mixed % bound as u64) as usize
    }
}

fn random_pair<'a, K: Keys>(
    document: &'a Document<'a>,
    nodes: &[Node<'a, 'a>],
    keys: &impl Fn() -> K,
    budget: &NodeSetMaterializationBudget,
    choices: &mut Choices,
) -> (Projection<'a, K>, Reference) {
    if choices.below(3) == 0 {
        let root = nodes[choices.below(nodes.len())];
        let comments = choices.below(2) == 0;
        return (
            Projection::subtree(root, comments, budget, keys()).expect("subtree fits"),
            Reference::subtree(root, comments),
        );
    }
    let mut projection = Projection::empty(document, keys());
    let mut reference = Reference::default();
    // Selections range from a few nodes, kept sparse, to most of the
    // document, inserted out of order to exercise promotion to a bitset.
    let count = match choices.below(3) {
        0 => choices.below(8),
        1 => choices.below(nodes.len()),
        _ => nodes.len() * 4,
    };
    for _ in 0..count {
        let node = nodes[choices.below(nodes.len())];
        match choices.below(3) {
            0 => {
                projection
                    .insert_tree(node, Some(budget))
                    .expect("tree insertion fits");
                reference.insert_tree(node);
            }
            1 if node.attributes().len() > 0 => {
                let ordinal = choices.below(node.attributes().len());
                projection
                    .insert_attribute_at(node, ordinal, budget)
                    .expect("attribute insertion fits");
                reference.keys.insert((ATTRIBUTE, node.id().get(), ordinal));
            }
            2 if node.namespaces().len() > 0 => {
                let ordinal = choices.below(node.namespaces().len());
                projection
                    .insert_namespace_at(node, ordinal, budget)
                    .expect("namespace insertion fits");
                reference.keys.insert((NAMESPACE, node.id().get(), ordinal));
            }
            _ => {}
        }
    }
    (projection, reference)
}

fn assert_same_members<K: Keys>(
    projection: &Projection<'_, K>,
    reference: &Reference,
    nodes: &[Node<'_, '_>],
    context: &str,
) {
    assert_eq!(projection.len(), reference.keys.len(), "{context}: length");
    assert_eq!(
        projection.with_comments(),
        reference.with_comments,
        "{context}: comment flag"
    );
    for &node in nodes {
        let id = node.id().get();
        assert_eq!(
            projection.contains_tree(node).expect("tree lookup"),
            reference.keys.contains(&(TREE, id, 0)),
            "{context}: tree node {id}"
        );
        for ordinal in 0..node.attributes().len() {
            assert_eq!(
                projection
                    .contains_attribute_at(node, ordinal)
                    .expect("attribute lookup"),
                reference.keys.contains(&(ATTRIBUTE, id, ordinal)),
                "{context}: attribute {ordinal} of node {id}"
            );
        }
        for ordinal in 0..node.namespaces().len() {
            assert_eq!(
                projection
                    .contains_namespace_at(node, ordinal)
                    .expect("namespace lookup"),
                reference.keys.contains(&(NAMESPACE, id, ordinal)),
                "{context}: namespace {ordinal} of node {id}"
            );
        }
    }
}

fn randomized_algebra<K: Keys>(
    document: &Document<'_>,
    keys: impl Fn() -> K,
    seed: u64,
    seen: &mut std::collections::BTreeSet<&'static str>,
) {
    let nodes: Vec<_> = document.descendants().collect();
    let budget = NodeSetMaterializationBudget::default();
    let mut choices = Choices(seed);
    let (mut projection, mut reference) =
        random_pair(document, &nodes, &keys, &budget, &mut choices);
    for step in 0..12 {
        seen.insert(projection.representation());
        let context = format!("seed {seed}, step {step}");
        match choices.below(5) {
            0 => {
                let node = nodes[choices.below(nodes.len())];
                projection.exclude_subtree(node).expect("exclusion");
                reference.exclude_subtree(node);
            }
            1 => {
                let (other, other_reference) =
                    random_pair(document, &nodes, &keys, &budget, &mut choices);
                projection.intersect(&other).expect("intersection");
                reference.intersect(&other_reference);
            }
            2 => {
                let (other, other_reference) =
                    random_pair(document, &nodes, &keys, &budget, &mut choices);
                projection.subtract(&other).expect("subtraction");
                reference.subtract(&other_reference);
            }
            3 => {
                let (other, other_reference) =
                    random_pair(document, &nodes, &keys, &budget, &mut choices);
                projection.union(&other, &budget).expect("union");
                reference.union(&other_reference);
            }
            _ => {
                let node = nodes[choices.below(nodes.len())];
                projection
                    .insert_tree(node, Some(&budget))
                    .expect("tree insertion");
                reference.insert_tree(node);
            }
        }
        assert_same_members(&projection, &reference, &nodes, &context);
    }
    for mode in [
        crate::c14n::C14nMode::Inclusive1_0,
        crate::c14n::C14nMode::Inclusive1_1,
        crate::c14n::C14nMode::Exclusive1_0,
    ] {
        for comments in [false, true] {
            let algorithm = crate::c14n::C14nAlgorithm::new(mode, comments);
            let mut expected = Vec::new();
            crate::c14n::canonicalize_with_visibility(
                document,
                Some(&reference),
                &algorithm,
                &mut expected,
            )
            .expect("reference canonical output");
            let mut actual = Vec::new();
            crate::c14n::canonicalize_with_visibility(
                document,
                Some(&projection),
                &algorithm,
                &mut actual,
            )
            .expect("projection canonical output");
            assert_eq!(
                actual, expected,
                "seed {seed}: {mode:?} comments={comments}"
            );
        }
    }
}

fn algebra_documents() -> Vec<String> {
    let wide = (0..300)
        .map(|index| {
            let child = if index % 7 == 0 { "<!--x-->" } else { "t" };
            format!("<e i='{index}' n:j='{index}'>{child}</e>")
        })
        .collect::<String>();
    vec![
        r#"<outer xmlns="urn:default" xmlns:p="urn:a" xml:lang="en"><child p:a="v" b="w"><!--c1--><p:leaf xmlns:p="urn:b" p:x="1"/><?pi data?>text</child><!--c2--><other xmlns="" q="2"/></outer>"#.to_owned(),
        "<!--head--><?top x?><r a='1'><s><t/></s><!--tail--></r><!--after-->".to_owned(),
        format!("<w xmlns:n='urn:n'>{wide}</w>"),
    ]
}

#[test]
fn randomized_set_algebra_matches_previous_representation_and_c14n() {
    // Semantic ranges, sparse vectors and bitsets must agree with the former
    // one-key-per-node table for every tree, attribute and namespace node,
    // through exclusion, intersection, subtraction, union and insertion, and
    // must canonicalize to identical bytes in every mode.
    let mut seen = std::collections::BTreeSet::new();
    for xml in algebra_documents() {
        let document = Document::parse(&xml).expect("fixed algebra source XML");
        for seed in 0..64 {
            randomized_algebra(&document, NativeKeys::default, seed, &mut seen);
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        ["dense", "sparse", "subtree"],
        "every representation is exercised"
    );
}

#[test]
fn randomized_paid_set_algebra_matches_and_releases_storage() {
    // The accounted storage strategy follows the same representation rules and
    // returns every index vector and bitset to its account.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 40)));
    for xml in algebra_documents() {
        let document = Document::parse(&xml).expect("fixed algebra source XML");
        for seed in 0..16 {
            randomized_algebra(
                &document,
                || PaidKeys::new(&memory),
                seed,
                &mut Default::default(),
            );
            assert_eq!(memory.used(), 0, "seed {seed}");
        }
    }
}
