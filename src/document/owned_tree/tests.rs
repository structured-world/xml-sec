use alloc::boxed::Box;
use alloc::vec::Vec;

use super::*;
use crate::document::XmlDocument;
use crate::policy::{PolicyViolation, VerificationPolicy, resource_name};

fn parsed(xml: &str) -> OwnedTree {
    OwnedTree::parse_with_policy(xml, &VerificationPolicy::default()).expect("the document parses")
}

fn children(tree: &OwnedTree, node: TreeNode) -> Vec<TreeNode> {
    let mut found = Vec::new();
    let mut current = tree.first_child(node).expect("a live node");
    while let Some(child) = current {
        found.push(child);
        current = tree.next_sibling(child).expect("a live node");
    }
    found
}

#[test]
fn a_parse_reads_names_namespaces_attributes_and_text() {
    let tree = parsed(r#"<a:r xmlns:a="urn:a" id="1"><c>t</c><!--x--></a:r>"#);
    let root = tree.root_element().expect("a document element");
    assert_eq!(tree.kind(root), Ok(TreeNodeKind::Element));
    assert_eq!(tree.name(root), Ok(Some("r")));
    assert_eq!(tree.prefix(root), Ok(Some("a")));
    assert_eq!(tree.namespace(root), Ok(Some("urn:a")));
    assert_eq!(tree.attribute(root, "id", None), Ok(Some("1")));
    let declarations: Vec<_> = tree
        .namespace_declarations(root)
        .expect("a live node")
        .collect();
    assert_eq!(
        declarations,
        [TreeNamespace {
            prefix: Some("a"),
            uri: "urn:a"
        }]
    );
    let kids = children(&tree, root);
    assert_eq!(kids.len(), 2);
    assert_eq!(tree.text_content(kids[0]), Ok(String::from("t")));
    assert_eq!(tree.kind(kids[1]), Ok(TreeNodeKind::Comment));
    assert_eq!(tree.parent(kids[0]), Ok(Some(root)));
}

#[test]
fn the_parse_refuses_a_document_over_the_node_limit_as_the_policy_violation() {
    // Root, r, c, d: four nodes. The limit is enforced while the parser reads.
    let xml = "<r><c/><d/></r>";
    let mut policy = VerificationPolicy::default();
    policy.resources.max_xml_nodes = 4;
    assert!(OwnedTree::parse_with_policy(xml, &policy).is_ok());
    policy.resources.max_xml_nodes = 3;
    assert!(matches!(
        OwnedTree::parse_with_policy(xml, &policy),
        Err(XmlDocumentError::Policy(PolicyViolation::ResourceLimit {
            resource: resource_name::XML_NODES,
            maximum: 3,
            ..
        }))
    ));
}

#[test]
fn a_document_type_declaration_is_refused_unless_the_policy_allows_it() {
    assert!(matches!(
        OwnedTree::parse_with_policy("<!DOCTYPE r><r/>", &VerificationPolicy::default()),
        Err(XmlDocumentError::Parse(ParseError::DtdDetected) | XmlDocumentError::Policy(_))
    ));
}

#[test]
fn created_nodes_link_and_a_freed_node_is_refused_afterwards() {
    let mut tree = parsed("<r/>");
    let root = tree.root_element().expect("a document element");
    let child = tree
        .create_element("c", Some("p"), Some("urn:p"))
        .expect("a valid name");
    tree.declare_namespace(child, Some("p"), "urn:p")
        .expect("an element");
    tree.set_attribute(child, "a", None, None, "v")
        .expect("an element");
    let text = tree.create_text("t").expect("valid text");
    tree.append_child(child, text).expect("both live");
    tree.append_child(root, child).expect("both live");
    assert_eq!(children(&tree, root), [child]);
    assert_eq!(tree.text_content(root), Ok(String::from("t")));
    // A linked node cannot be linked again.
    assert_eq!(
        tree.append_child(root, child),
        Err(TreeError::AlreadyLinked)
    );
    tree.free(child).expect("a live node");
    assert!(!tree.contains(child));
    assert!(!tree.contains(text), "the subtree is freed with it");
    assert_eq!(tree.name(child), Err(TreeError::StaleNode));
    assert_eq!(children(&tree, root), [] as [TreeNode; 0]);
}

#[test]
fn a_link_that_would_make_a_node_its_own_ancestor_is_refused() {
    let mut tree = parsed("<r><c/></r>");
    let root = tree.root_element().expect("a document element");
    let child = children(&tree, root)[0];
    tree.unlink(root).expect("a live node");
    assert_eq!(tree.append_child(child, root), Err(TreeError::Cycle));
    assert_eq!(
        tree.unlink(tree.document_node()),
        Err(TreeError::DocumentNode)
    );
}

#[test]
fn a_number_that_names_no_node_is_stale() {
    let tree = parsed("<r/>");
    let beyond = TreeNode::new(10_000).expect("not zero");
    assert_eq!(tree.kind(beyond), Err(TreeError::StaleNode));
    assert_eq!(TreeNode::new(0), None);
}

#[test]
fn an_xml_id_is_registered_by_the_parse() {
    // xml:id 1.0 section 4: an xml:id attribute is an ID without any
    // declaration, so the tree's ID table names its element.
    let tree = parsed(r#"<r><c xml:id="k"/><d id="other"/></r>"#);
    let element = tree.element_by_id("k").expect("the xml:id is registered");
    assert_eq!(tree.name(element), Ok(Some("c")));
    assert_eq!(tree.element_by_id("other"), None, "an undeclared id is not");
}

#[test]
fn set_text_replaces_an_elements_children_and_frees_them() {
    let mut tree = parsed("<r><c/>x</r>");
    let root = tree.root_element().expect("a document element");
    let old = children(&tree, root);
    tree.set_text(root, "new").expect("a live element");
    assert_eq!(tree.text_content(root), Ok(String::from("new")));
    assert!(old.iter().all(|node| !tree.contains(*node)));
}

#[test]
fn the_serialization_reflects_edits() {
    let mut tree = parsed("<r/>");
    let root = tree.root_element().expect("a document element");
    let child = tree.create_element("c", None, None).expect("a valid name");
    tree.set_attribute(child, "a", None, None, "1&2")
        .expect("an element");
    tree.append_child(root, child).expect("both live");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r><c a=\"1&amp;2\"/></r>\n"
    );
}

#[test]
fn a_tree_lent_to_a_document_comes_back_with_its_nodes() {
    // A caller lends its tree to a document for an operation and takes it
    // back; the nodes it held still name the same nodes.
    let tree = parsed("<r><c/></r>");
    let root = tree.root_element().expect("a document element");
    let document = XmlDocument::from_external_tree(Box::new(tree), &VerificationPolicy::default())
        .expect("the tree projects");
    let tree = document.into_owned_tree().expect("the lent tree");
    assert_eq!(tree.name(root), Ok(Some("r")));
}

#[test]
fn freeing_a_node_releases_the_payload_of_its_subtree() {
    // Freed numbers stay refused, but a long-lived document must not keep
    // the text and attributes of every node it ever freed.
    let mut tree = parsed(r#"<r><c a="value">text</c></r>"#);
    let root = tree.root_element().expect("a document element");
    let child = children(&tree, root)[0];
    let text = children(&tree, child)[0];
    tree.free(child).expect("a live node");
    for node in [child, text] {
        let kind = &tree.document.node(node.id().expect("not zero")).kind;
        assert!(
            matches!(kind, NodeKind::Text { content } if content.capacity() == 0),
            "{kind:?}"
        );
    }
}

#[test]
fn entity_replacement_markup_projects_as_markup() {
    // XML 1.0 section 4.4.2: markup in an entity's replacement text is
    // recognized as markup, so `&e;` is the element `b`, not the text "<b>".
    let mut policy = VerificationPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let xml = r#"<!DOCTYPE r [<!ENTITY e "<b>hi</b>">]><r>&e;</r>"#;
    let tree = OwnedTree::parse_with_policy(xml, &policy).expect("the document parses");
    let document =
        XmlDocument::from_external_tree(Box::new(tree), &policy).expect("the tree projects");
    let parsed = XmlDocument::parse_with_policy(xml, &policy).expect("the text parses");
    let shape = |document: &XmlDocument| {
        document.with_view(|view| {
            let root = view.document().root_element();
            let child = root.first_element_child().map(|child| {
                (
                    String::from(child.tag_name().name()),
                    child.text().map(String::from),
                )
            });
            (child, root.text().map(String::from))
        })
    };
    assert_eq!(
        shape(&document),
        (Some((String::from("b"), Some(String::from("hi")))), None)
    );
    assert_eq!(shape(&document), shape(&parsed));
}

#[test]
fn an_xml_id_value_is_normalized_before_it_is_registered() {
    // xml:id 1.0 section 4: the value is normalized as an ID before it is
    // assigned, and the attribute holds the normalized value.
    let tree = parsed(r#"<r xml:id="  target   value "/>"#);
    let root = tree.root_element().expect("a document element");
    assert_eq!(tree.element_by_id("target value"), Some(root));
    assert_eq!(
        tree.attribute(root, "id", Some(XML_NAMESPACE)),
        Ok(Some("target value"))
    );
}

#[test]
fn setting_or_removing_an_xml_id_keeps_the_id_table_in_step() {
    // The table follows the attribute: a changed xml:id answers under its
    // new value only, a new one is registered, a removed one is gone.
    let mut tree = parsed(r#"<r xml:id="old"><c/></r>"#);
    let root = tree.root_element().expect("a document element");
    let child = children(&tree, root)[0];
    tree.set_attribute(root, "id", Some("xml"), Some(XML_NAMESPACE), " new ")
        .expect("an element");
    assert_eq!(tree.element_by_id("old"), None);
    assert_eq!(tree.element_by_id("new"), Some(root));
    tree.set_attribute(child, "id", Some("xml"), Some(XML_NAMESPACE), "kid")
        .expect("an element");
    assert_eq!(tree.element_by_id("kid"), Some(child));
    tree.remove_attribute(child, "id", Some(XML_NAMESPACE))
        .expect("an element");
    assert_eq!(tree.element_by_id("kid"), None);
}

#[test]
fn a_registered_id_follows_its_attribute() {
    // An ID registered for an attribute answers under the attribute's
    // current value: a changed value moves it, a removed attribute ends it.
    let mut tree = parsed(r#"<r token="old"/>"#);
    let root = tree.root_element().expect("a document element");
    tree.register_id(root, "token", None, "old")
        .expect("a fresh ID");
    tree.set_attribute(root, "token", None, None, "new")
        .expect("an element");
    assert_eq!(tree.element_by_id("old"), None);
    assert_eq!(tree.element_by_id("new"), Some(root));
    tree.remove_attribute(root, "token", None)
        .expect("an element");
    assert_eq!(tree.element_by_id("new"), None);
}

#[test]
fn a_second_registration_of_a_held_id_is_refused() {
    // As libxml2's xmlAddID: an ID a live element holds is not taken over,
    // and the first element keeps it.
    let mut tree = parsed(r#"<r><a k="x"/><b k="x"/></r>"#);
    let root = tree.root_element().expect("a document element");
    let kids = children(&tree, root);
    tree.register_id(kids[0], "k", None, "x")
        .expect("a fresh ID");
    assert_eq!(
        tree.register_id(kids[1], "k", None, "x"),
        Err(TreeError::DuplicateId)
    );
    assert_eq!(tree.element_by_id("x"), Some(kids[0]));
    // The holder registering again is no conflict.
    assert_eq!(tree.register_id(kids[0], "k", None, "x"), Ok(()));
}

#[test]
fn an_unlinked_element_keeps_its_id() {
    // As libxml2 keeps the ID of an unlinked node: another element cannot
    // take it, so relinking the holder never leaves two elements one ID.
    let mut tree = parsed(r#"<r><a xml:id="x"/><b/></r>"#);
    let root = tree.root_element().expect("a document element");
    let kids = children(&tree, root);
    tree.unlink(kids[0]).expect("a live node");
    assert_eq!(
        tree.set_attribute(kids[1], "id", Some("xml"), Some(XML_NAMESPACE), "x"),
        Err(TreeError::DuplicateId)
    );
    tree.append_child(root, kids[0]).expect("both live");
    assert_eq!(tree.element_by_id("x"), Some(kids[0]));
}

#[test]
fn a_duplicate_id_leaves_the_attribute_and_the_table_as_they_were() {
    // xml:id 1.0 section 4: a repeated value is an error. A refused change
    // keeps the old value and its registration.
    let mut tree = parsed(r#"<r><a xml:id="x"/><b xml:id="y"/></r>"#);
    let root = tree.root_element().expect("a document element");
    let kids = children(&tree, root);
    assert_eq!(
        tree.set_attribute(kids[1], "id", Some("xml"), Some(XML_NAMESPACE), "x"),
        Err(TreeError::DuplicateId)
    );
    assert_eq!(
        tree.attribute(kids[1], "id", Some(XML_NAMESPACE)),
        Ok(Some("y"))
    );
    assert_eq!(tree.element_by_id("y"), Some(kids[1]));
    assert_eq!(tree.element_by_id("x"), Some(kids[0]));
    // An inserted fragment repeating an ID is refused and rolled back.
    let mut document =
        XmlDocument::from_external_tree(Box::new(tree), &VerificationPolicy::default())
            .expect("the tree projects");
    let root = document.with_view(|view| view.node_identity(view.document().root_element()));
    assert!(document.append_child(root, r#"<c xml:id="x"/>"#).is_err());
    let tree = document.into_owned_tree().expect("the lent tree");
    let root = tree.root_element().expect("a document element");
    assert_eq!(children(&tree, root).len(), 2);
    assert_eq!(tree.element_by_id("x"), Some(kids[0]));
}

#[test]
fn a_replacement_takes_over_the_id_of_what_it_replaces() {
    // An element put in the place of one holding the same xml:id, as
    // decryption restores it, takes the ID: the replaced one leaves with the
    // edit.
    let tree = parsed(r#"<r><a xml:id="x"/></r>"#);
    let mut document =
        XmlDocument::from_external_tree(Box::new(tree), &VerificationPolicy::default())
            .expect("the tree projects");
    let replaced = document.with_view(|view| {
        let child = view
            .document()
            .root_element()
            .first_element_child()
            .expect("a child element");
        view.node_identity(child)
    });
    document
        .replace_element(replaced, r#"<b xml:id="x"/>"#)
        .expect("the replacement is admitted");
    let tree = document.into_owned_tree().expect("the lent tree");
    let element = tree.element_by_id("x").expect("the ID is registered");
    assert_eq!(tree.name(element), Ok(Some("b")));
}

#[test]
fn an_id_is_registered_only_for_an_attribute_carrying_it() {
    // The registration names the attribute and its value; a missing
    // attribute or another value would make lookup and projection disagree.
    let mut tree = parsed(r#"<r token="old"/>"#);
    let root = tree.root_element().expect("a document element");
    assert_eq!(
        tree.register_id(root, "missing", None, "x"),
        Err(TreeError::IdNotCarried)
    );
    assert_eq!(
        tree.register_id(root, "token", None, "other"),
        Err(TreeError::IdNotCarried)
    );
    assert_eq!(tree.element_by_id("x"), None);
    assert_eq!(tree.element_by_id("other"), None);
}

#[test]
fn a_snapshot_counts_its_projected_bytes() {
    // The byte ceiling of a later operation is checked against what the
    // projection read, not against an empty serialization.
    let tree = parsed("<r><c>text</c></r>");
    let snapshot = XmlDocument::snapshot_of_external_tree(&tree, &VerificationPolicy::default())
        .expect("the tree projects");
    let owned = XmlDocument::from_external_tree(
        Box::new(parsed("<r><c>text</c></r>")),
        &VerificationPolicy::default(),
    )
    .expect("the tree projects");
    assert!(snapshot.content_len() > 0);
    assert_eq!(snapshot.content_len(), owned.content_len());
    assert!(snapshot.is_tree_backed());
}

#[test]
fn a_carriage_return_in_text_serializes_as_libxml2_writes_it() {
    // xmlDocDumpMemory writes a carriage return in text as `&#xD;`; a
    // document dumped through the tree layer must print the same bytes.
    let mut tree = parsed("<r/>");
    let root = tree.root_element().expect("a document element");
    tree.set_text(root, "a\r\nb").expect("a live element");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r>a&#xD;\nb</r>\n"
    );
}

#[test]
fn unlinked_children_stay_a_sibling_run_without_a_parent() {
    // As libxml2 hands back replaced content: the former children are
    // unlinked, keep their order as siblings and report no parent; linking
    // one moves it out of the run.
    let mut tree = parsed("<r><a/>t<b/></r>");
    let root = tree.root_element().expect("a document element");
    let first = tree
        .unlink_children(root)
        .expect("a live element")
        .expect("the element had children");
    assert_eq!(children(&tree, root), [] as [TreeNode; 0]);
    assert_eq!(tree.parent(first), Ok(None));
    assert_eq!(tree.name(first), Ok(Some("a")));
    let second = tree
        .next_sibling(first)
        .expect("a live node")
        .expect("a sibling");
    let third = tree
        .next_sibling(second)
        .expect("a live node")
        .expect("a sibling");
    assert_eq!(tree.text(second), Ok(Some("t")));
    assert_eq!(tree.parent(third), Ok(None));
    tree.append_child(root, third)
        .expect("an unlinked node links");
    assert_eq!(children(&tree, root), [third]);
    assert_eq!(tree.next_sibling(second), Ok(None));
    tree.free(first).expect("a live node");
    tree.free(second).expect("a live node");
    assert!(!tree.contains(second));
    assert_eq!(
        tree.unlink_children(root).map(|first| first.is_some()),
        Ok(true)
    );
}

#[test]
fn a_fragment_parses_in_the_namespaces_of_its_context() {
    // As libxml2's xmlParseInNodeContext: the fragment sees the bindings in
    // scope at the context element and comes back as an unlinked run.
    let mut tree = parsed(r#"<r xmlns:p="urn:p"><c/></r>"#);
    let root = tree.root_element().expect("a document element");
    let context = children(&tree, root)[0];
    let first = tree
        .parse_in_context(context, "<p:x>1</p:x><y/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    assert_eq!(tree.parent(first), Ok(None));
    assert_eq!(tree.namespace(first), Ok(Some("urn:p")));
    assert_eq!(tree.prefix(first), Ok(Some("p")));
    assert_eq!(tree.text_content(first), Ok(String::from("1")));
    let second = tree
        .next_sibling(first)
        .expect("a live node")
        .expect("a sibling");
    assert_eq!(tree.name(second), Ok(Some("y")));
    let parse_failed = |result: Result<Option<TreeNode>, XmlDocumentError>| {
        matches!(
            result,
            Err(XmlDocumentError::Parse(_) | XmlDocumentError::AccountedParse(_))
        )
    };
    assert!(parse_failed(tree.parse_in_context(
        context,
        "<p:x>",
        &VerificationPolicy::default()
    )));
    assert!(
        parse_failed(tree.parse_in_context(context, "<q:x/>", &VerificationPolicy::default())),
        "an unbound prefix is refused"
    );
}

#[test]
fn a_context_namespace_with_whitespace_reaches_the_fragment_unchanged() {
    // The context's bindings are written into the wrapper the fragment is
    // parsed in; a tab in a namespace name survives attribute-value
    // normalization (XML 1.0 section 3.3.3) as a character reference.
    let mut tree = parsed("<r/>");
    let root = tree.root_element().expect("a document element");
    tree.declare_namespace(root, Some("p"), "urn:a\tb")
        .expect("an element");
    let first = tree
        .parse_in_context(root, "<p:x/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    assert_eq!(tree.namespace(first), Ok(Some("urn:a\tb")));
}

#[test]
fn a_fragment_linked_outside_its_context_declares_what_it_uses() {
    // Linked where its context's binding is in scope, the fragment adds no
    // declaration; linked elsewhere, it declares the prefix it uses, so the
    // document reads the same names.
    let mut tree = parsed(r#"<r><a xmlns:p="urn:p"><c/></a><d/></r>"#);
    let root = tree.root_element().expect("a document element");
    let a = children(&tree, root)[0];
    let d = children(&tree, root)[1];
    let c = children(&tree, a)[0];
    let inside = tree
        .parse_in_context(c, "<p:x/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.append_child(c, inside)
        .expect("an unlinked node links");
    let outside = tree
        .parse_in_context(c, "<p:y/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.append_child(d, outside)
        .expect("an unlinked node links");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r><a xmlns:p=\"urn:p\"><c><p:x/></c></a>\
         <d><p:y xmlns:p=\"urn:p\"/></d></r>\n"
    );
}

#[test]
fn a_fragment_unlinked_and_linked_elsewhere_declares_what_it_uses() {
    // Taken out of its run by an explicit unlink, the fragment no longer
    // knows its context when it is linked; it keeps the binding it uses, so
    // the document still reads `p:x` in `urn:p`.
    let mut tree = parsed(r#"<r><a xmlns:p="urn:p"/><b/></r>"#);
    let root = tree.root_element().expect("a document element");
    let [a, b] = children(&tree, root)[..] else {
        panic!("two children");
    };
    let x = tree
        .parse_in_context(a, "<p:x/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.unlink(x).expect("a live node");
    tree.append_child(b, x).expect("an unlinked node links");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r><a xmlns:p=\"urn:p\"/><b><p:x xmlns:p=\"urn:p\"/></b></r>\n"
    );
}

#[test]
fn a_fragment_in_no_namespace_unlinked_and_linked_under_a_default_one_undeclares_it() {
    // `x` was read in no namespace. Unlinked from its run it needs no
    // declaration, but linked under a default namespace it must undeclare
    // that one, or the document would read `x` in `urn:b`.
    let mut tree = parsed(r#"<r><a/><b xmlns="urn:b"/></r>"#);
    let root = tree.root_element().expect("a document element");
    let [a, b] = children(&tree, root)[..] else {
        panic!("two children");
    };
    let x = tree
        .parse_in_context(a, "<x/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.unlink(x).expect("a live node");
    assert_eq!(tree.parent(x), Ok(None));
    tree.append_child(b, x).expect("an unlinked node links");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r><a/><b xmlns=\"urn:b\"><x xmlns=\"\"/></b></r>\n"
    );
}

#[test]
fn a_linked_element_unlinked_and_linked_under_a_default_namespace_undeclares_it() {
    // An element that leaves a linked place leaves its context as one
    // leaving a run does: `x`, in no namespace, linked under a default
    // namespace undeclares it, whether it was parsed in place or linked
    // from a fragment first, or the document would read `x` in `urn:b`.
    let mut tree = parsed(r#"<r><a><y/></a><b xmlns="urn:b"/></r>"#);
    let root = tree.root_element().expect("a document element");
    let [a, b] = children(&tree, root)[..] else {
        panic!("two children");
    };
    let x = tree
        .parse_in_context(a, "<x/>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.append_child(a, x).expect("an unlinked node links");
    tree.unlink(x).expect("a live node");
    tree.append_child(b, x).expect("an unlinked node links");
    let [y] = children(&tree, a)[..] else {
        panic!("one child left");
    };
    tree.unlink(y).expect("a live node");
    tree.append_child(b, y).expect("an unlinked node links");
    assert_eq!(
        tree.serialize(),
        "<?xml version=\"1.0\"?>\n<r><a/><b xmlns=\"urn:b\"><x xmlns=\"\"/><y xmlns=\"\"/></b></r>\n"
    );
}

#[test]
fn only_an_element_or_the_document_takes_children() {
    // A child under a text node would vanish from the serialization, which
    // writes a text node's payload alone.
    let mut tree = parsed("<r>t<b/></r>");
    let root = tree.root_element().expect("a document element");
    let [text, b] = children(&tree, root)[..] else {
        panic!("two children");
    };
    tree.unlink(b).expect("a live node");
    assert_eq!(tree.append_child(text, b), Err(TreeError::NotAnElement));
    tree.append_child(root, b)
        .expect("an element takes children");
}

#[test]
fn freed_id_carriers_leave_the_id_table() {
    // Parsing and freeing the same `xml:id` again and again must not leave
    // a record per freed element behind, or every later claim of the value
    // scans the dead ones.
    let mut tree = parsed("<r/>");
    let root = tree.root_element().expect("a document element");
    for _ in 0..3 {
        let x = tree
            .parse_in_context(
                root,
                r#"<x xml:id="same"/>"#,
                &VerificationPolicy::default(),
            )
            .expect("the fragment parses")
            .expect("the fragment has nodes");
        tree.free(x).expect("a live node");
    }
    assert_eq!(tree.ids.recorded(), 0);
    assert_eq!(tree.element_by_id("same"), None);
}

#[test]
fn a_copy_of_a_fragment_descendant_declares_what_it_uses() {
    // The descendant's binding came from the fragment's context, which the
    // copy's source tree no longer shows above it; linked in another tree,
    // the copy declares it.
    let mut source = parsed(r#"<s xmlns:p="urn:p"><c/></s>"#);
    let root = source.root_element().expect("a document element");
    let c = children(&source, root)[0];
    let wrapper = source
        .parse_in_context(c, "<w><p:x/></w>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    let x = children(&source, wrapper)[0];
    let mut target = parsed("<t/>");
    let target_root = target.root_element().expect("a document element");
    let copy = target.copy_from(&source, x).expect("a live node");
    target
        .append_child(target_root, copy)
        .expect("an unlinked node links");
    assert_eq!(
        target.serialize(),
        "<?xml version=\"1.0\"?>\n<t><p:x xmlns:p=\"urn:p\"/></t>\n"
    );
}

#[test]
fn a_copy_without_a_namespace_stays_without_one_under_a_default() {
    // Linked under a default namespace, an element in no namespace
    // undeclares it, or it would read as one of the default's.
    let source = parsed("<s><a/></s>");
    let a = children(&source, source.root_element().expect("a root"))[0];
    let mut target = parsed(r#"<t xmlns="urn:t"/>"#);
    let root = target.root_element().expect("a document element");
    let copy = target.copy_from(&source, a).expect("a live node");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    assert_eq!(
        target.serialize(),
        "<?xml version=\"1.0\"?>\n<t xmlns=\"urn:t\"><a xmlns=\"\"/></t>\n"
    );
}

#[test]
fn a_value_a_shadowed_carrier_still_holds_is_not_claimed_again() {
    // Once the registered carrier lets the value go, the shadowed one is its
    // only carrier: a third element cannot claim it, or the lookup would
    // find two.
    let mut tree = parsed(r#"<r><a xml:id="x"/><b xml:id="x"/><c/></r>"#);
    let root = tree.root_element().expect("a root");
    let [a, b, c] = children(&tree, root)[..] else {
        panic!("three children");
    };
    tree.remove_attribute(a, "id", Some(XML_NAMESPACE))
        .expect("an element");
    assert_eq!(tree.element_by_id("x"), Some(b));
    assert_eq!(
        tree.set_attribute(c, "id", Some("xml"), Some(XML_NAMESPACE), "x"),
        Err(TreeError::DuplicateId)
    );
    assert_eq!(tree.element_by_id("x"), Some(b));
}

#[test]
fn a_removed_shadowed_id_attribute_stops_being_an_id() {
    // Removing the attribute ends its role as a further carrier: the same
    // name set again later is an ordinary attribute until registered.
    let mut source = parsed(r#"<s><b id="x"/></s>"#);
    let carrier = children(&source, source.root_element().expect("a root"))[0];
    source
        .register_id(carrier, "id", None, "x")
        .expect("the attribute carries the value");
    let mut target = parsed(r#"<t><a id="x"/></t>"#);
    let root = target.root_element().expect("a root");
    let holder = children(&target, root)[0];
    target
        .register_id(holder, "id", None, "x")
        .expect("the attribute carries the value");
    let copy = target.copy_from(&source, carrier).expect("a live node");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    target
        .remove_attribute(copy, "id", None)
        .expect("an element");
    target
        .set_attribute(copy, "id", None, None, "y")
        .expect("an element");
    assert_eq!(target.element_by_id("y"), None);
}

#[test]
fn a_shadowed_id_carrier_moves_its_id_when_its_value_changes() {
    // A copy shadowed for a value the target holds still carries its ID: a
    // new value is registered for it.
    let mut source = parsed(r#"<s><b id="x"/></s>"#);
    let carrier = children(&source, source.root_element().expect("a root"))[0];
    source
        .register_id(carrier, "id", None, "x")
        .expect("the attribute carries the value");
    let mut target = parsed(r#"<t><a id="x"/></t>"#);
    let root = target.root_element().expect("a root");
    let holder = children(&target, root)[0];
    target
        .register_id(holder, "id", None, "x")
        .expect("the attribute carries the value");
    let copy = target.copy_from(&source, carrier).expect("a live node");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    target
        .set_attribute(copy, "id", None, None, "y")
        .expect("an element");
    assert_eq!(target.element_by_id("y"), Some(copy));
    assert_eq!(target.element_by_id("x"), Some(holder));
}

#[test]
fn a_fragment_parses_in_the_document_context() {
    // libxml2 accepts the document node as the context, which binds no
    // prefix: the document element can be replaced from a buffer.
    let mut tree = parsed(r#"<r xmlns:p="urn:p"/>"#);
    let document = tree.document_node();
    let first = tree
        .parse_in_context(document, "<n>1</n>", &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    assert_eq!(tree.parent(first), Ok(None));
    assert_eq!(tree.name(first), Ok(Some("n")));
    assert!(
        tree.parse_in_context(document, "<p:x/>", &VerificationPolicy::default())
            .is_err(),
        "the document binds no prefix"
    );
}

#[test]
fn a_node_copied_from_another_tree_keeps_its_namespaces() {
    // As libxml2's xmlDocCopyNode: the copy is unlinked in the target tree
    // and declares the bindings its source inherited, so it reads the same
    // once linked there; its xml:id is registered.
    let source = parsed(r#"<s xmlns:p="urn:p"><p:a xml:id="i"><b p:x="1"/></p:a></s>"#);
    let element = children(&source, source.root_element().expect("a root"))[0];
    let mut target = parsed("<t/>");
    let copy = target.copy_from(&source, element).expect("a live node");
    assert_eq!(target.parent(copy), Ok(None));
    let root = target.root_element().expect("a root");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    assert_eq!(
        target.serialize(),
        "<?xml version=\"1.0\"?>\n<t><p:a xmlns:p=\"urn:p\" xml:id=\"i\"><b p:x=\"1\"/></p:a></t>\n"
    );
    assert_eq!(target.element_by_id("i"), Some(copy));
    assert_eq!(
        target.copy_from(&source, source.document_node()),
        Err(TreeError::DocumentNode)
    );
}

#[test]
fn a_copy_of_an_unlinked_node_declares_the_prefixes_it_uses() {
    // A fragment parsed in a context uses the context's bindings but holds
    // no declaration of them; its copy declares what it uses, as libxml2's
    // copy reconciles namespaces, so it reads the same wherever it is linked.
    let mut source = parsed(r#"<r xmlns:p="urn:p" xmlns="urn:d"/>"#);
    let context = source.root_element().expect("a root");
    let first = source
        .parse_in_context(
            context,
            r#"<p:x p:a="1"><y/></p:x>"#,
            &VerificationPolicy::default(),
        )
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    let mut target = parsed("<t/>");
    let copy = target.copy_from(&source, first).expect("a live node");
    let root = target.root_element().expect("a root");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    let xml = target.serialize();
    let reparsed = parsed(&xml);
    let x = children(&reparsed, reparsed.root_element().expect("a root"))[0];
    assert_eq!(reparsed.namespace(x), Ok(Some("urn:p")), "{xml}");
    let y = children(&reparsed, x)[0];
    assert_eq!(reparsed.namespace(y), Ok(Some("urn:d")), "{xml}");
}

#[test]
fn a_prefixed_attribute_named_xmlns_stays_an_ordinary_attribute() {
    // Only an unprefixed `xmlns` and the `xmlns:` prefix declare a namespace
    // (Namespaces in XML 1.0 section 3): `p:xmlns` keeps its place among the
    // attributes and its source text.
    let xml = r#"<r xmlns:p="urn:p" a="1" p:xmlns="&amp;"/>"#;
    let tree = parsed(xml);
    assert_eq!(
        tree.serialize(),
        format!("<?xml version=\"1.0\"?>\n{xml}\n")
    );
}

#[test]
fn a_shadowed_registered_id_carries_into_a_later_copy() {
    // A copy whose registered ID the target already holds is shadowed
    // there; copied on into a tree without the value, it is that tree's
    // sole carrier and the lookup finds it.
    let mut first = parsed(r#"<s><b id="x"/></s>"#);
    let carrier = children(&first, first.root_element().expect("a root"))[0];
    first
        .register_id(carrier, "id", None, "x")
        .expect("the attribute carries the value");
    let mut second = parsed(r#"<t><a id="x"/></t>"#);
    let holder = children(&second, second.root_element().expect("a root"))[0];
    second
        .register_id(holder, "id", None, "x")
        .expect("the attribute carries the value");
    let shadowed = second.copy_from(&first, carrier).expect("a live node");
    let mut third = parsed("<u/>");
    let root = third.root_element().expect("a root");
    let copy = third.copy_from(&second, shadowed).expect("a live node");
    third
        .append_child(root, copy)
        .expect("an unlinked node links");
    assert_eq!(third.element_by_id("x"), Some(copy));
}

#[test]
fn an_id_two_linked_elements_carry_names_neither() {
    // A copy bringing an ID the target already holds is linked, as libxml2
    // links it, but a lookup of the value names no element while both are
    // linked, and the copy once the original leaves.
    let source = parsed(r#"<s><b xml:id="x"/></s>"#);
    let copied = children(&source, source.root_element().expect("a root"))[0];
    let mut target = parsed(r#"<t><a xml:id="x"/></t>"#);
    let root = target.root_element().expect("a root");
    let original = children(&target, root)[0];
    let copy = target.copy_from(&source, copied).expect("a live node");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    assert_eq!(target.element_by_id("x"), None, "two linked carriers");
    target.unlink(original).expect("a linked node unlinks");
    assert_eq!(target.element_by_id("x"), Some(copy));
}

#[test]
fn a_replaced_node_linked_again_makes_its_id_ambiguous() {
    // The replacement takes the ID the replaced node held; linking that node
    // again does not take it back silently.
    let mut tree = parsed(r#"<r><old xml:id="x"/></r>"#);
    let root = tree.root_element().expect("a root");
    let old = children(&tree, root)[0];
    let first = tree
        .parse_in_context(root, r#"<new xml:id="x"/>"#, &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.replace_with_run(old, first).expect("the run links");
    assert_eq!(tree.element_by_id("x"), Some(first));
    tree.append_child(root, old)
        .expect("the old node links again");
    assert_eq!(tree.element_by_id("x"), None);
}

#[test]
fn a_replacement_owns_the_id_of_the_node_it_replaced() {
    // The replaced node is kept, unlinked, but releases its ID to the
    // replacement: setting the replacement's `xml:id` to the value it
    // already carries is no duplicate.
    let mut tree = parsed(r#"<r><old xml:id="x"/></r>"#);
    let root = tree.root_element().expect("a root");
    let old = children(&tree, root)[0];
    let first = tree
        .parse_in_context(root, r#"<new xml:id="x"/>"#, &VerificationPolicy::default())
        .expect("the fragment parses")
        .expect("the fragment has nodes");
    tree.replace_with_run(old, first).expect("the run links");
    tree.set_attribute(first, "id", Some("xml"), Some(XML_NAMESPACE), "x")
        .expect("the replacement owns its ID");
    assert_eq!(tree.element_by_id("x"), Some(first));
}

#[test]
fn a_copy_keeps_the_ids_a_caller_registered() {
    // An ID registered on an attribute of the copied subtree carries over
    // with the attribute, as libxml2's copy re-adds a copied ID attribute.
    let mut source = parsed(r#"<s><a Id="target"><b ref="inner"/></a></s>"#);
    let element = children(&source, source.root_element().expect("a root"))[0];
    let inner = children(&source, element)[0];
    source
        .register_id(element, "Id", None, "target")
        .expect("the attribute carries the value");
    source
        .register_id(inner, "ref", None, "inner")
        .expect("the attribute carries the value");
    let mut target = parsed("<t/>");
    let copy = target.copy_from(&source, element).expect("a live node");
    let root = target.root_element().expect("a root");
    target
        .append_child(root, copy)
        .expect("an unlinked node links");
    assert_eq!(target.element_by_id("target"), Some(copy));
    assert_eq!(
        target.element_by_id("inner"),
        Some(children(&target, copy)[0])
    );
}

#[test]
fn a_cdata_terminator_in_edited_content_survives_serialization() {
    // XML 1.0 section 2.7: CDATA content cannot hold `]]>`, so the
    // serialization splits it across sections, as libxml2 writes it.
    let mut tree = parsed("<r><![CDATA[x]]></r>");
    let root = tree.root_element().expect("a document element");
    let cdata = children(&tree, root)[0];
    tree.set_text(cdata, "a]]>b").expect("a CDATA node");
    let xml = tree.serialize();
    assert!(xml.contains("<![CDATA[a]]]]><![CDATA[>b]]>"), "{xml}");
    let again = parsed(&xml);
    let root = again.root_element().expect("a document element");
    assert_eq!(again.text_content(root), Ok(String::from("a]]>b")));
}

#[test]
fn an_attribute_value_survives_serialization_and_reparse() {
    // XML 1.0 section 3.3.3: a literal newline in an attribute value is
    // normalized to a space, a reference is not; the serialization must
    // keep the normalized value, not the source's newline.
    let tree = parsed("<r a=\"x\n&amp;y\" b=\"p&#10;q\"/>");
    let root = tree.root_element().expect("a document element");
    assert_eq!(tree.attribute(root, "a", None), Ok(Some("x &y")));
    let again = parsed(&tree.serialize());
    let root = again.root_element().expect("a document element");
    assert_eq!(again.attribute(root, "a", None), Ok(Some("x &y")));
    assert_eq!(again.attribute(root, "b", None), Ok(Some("p\nq")));
}

#[test]
fn the_serialization_declares_the_encoding_of_its_bytes() {
    // XML 1.0 section 4.3.3: the declared encoding is the one the bytes use,
    // and the serialization is UTF-8 whatever the source declared.
    let mut tree = parsed(r#"<?xml version="1.0" encoding="ISO-8859-1"?><r/>"#);
    let root = tree.root_element().expect("a document element");
    tree.set_text(root, "\u{e9}").expect("a live element");
    let xml = tree.serialize();
    assert!(xml.contains("encoding=\"UTF-8\""), "{xml}");
    assert!(!xml.contains("ISO-8859-1"), "{xml}");
}

#[test]
fn an_ordinary_attribute_never_replaces_a_namespace_declaration() {
    // `xmlns:a` and an unqualified `a` share a local name; setting `a` must
    // leave the declaration of the prefix `a` in place.
    let mut tree = parsed(r#"<r xmlns:a="urn:a"><a:c/></r>"#);
    let root = tree.root_element().expect("a document element");
    tree.set_attribute(root, "a", None, None, "value")
        .expect("an element");
    let declarations: Vec<_> = tree
        .namespace_declarations(root)
        .expect("a live node")
        .collect();
    assert_eq!(
        declarations,
        [TreeNamespace {
            prefix: Some("a"),
            uri: "urn:a"
        }]
    );
    assert_eq!(tree.attribute(root, "a", None), Ok(Some("value")));
    // An empty namespace is no namespace: the same attribute is set again.
    tree.set_attribute(root, "a", None, Some(""), "other")
        .expect("an element");
    let named_a = tree
        .attributes(root)
        .expect("a live node")
        .filter(|attribute| attribute.local_name == "a")
        .count();
    assert_eq!(named_a, 1);
    assert_eq!(tree.attribute(root, "a", None), Ok(Some("other")));
}

#[test]
fn the_byte_ceiling_is_the_policy_violation() {
    let mut policy = VerificationPolicy::default();
    policy.resources.max_xml_document_bytes = 4;
    assert!(matches!(
        OwnedTree::parse_with_policy("<r></r>", &policy),
        Err(XmlDocumentError::Policy(PolicyViolation::ResourceLimit {
            resource: resource_name::XML_DOCUMENT,
            maximum: 4,
            actual: 7,
        }))
    ));
}

#[test]
fn a_forbidden_document_type_is_refused_before_its_subset_is_read() {
    // The recursive entities would fail only once the parser expands them;
    // a policy without DTDs refuses the declaration before that.
    let xml = r#"<!DOCTYPE r [<!ENTITY a "&b;"><!ENTITY b "&a;">]><r>&a;</r>"#;
    assert!(matches!(
        OwnedTree::parse_with_policy(xml, &VerificationPolicy::default()),
        Err(XmlDocumentError::Parse(ParseError::DtdDetected))
    ));
}

#[test]
fn an_inserted_xml_id_is_registered_in_the_trees_id_table() {
    // An element an edit inserts, such as one decryption restores, is found
    // by its xml:id as a parsed one is.
    let tree = parsed("<r/>");
    let mut document =
        XmlDocument::from_external_tree(Box::new(tree), &VerificationPolicy::default())
            .expect("the tree projects");
    let root = document.with_view(|view| view.node_identity(view.document().root_element()));
    document
        .append_child(root, r#"<c xml:id=" k "/>"#)
        .expect("the fragment is appended");
    let tree = document.into_owned_tree().expect("the lent tree");
    let element = tree.element_by_id("k").expect("the xml:id is registered");
    assert_eq!(tree.name(element), Ok(Some("c")));
}

#[test]
fn a_snapshot_refuses_every_edit_and_keeps_its_content() {
    // A snapshot keeps no tree and no serialization to edit: an edit is
    // refused rather than spliced into nothing.
    let tree = parsed("<!--before--><r><c/></r>");
    let mut snapshot =
        XmlDocument::snapshot_of_external_tree(&tree, &VerificationPolicy::default())
            .expect("the tree projects");
    let (root, child) = snapshot.with_view(|view| {
        let root = view.root_element();
        let child = view
            .document()
            .root_element()
            .first_element_child()
            .map(|child| view.node_identity(child))
            .expect("a child element");
        (root, child)
    });
    assert!(matches!(
        snapshot.replace_element(root, "<n/>"),
        Err(XmlDocumentError::ReadOnlySnapshot)
    ));
    assert!(matches!(
        snapshot.replace_element(child, "<n/>"),
        Err(XmlDocumentError::ReadOnlySnapshot)
    ));
    assert!(matches!(
        snapshot.append_child(root, "<n/>"),
        Err(XmlDocumentError::ReadOnlySnapshot)
    ));
    assert!(matches!(
        snapshot.replace_content(root, "t"),
        Err(XmlDocumentError::ReadOnlySnapshot)
    ));
    assert!(matches!(
        snapshot.insert_before(child, "<n/>"),
        Err(XmlDocumentError::ReadOnlySnapshot)
    ));
    snapshot.with_view(|view| {
        let document = view.document();
        assert!(
            document
                .root()
                .first_child()
                .is_some_and(|node| node.is_comment())
        );
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "r");
        assert_eq!(
            root.first_element_child()
                .map(|child| child.tag_name().name()),
            Some("c")
        );
    });
}

#[test]
fn operations_read_the_tree_through_a_tree_backed_document() {
    // The tree is an external tree of a core document: its projection is the
    // document every operation reads.
    let tree = parsed(r#"<r xmlns="urn:d"><c id="x">t</c></r>"#);
    let document = XmlDocument::from_external_tree(Box::new(tree), &VerificationPolicy::default())
        .expect("the tree projects");
    document.with_view(|view| {
        let root = view.document().root_element();
        assert_eq!(root.tag_name().name(), "r");
        assert_eq!(root.tag_name().namespace(), Some("urn:d"));
        let child = root.first_element_child().expect("a child element");
        assert_eq!(child.attribute("id"), Some("x"));
        assert_eq!(child.text(), Some("t"));
    });
}
