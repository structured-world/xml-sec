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
