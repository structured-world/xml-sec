use alloc::boxed::Box;

use super::{SelectedNode, XPathForm, select_xpath};
use crate::document::external::{ExternalNode, ExternalTree, TreeEdit, TreeEditError, TreeSink};
use crate::policy::{ResourcePolicy, VerificationPolicy};
use crate::xml::IdAttributeRegistration;
use crate::xmldsig::transforms::XPathExpression;
use crate::{ParseError, XmlDocument};

const ROOT: ExternalNode = ExternalNode(2);
const KEEP: ExternalNode = ExternalNode(3);
const TEXT: ExternalNode = ExternalNode(4);
const COMMENT: ExternalNode = ExternalNode(5);

/// `<r xmlns:p="urn:p" a="1"><p:k Id="x">t</p:k><!--c--></r>`, reported the
/// way a libxml2 walk reports it.
struct Tree;

impl ExternalTree for Tree {
    fn document(&self) -> ExternalNode {
        ExternalNode(1)
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        sink.begin_element(ROOT, "r", None, None)?;
        sink.declare_namespace(Some("p"), "urn:p")?;
        sink.attribute("a", None, None, "1", false)?;
        sink.open_element()?;
        sink.begin_element(KEEP, "k", Some("p"), Some("urn:p"))?;
        sink.attribute("Id", None, None, "x", false)?;
        sink.open_element()?;
        sink.text(TEXT, "t")?;
        sink.end_element()?;
        sink.comment(COMMENT, "c")?;
        sink.end_element()
    }

    fn apply(&mut self, _: &[TreeEdit<'_>]) -> Result<(), TreeEditError> {
        Err(TreeEditError("read-only test tree".into()))
    }
    fn checkpoint(&mut self) -> usize {
        0
    }
    fn rollback(&mut self, _: usize) {}
    fn release(&mut self, _: usize) {}
}

fn document() -> XmlDocument {
    XmlDocument::from_external_tree(Box::new(Tree), &VerificationPolicy::default())
        .expect("the tree must project")
}

fn select(
    expression: &XPathExpression,
    here: Option<ExternalNode>,
    form: XPathForm,
    registrations: &[IdAttributeRegistration],
) -> Result<alloc::vec::Vec<SelectedNode<'static>>, crate::xmldsig::types::TransformError> {
    let document = document();
    document.with_view(|view| {
        select_xpath(
            view,
            expression,
            here,
            form,
            registrations,
            &ResourcePolicy::default(),
        )
        .map(|nodes| nodes.into_iter().map(owned).collect())
    })
}

/// Detach a selected node from the document it borrows, for comparison.
fn owned(node: SelectedNode<'_>) -> SelectedNode<'static> {
    let leak = |text: &str| -> &'static str { Box::leak(text.into()) };
    match node {
        SelectedNode::Node(node) => SelectedNode::Node(node),
        SelectedNode::Attribute {
            owner,
            namespace,
            local_name,
        } => SelectedNode::Attribute {
            owner,
            namespace: namespace.map(leak),
            local_name: leak(local_name),
        },
        SelectedNode::Namespace { owner, prefix, uri } => SelectedNode::Namespace {
            owner,
            prefix: prefix.map(leak),
            uri: leak(uri),
        },
    }
}

#[test]
fn each_node_form_keeps_every_node_the_predicate_accepts() {
    // XMLDSig XPath: the expression is a per-node predicate, so attributes,
    // namespace nodes and text of the element are judged one by one and the
    // element's parent and sibling comment are left out.
    let expression = XPathExpression::new("ancestor-or-self::p:k").with_namespace("p", "urn:p");
    let nodes = select(&expression, None, XPathForm::EachNode, &[]).expect("selection");
    assert!(nodes.contains(&SelectedNode::Node(KEEP)));
    assert!(nodes.contains(&SelectedNode::Node(TEXT)));
    assert!(nodes.contains(&SelectedNode::Attribute {
        owner: KEEP,
        namespace: None,
        local_name: "Id",
    }));
    assert!(nodes.contains(&SelectedNode::Namespace {
        owner: KEEP,
        prefix: Some("p"),
        uri: "urn:p",
    }));
    assert!(!nodes.contains(&SelectedNode::Node(ROOT)));
    assert!(!nodes.contains(&SelectedNode::Node(COMMENT)));
    let position = |wanted| nodes.iter().position(|node| *node == wanted);
    assert!(
        position(SelectedNode::Node(KEEP)) < position(SelectedNode::Node(TEXT)),
        "document order"
    );
}

#[test]
fn node_set_form_returns_exactly_the_evaluated_nodes() {
    // Filter 2.0 and XPointer read the node-set itself: an attribute stays an
    // attribute, without its owner or a subtree around it.
    let expression = XPathExpression::new("//p:k/@Id | //comment()").with_namespace("p", "urn:p");
    let nodes = select(&expression, None, XPathForm::NodeSet, &[]).expect("selection");
    assert_eq!(
        nodes,
        [
            SelectedNode::Attribute {
                owner: KEEP,
                namespace: None,
                local_name: "Id",
            },
            SelectedNode::Node(COMMENT),
        ]
    );
}

#[test]
fn node_set_form_refuses_a_scalar_result() {
    let expression = XPathExpression::new("count(//*)");
    assert!(select(&expression, None, XPathForm::NodeSet, &[]).is_err());
}

#[test]
fn here_names_the_caller_node_and_id_uses_the_registrations() {
    // here() is the external node the caller names; id() matches only the
    // attributes the request registers.
    let parent = XPathExpression::new("here()/..");
    assert_eq!(
        select(&parent, Some(KEEP), XPathForm::NodeSet, &[]).expect("selection"),
        [SelectedNode::Node(ROOT)]
    );
    let by_id = XPathExpression::new("id('x')");
    let registrations = [IdAttributeRegistration::global("Id")];
    assert_eq!(
        select(&by_id, None, XPathForm::NodeSet, &registrations).expect("selection"),
        [SelectedNode::Node(KEEP)]
    );
}

fn pointer(
    text: &str,
    namespaces: &[(&str, &str)],
) -> Result<alloc::vec::Vec<SelectedNode<'static>>, crate::xmldsig::types::TransformError> {
    let document = document();
    let registrations = [IdAttributeRegistration::global("Id")];
    document.with_view(|view| {
        super::select_xpointer(
            view,
            text,
            namespaces,
            None,
            &registrations,
            &ResourcePolicy::default(),
        )
        .map(|nodes| nodes.into_iter().map(owned).collect())
    })
}

#[test]
fn xpointer_parts_are_tried_in_order_until_one_identifies_nodes() {
    // XPointer Framework 3.3: an empty part, and a part of an unknown scheme,
    // pass to the next; xmlns() binds a prefix for the parts after it.
    assert_eq!(
        pointer("x", &[]).expect("shorthand"),
        [SelectedNode::Node(KEEP)]
    );
    assert_eq!(
        pointer(
            "xpointer(//nothing) foo:bar(x) xmlns(q=urn:p) xpointer(//q:k)",
            &[]
        )
        .expect("scheme parts"),
        [SelectedNode::Node(KEEP)]
    );
    assert_eq!(
        pointer("xpointer(//q:k)", &[("q", "urn:p")]).expect("caller bindings"),
        [SelectedNode::Node(KEEP)]
    );
}

#[test]
fn a_pointer_that_identifies_nothing_is_an_error() {
    // XPointer Framework 3.3: a pointer none of whose parts identifies a
    // subresource fails, like a shorthand naming no element.
    assert!(pointer("xpointer(//nothing)", &[]).is_err());
    assert!(pointer("xpointer(//nothing) foo:bar(x)", &[]).is_err());
    assert!(pointer("absent", &[]).is_err());
}

#[test]
fn element_scheme_follows_ids_and_child_sequences() {
    assert_eq!(
        pointer("element(/1/1)", &[]).expect("child sequence"),
        [SelectedNode::Node(KEEP)]
    );
    assert_eq!(
        pointer("element(x)", &[]).expect("by id"),
        [SelectedNode::Node(KEEP)]
    );
    assert_eq!(
        pointer("element(/1)", &[]).expect("root"),
        [SelectedNode::Node(ROOT)]
    );
    assert!(pointer("element(/0)", &[]).is_err());
    assert!(pointer("element()", &[]).is_err());
}

#[test]
fn xpointer_escapes_and_grammar_errors() {
    // `^)` keeps a parenthesis inside the scheme data; an unbalanced part or
    // an invalid escape breaks the Framework grammar.
    assert_eq!(
        pointer("xpointer(//comment()[. != '^)'])", &[]).expect("escaped"),
        [SelectedNode::Node(COMMENT)]
    );
    assert!(pointer("xpointer(//*", &[]).is_err());
    assert!(pointer("xpointer(^x)", &[]).is_err());
    assert!(pointer("1bad(x)", &[]).is_err());
}

#[test]
fn a_here_node_outside_the_document_is_refused() {
    let expression = XPathExpression::new("here()");
    assert!(select(&expression, Some(ExternalNode(99)), XPathForm::NodeSet, &[]).is_err());
}
