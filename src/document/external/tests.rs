use alloc::{boxed::Box, string::String, vec::Vec};

use super::{ExternalNode, ExternalTree, TreeSink};
use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize, canonicalize_document};
use crate::policy::{ResourcePolicy, VerificationPolicy, XmlInputPolicy};
use crate::{Node, NodeType, ParseError, XmlDocument, XmlDocumentError};

/// An external tree that reports a parsed document node by node, the way a
/// libxml2 walk reports its tree: every element names the declarations of its
/// own start tag, and each node's reference is its arena position plus one.
struct Mirror {
    xml: String,
    /// Attributes the tree itself registered as IDs, by local name.
    ids: Vec<&'static str>,
    has_dtd: bool,
}

impl Mirror {
    fn new(xml: &str) -> Self {
        Self {
            xml: xml.into(),
            ids: Vec::new(),
            has_dtd: false,
        }
    }

    fn report(&self, node: Node<'_, '_>, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        let reference = ExternalNode(u64::from(node.id().get()) + 1);
        match node.node_type() {
            NodeType::Element => {
                let name = node.tag_name();
                sink.begin_element(reference, name.name(), node.prefix(), name.namespace())?;
                let inherited = node.parent_element();
                for namespace in node.namespaces() {
                    let declared_by_parent = inherited.is_some_and(|parent| {
                        parent.lookup_namespace_uri(namespace.name()) == Some(namespace.uri())
                    });
                    if !declared_by_parent {
                        sink.declare_namespace(namespace.name(), namespace.uri())?;
                    }
                }
                for attribute in node.attributes() {
                    sink.attribute(
                        attribute.name(),
                        attribute.prefix(),
                        attribute.namespace(),
                        attribute.value(),
                        self.ids.contains(&attribute.name()),
                    )?;
                }
                sink.open_element()?;
                for child in node.children() {
                    self.report(child, sink)?;
                }
                sink.end_element()
            }
            NodeType::Text => sink.text(reference, node.text().unwrap_or_default()),
            NodeType::Comment => sink.comment(reference, node.text().unwrap_or_default()),
            NodeType::PI => {
                let pi = node.pi().expect("a processing instruction");
                sink.processing_instruction(reference, pi.target, pi.value)
            }
            NodeType::Root => unreachable!("the root is reported by its children"),
        }
    }
}

impl ExternalTree for Mirror {
    fn document(&self) -> ExternalNode {
        ExternalNode(1)
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        if self.has_dtd {
            sink.document_type()?;
        }
        let document = crate::Document::parse(&self.xml)?;
        for child in document.root().children() {
            self.report(child, sink)?;
        }
        Ok(())
    }
}

/// A tree that reports whatever `walk` reports, for shapes no parse produces.
struct Scripted(fn(&mut TreeSink<'_>) -> Result<(), ParseError>);

impl ExternalTree for Scripted {
    fn document(&self) -> ExternalNode {
        ExternalNode(1)
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        (self.0)(sink)
    }
}

fn with_comments() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Inclusive1_0, true)
}

fn project(tree: impl ExternalTree + 'static, policy: &VerificationPolicy) -> XmlDocument {
    XmlDocument::from_external_tree(Box::new(tree), policy).expect("the tree must project")
}

fn refused(tree: impl ExternalTree + 'static, policy: &VerificationPolicy) -> XmlDocumentError {
    match XmlDocument::from_external_tree(Box::new(tree), policy) {
        Ok(_) => panic!("the tree must be refused"),
        Err(error) => error,
    }
}

fn limited(resources: ResourcePolicy) -> VerificationPolicy {
    VerificationPolicy {
        resources,
        ..VerificationPolicy::default()
    }
}

#[test]
fn a_projected_tree_canonicalizes_like_its_parse() {
    // The walk must carry every name, namespace, attribute, text, comment and
    // processing instruction; C14N with comments reads all of them.
    let xml = concat!(
        "<?pi before?><!--lead-->",
        r#"<a:root xmlns:a="urn:a" xmlns="urn:default" attr="1" a:qualified="2">"#,
        "text<b:child xmlns:b=\"urn:b\" xmlns=\"\">inner<!--c--><?target value?></b:child>",
        "<empty/>tail &amp; more</a:root><!--trail-->"
    );
    let document = project(Mirror::new(xml), &VerificationPolicy::default());
    let parsed = crate::Document::parse(xml).expect("the fixture parses");
    let mut expected = Vec::new();
    canonicalize(&parsed, None, &with_comments(), &mut expected).expect("the parse canonicalizes");
    let projected =
        canonicalize_document(&document, &with_comments()).expect("the projection canonicalizes");
    assert_eq!(projected, expected);
}

#[test]
fn every_projected_node_keeps_the_external_node_it_came_from() {
    // Edits and results address the caller's nodes through these references.
    let xml = "<root><child>text</child><!--note--></root>";
    let document = project(Mirror::new(xml), &VerificationPolicy::default());
    document.with_view(|view| {
        for node in view.document().descendants() {
            let identity = view.node_identity(node);
            assert_eq!(
                document
                    .external_node(identity)
                    .expect("every node of the walk has its reference"),
                ExternalNode(u64::from(node.id().get()) + 1)
            );
        }
    });
}

#[test]
fn adjacent_text_joins_one_node_that_keeps_the_first_reference() {
    // libxml2 keeps text and CDATA as separate siblings; the infoset has one
    // character-data run, and an edit of it must reach the first sibling.
    let document = project(
        Scripted(|sink| {
            sink.begin_element(ExternalNode(2), "root", None, None)?;
            sink.open_element()?;
            sink.text(ExternalNode(3), "first ")?;
            sink.text(ExternalNode(4), "second")?;
            sink.end_element()
        }),
        &VerificationPolicy::default(),
    );
    document.with_view(|view| {
        let root = view.document().root_element();
        let children: Vec<_> = root.children().collect();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].text(), Some("first second"));
        let identity = view.node_identity(children[0]);
        assert_eq!(
            document
                .external_node(identity)
                .expect("joined text keeps a reference"),
            ExternalNode(3)
        );
    });
}

#[test]
fn an_id_the_tree_registered_is_an_id_with_its_value_unchanged() {
    // A caller's xmlAddID registration is an ID like a DTD one, and libxml2
    // does not normalize its value; normalizing it here would change the
    // attribute C14N writes.
    let xml = r#"<root><item ref=" two  spaces ">x</item><item other="y"/></root>"#;
    let mut mirror = Mirror::new(xml);
    mirror.ids.push("ref");
    let document = project(mirror, &VerificationPolicy::default());
    document.with_view(|view| {
        let ids: Vec<(&str, &str, bool)> = view
            .document()
            .descendants()
            .flat_map(Node::attributes)
            .map(|attribute| (attribute.name(), attribute.value(), attribute.is_id()))
            .collect();
        assert_eq!(ids, [("ref", " two  spaces ", true), ("other", "y", false)]);
    });
}

#[test]
fn a_projection_without_a_document_element_is_refused() {
    let error = refused(
        Scripted(|sink| sink.comment(ExternalNode(2), "only a comment")),
        &VerificationPolicy::default(),
    );
    assert!(
        matches!(&error, XmlDocumentError::Parse(ParseError::Backend { message, .. })
            if message.contains("no document element")),
        "{error}"
    );
}

#[test]
fn calls_out_of_order_are_refused_by_name() {
    // A broken walk must fail loudly, never build a tree it did not describe.
    let error = refused(
        Scripted(|sink| {
            sink.begin_element(ExternalNode(2), "root", None, None)?;
            sink.text(ExternalNode(3), "inside the start tag")
        }),
        &VerificationPolicy::default(),
    );
    assert!(
        error
            .to_string()
            .contains("text reported inside a start tag"),
        "{error}"
    );
}

#[test]
fn a_walk_that_leaves_an_element_open_is_refused() {
    let error = refused(
        Scripted(|sink| {
            sink.begin_element(ExternalNode(2), "root", None, None)?;
            sink.open_element()
        }),
        &VerificationPolicy::default(),
    );
    assert!(
        error.to_string().contains("ended inside an open node"),
        "{error}"
    );
}

#[test]
fn a_tree_past_the_node_limit_is_refused() {
    let resources = ResourcePolicy {
        max_xml_nodes: 3,
        ..ResourcePolicy::default()
    };
    let error = refused(Mirror::new("<a><b/><c/><d/></a>"), &limited(resources));
    assert!(
        matches!(
            error,
            XmlDocumentError::Parse(ParseError::NodesLimitReached)
        ),
        "{error}"
    );
}

#[test]
fn a_tree_past_the_depth_limit_is_refused_with_its_depth() {
    let resources = ResourcePolicy {
        max_xml_depth: 2,
        ..ResourcePolicy::default()
    };
    // The exact limit is accepted; one level deeper is not.
    project(Mirror::new("<a><b/></a>"), &limited(resources.clone()));
    let error = refused(Mirror::new("<a><b><c/></b></a>"), &limited(resources));
    assert!(
        matches!(
            error,
            XmlDocumentError::Parse(ParseError::DepthLimitReached {
                maximum: 2,
                actual: 3
            })
        ),
        "{error}"
    );
}

#[test]
fn a_tree_past_the_namespace_limit_is_refused() {
    let resources = ResourcePolicy {
        max_xml_namespace_bindings: 1,
        ..ResourcePolicy::default()
    };
    let xml = r#"<root xmlns:first="urn:first" xmlns:second="urn:second"/>"#;
    let error = refused(Mirror::new(xml), &limited(resources));
    assert!(
        matches!(
            error,
            XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: 1,
                actual: 2
            })
        ),
        "{error}"
    );
}

#[test]
fn a_tree_past_the_byte_limit_is_refused() {
    let resources = ResourcePolicy {
        max_xml_document_bytes: 16,
        ..ResourcePolicy::default()
    };
    let error = refused(
        Mirror::new("<root>0123456789abcdef</root>"),
        &limited(resources),
    );
    assert!(
        matches!(
            error,
            XmlDocumentError::Parse(ParseError::ByteLimitReached { maximum: 16, .. })
        ),
        "{error}"
    );
}

#[test]
fn a_document_type_is_refused_unless_the_policy_allows_it() {
    // The tree's own DTD is the same input risk as a parsed one.
    let mut mirror = Mirror::new("<root/>");
    mirror.has_dtd = true;
    let error = refused(mirror, &VerificationPolicy::default());
    assert!(
        matches!(error, XmlDocumentError::Parse(ParseError::DtdDetected)),
        "{error}"
    );

    let mut mirror = Mirror::new("<root/>");
    mirror.has_dtd = true;
    let allowing = VerificationPolicy {
        xml: XmlInputPolicy {
            allow_internal_dtd: true,
        },
        ..VerificationPolicy::default()
    };
    let document = project(mirror, &allowing);
    // A stricter operation later refuses the document the DTD made.
    assert!(document.validate_xml_input_policy(false).is_err());
}

#[test]
fn entity_content_is_content_that_no_edit_can_address() {
    // XML 1.0 section 4.4.2: an included entity's replacement is part of the
    // document, but it has no node of its own in the instance to edit.
    let document = project(
        Scripted(|sink| {
            sink.begin_element(ExternalNode(2), "root", None, None)?;
            sink.open_element()?;
            sink.enter_entity()?;
            sink.begin_element(ExternalNode(3), "expanded", None, None)?;
            sink.open_element()?;
            sink.end_element()?;
            sink.leave_entity()?;
            sink.end_element()
        }),
        &VerificationPolicy::default(),
    );
    document.with_view(|view| {
        let expanded = view
            .document()
            .root_element()
            .first_element_child()
            .expect("the entity's element is content");
        assert_eq!(expanded.tag_name().name(), "expanded");
        assert!(matches!(
            document.external_node(view.node_identity(expanded)),
            Err(XmlDocumentError::MissingNode)
        ));
    });
}
