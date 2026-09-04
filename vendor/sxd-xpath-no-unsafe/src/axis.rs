use std::fmt;

use crate::context;
use crate::expression::Error;
use crate::node_test::NodeTest;
use crate::nodeset::{self, Node, OrderedNodes};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PrincipalNodeType {
    Attribute,
    Element,
    Namespace,
}

/// A directed traversal of Nodes.
pub trait AxisLike: fmt::Debug {
    /// Applies the given node test to the nodes selected by this axis,
    /// adding matching nodes to the nodeset.
    fn select_nodes<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        node_test: &dyn NodeTest,
    ) -> Result<OrderedNodes<'d>, Error>;

    /// Describes what node type is naturally selected by this axis.
    fn principal_node_type(&self) -> PrincipalNodeType {
        PrincipalNodeType::Element
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Axis {
    Ancestor,
    AncestorOrSelf,
    Attribute,
    Namespace,
    Child,
    Descendant,
    DescendantOrSelf,
    Parent,
    PrecedingSibling,
    FollowingSibling,
    Preceding,
    Following,
    #[allow(clippy::enum_variant_names)]
    SelfAxis,
}

struct CompleteNodeTest<'c, 'd> {
    context: &'c context::Evaluation<'c, 'd>,
    node_test: &'c dyn NodeTest,
    result: OrderedNodes<'d>,
    error: Option<Error>,
}

impl<'c, 'd> CompleteNodeTest<'c, 'd> {
    fn new(context: &'c context::Evaluation<'c, 'd>, node_test: &'c dyn NodeTest) -> Self {
        CompleteNodeTest {
            context,
            node_test,
            result: OrderedNodes::new(),
            error: None,
        }
    }

    fn run(&mut self, node: Node<'d>) {
        if self.error.is_some() {
            return;
        }
        let new_context = self.context.new_context_for(node);
        if let Err(error) = self.node_test.test(&new_context, &mut self.result) {
            self.error = Some(error);
        }
    }
}

impl AxisLike for Axis {
    fn select_nodes<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        node_test: &dyn NodeTest,
    ) -> Result<OrderedNodes<'d>, Error> {
        use self::Axis::*;

        let mut node_test = CompleteNodeTest::new(context, node_test);

        match *self {
            Ancestor => each_parent(context.node.clone(), |n| node_test.run(n)),
            AncestorOrSelf => node_and_each_parent(context.node.clone(), |n| node_test.run(n)),
            Attribute => {
                if let Node::Element(ref e) = context.node {
                    for attr in e.attributes() {
                        node_test.run(Node::Attribute(attr));
                    }
                }
            }
            Namespace => {
                if let Node::Element(ref e) = context.node {
                    for ns in e
                        .namespaces_in_scope()
                        .into_iter()
                        .filter(|namespace| !namespace.uri().is_empty())
                    {
                        let ns = Node::Namespace(nodeset::Namespace {
                            parent: *e,
                            prefix: sxd_document_no_unsafe::to_ns_str!(ns.prefix()),
                            uri: sxd_document_no_unsafe::to_ns_str!(ns.uri()),
                        });

                        node_test.run(ns);
                    }
                }
            }
            Child => {
                for index in 0..context.node.children_len() {
                    let child = context
                        .node
                        .child_at(index)
                        .expect("child index is within the observed length");
                    node_test.run(child);
                }
            }
            Descendant => {
                for index in 0..context.node.children_len() {
                    let child = context
                        .node
                        .child_at(index)
                        .expect("child index is within the observed length");
                    preorder_left_to_right(context, child, |n| node_test.run(n))?;
                }
            }
            DescendantOrSelf => {
                preorder_left_to_right(context, context.node.clone(), |n| node_test.run(n))?
            }
            Parent => {
                if let Some(parent) = context.node.parent() {
                    node_test.run(parent);
                }
            }
            PrecedingSibling => {
                each_preceding_sibling(&context.node, |sibling| node_test.run(sibling));
            }
            FollowingSibling => {
                each_following_sibling(&context.node, |sibling| node_test.run(sibling));
            }
            Preceding => node_and_each_parent_before(
                context.node.clone(),
                context.document_root_for(context.node.clone()),
                |node| {
                    each_preceding_sibling(&node, |sibling| {
                        if node_test.error.is_none()
                            && let Err(error) =
                                postorder_right_to_left(context, sibling, |n| node_test.run(n))
                        {
                            node_test.error = Some(error);
                        }
                    });
                },
            ),
            Following => {
                let document_root = context.document_root_for(context.node.clone());
                let mut traversal_root = context.node.clone();
                if matches!(traversal_root, Node::Attribute(_) | Node::Namespace(_))
                    && let Some(owner) = traversal_root.parent()
                {
                    // XPath 1.0 section 5 orders namespace and attribute nodes before children.
                    // Owner descendants are therefore following, not descendants, of either
                    // non-child context node: https://www.w3.org/TR/xpath/#data-model
                    for index in 0..owner.children_len() {
                        let child = owner
                            .child_at(index)
                            .expect("child index is within the observed length");
                        preorder_left_to_right(context, child, |node| node_test.run(node))?;
                    }
                    traversal_root = owner;
                }
                node_and_each_parent_before(traversal_root, document_root, |node| {
                    each_following_sibling(&node, |sibling| {
                        if node_test.error.is_none()
                            && let Err(error) =
                                preorder_left_to_right(context, sibling, |n| node_test.run(n))
                        {
                            node_test.error = Some(error);
                        }
                    });
                });
            }
            SelfAxis => node_test.run(context.node.clone()),
        }

        node_test.error.map_or(Ok(node_test.result), Err)
    }

    fn principal_node_type(&self) -> PrincipalNodeType {
        use self::Axis::*;
        match *self {
            Attribute => PrincipalNodeType::Attribute,
            Namespace => PrincipalNodeType::Namespace,
            _ => PrincipalNodeType::Element,
        }
    }
}

fn preorder_left_to_right<'c, 'd, F>(
    context: &context::Evaluation<'c, 'd>,
    node: Node<'d>,
    mut f: F,
) -> Result<(), Error>
where
    F: FnMut(Node<'d>),
{
    let mut stack = Vec::new();
    push_traversal_frame(&mut stack, context, (node, 0))?;
    while let Some((current, next_child)) = stack.last_mut() {
        if *next_child == 0 {
            f(current.clone());
        }
        if let Some(child) = current.child_at(*next_child) {
            *next_child += 1;
            push_traversal_frame(&mut stack, context, (child, 0))?;
        } else {
            stack.pop();
        }
    }
    Ok(())
}

fn postorder_right_to_left<'c, 'd, F>(
    context: &context::Evaluation<'c, 'd>,
    node: Node<'d>,
    mut f: F,
) -> Result<(), Error>
where
    F: FnMut(Node<'d>),
{
    let last_child = node.children_len();
    let mut stack = Vec::new();
    push_traversal_frame(&mut stack, context, (node, last_child))?;
    while let Some((current, next_child)) = stack.last_mut() {
        if *next_child > 0 {
            *next_child -= 1;
            let child = current
                .child_at(*next_child)
                .expect("child index is within the observed length");
            let last_child = child.children_len();
            push_traversal_frame(&mut stack, context, (child, last_child))?;
        } else {
            let (current, _) = stack.pop().expect("stack is known to be non-empty");
            f(current);
        }
    }
    Ok(())
}

fn push_traversal_frame<'c, 'd>(
    stack: &mut Vec<(Node<'d>, usize)>,
    context: &context::Evaluation<'c, 'd>,
    frame: (Node<'d>, usize),
) -> Result<(), Error> {
    if stack.len() == stack.capacity() {
        let additional = stack.capacity().max(4);
        context
            .reserve_temporary_allocation(
                additional.saturating_mul(std::mem::size_of::<(Node<'d>, usize)>()),
            )
            .map_err(|source| Error::FunctionEvaluation { source })?;
        stack
            .try_reserve_exact(additional)
            .map_err(|_| Error::FunctionEvaluation {
                source: crate::function::Error::Other {
                    what: "XPath axis traversal allocation failed".into(),
                },
            })?;
    }
    stack.push(frame);
    Ok(())
}

fn each_preceding_sibling<'d>(node: &Node<'d>, mut f: impl FnMut(Node<'d>)) {
    let Some((parent, index)) = child_position(node) else {
        return;
    };
    for index in (0..index).rev() {
        f(parent.child_at(index).expect("sibling index is in bounds"));
    }
}

fn each_following_sibling<'d>(node: &Node<'d>, mut f: impl FnMut(Node<'d>)) {
    let Some((parent, index)) = child_position(node) else {
        return;
    };
    for index in index + 1..parent.children_len() {
        f(parent.child_at(index).expect("sibling index is in bounds"));
    }
}

fn child_position<'d>(node: &Node<'d>) -> Option<(Node<'d>, usize)> {
    if matches!(
        node,
        Node::Root(_) | Node::Attribute(_) | Node::Namespace(_)
    ) {
        return None;
    }
    let parent = node.parent()?;
    (0..parent.children_len())
        .find(|index| parent.child_at(*index).as_ref() == Some(node))
        .map(|index| (parent, index))
}

fn node_and_each_parent<'d, F>(node: Node<'d>, mut f: F)
where
    F: FnMut(Node<'d>),
{
    let n = node.clone();
    f(n);
    each_parent(node, f);
}

fn node_and_each_parent_before<'d, F>(mut node: Node<'d>, boundary: Node<'d>, mut f: F)
where
    F: FnMut(Node<'d>),
{
    while node != boundary {
        f(node.clone());
        let Some(parent) = node.parent() else {
            break;
        };
        node = parent;
    }
}

fn each_parent<'d, F>(mut node: Node<'d>, mut f: F)
where
    F: FnMut(Node<'d>),
{
    while let Some(parent) = node.parent() {
        node = parent.clone();
        f(parent);
    }
}

#[cfg(test)]
mod test {
    use sxd_document_no_unsafe::Package;
    use sxd_document_no_unsafe::dom;

    use crate::context::{self, Context};
    use crate::node_test::NodeTest;
    use crate::nodeset::{Node, OrderedNodes};

    use super::Axis::*;
    use super::*;

    #[derive(Debug)]
    struct DummyNodeTest;
    impl NodeTest for DummyNodeTest {
        fn test<'c, 'd>(
            &self,
            context: &context::Evaluation<'c, 'd>,
            result: &mut OrderedNodes<'d>,
        ) -> Result<(), Error> {
            result.add(context.node.clone());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RejectNodeTest;

    impl NodeTest for RejectNodeTest {
        fn test<'c, 'd>(
            &self,
            _context: &context::Evaluation<'c, 'd>,
            _result: &mut OrderedNodes<'d>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    fn execute<'n, N>(axis: Axis, node: N) -> OrderedNodes<'n>
    where
        N: Into<Node<'n>>,
    {
        let context = Context::without_core_functions();
        let context = context::Evaluation::new(&context, node.into());
        let node_test = &DummyNodeTest;

        axis.select_nodes(&context, node_test)
            .expect("test node selection succeeds")
    }

    #[test]
    fn descendant_axis_meters_its_depth_stack_before_allocation() {
        // A node test that rejects everything isolates traversal workspace from result storage.
        let package = Package::new();
        let document = package.as_document();
        let root = document.root();
        let child = document.create_element("child");
        root.append_child(child);
        child.append_child(document.create_element("grandchild"));
        let mut context = Context::without_core_functions();
        context.set_string_allocation_limit(0);
        let evaluation = context::Evaluation::new(&context, root.into());

        assert!(
            Descendant
                .select_nodes(&evaluation, &RejectNodeTest)
                .is_err()
        );
    }

    #[test]
    fn ancestor_includes_parents() {
        let package = Package::new();
        let doc = package.as_document();

        let level0 = doc.root();
        let level1 = doc.create_element("b");
        let level2 = doc.create_text("c");

        level0.append_child(level1);
        level1.append_child(level2);

        let result = execute(Ancestor, level2);

        assert_eq!(result, ordered_nodes![level1, level0]);
    }

    #[test]
    fn ancestor_or_self_also_includes_self() {
        let package = Package::new();
        let doc = package.as_document();

        let level0 = doc.root();
        let level1 = doc.create_element("b");
        let level2 = doc.create_text("c");

        level0.append_child(level1);
        level1.append_child(level2);

        let result = execute(AncestorOrSelf, level2);

        assert_eq!(result, ordered_nodes![level2, level1, level0]);
    }

    #[test]
    fn descendant_includes_parents() {
        let package = Package::new();
        let doc = package.as_document();

        let level0 = doc.root();
        let level1 = doc.create_element("b");
        let level2 = doc.create_text("c");

        level0.append_child(level1);
        level1.append_child(level2);

        let result = execute(Descendant, level0);

        assert_eq!(result, ordered_nodes![level1, level2]);
    }

    #[test]
    fn descendant_or_self_also_includes_self() {
        let package = Package::new();
        let doc = package.as_document();

        let level0 = doc.root();
        let level1 = doc.create_element("b");
        let level2 = doc.create_text("c");

        level0.append_child(level1);
        level1.append_child(level2);

        let result = execute(DescendantOrSelf, level0);

        assert_eq!(result, ordered_nodes![level0, level1, level2]);
    }

    #[test]
    fn namespace_axis_excludes_empty_uri_undeclarations() {
        // An empty binding shadows an inherited prefix but is not itself an XPath namespace node.
        let package = Package::new();
        let doc = package.as_document();
        let parent = doc.create_element("parent");
        parent.register_prefix("", "urn:outer");
        let child = doc.create_element("child");
        child.register_prefix("", "");
        child.register_prefix("p", "urn:visible");
        parent.append_child(child);
        doc.root().append_child(parent);

        assert_eq!(execute(Namespace, child).size(), 2);
    }

    #[test]
    fn preceding_sibling_selects_in_reverse_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let root = doc.root();
        let child1 = doc.create_element("a");
        let child2 = doc.create_comment("b");
        let child3 = doc.create_processing_instruction("c", None);

        root.append_child(child1);
        root.append_child(child2);
        root.append_child(child3);

        let result = execute(PrecedingSibling, child3);

        assert_eq!(result, ordered_nodes![child2, child1]);
    }

    #[test]
    fn following_sibling_selects_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let root = doc.root();
        let child1 = doc.create_element("a");
        let child2 = doc.create_comment("b");
        let child3 = doc.create_processing_instruction("c", None);

        root.append_child(child1);
        root.append_child(child2);
        root.append_child(child3);

        let result = execute(FollowingSibling, child1);

        assert_eq!(result, ordered_nodes![child2, child3]);
    }

    // <a0>
    //   <b0>
    //     <c0 />
    //     <c1 />
    //   </b0>
    //   <b1>
    //     <c2 />
    //     <c3 />
    //     <c4 />
    //   </b1>
    //   <b2>
    //     <c5 />
    //     <c6 />
    //   </b2>
    // </a0>

    struct PrecedingFollowing<'d> {
        b: [dom::Element<'d>; 3],
        c: [dom::Element<'d>; 7],
        midpoint: dom::Element<'d>,
    }

    impl<'d> PrecedingFollowing<'d> {
        fn new(doc: dom::Document<'d>) -> Self {
            let a = doc.create_element("a");

            let b0 = doc.create_element("b0");
            let b1 = doc.create_element("b1");
            let b2 = doc.create_element("b2");

            let c0 = doc.create_element("c0");
            let c1 = doc.create_element("c1");
            let c2 = doc.create_element("c2");
            let c3 = doc.create_element("c3");
            let c4 = doc.create_element("c4");
            let c5 = doc.create_element("c5");
            let c6 = doc.create_element("c6");

            a.append_child(b0);
            a.append_child(b1);
            a.append_child(b2);

            b0.append_child(c0);
            b0.append_child(c1);

            b1.append_child(c2);
            b1.append_child(c3);
            b1.append_child(c4);

            b2.append_child(c5);
            b2.append_child(c6);

            PrecedingFollowing {
                midpoint: c3,
                b: [b0, b1, b2],
                c: [c0, c1, c2, c3, c4, c5, c6],
            }
        }
    }

    #[test]
    fn preceding_selects_in_reverse_document_order() {
        let package = Package::new();
        let doc = package.as_document();
        let PrecedingFollowing { b, c, midpoint } = PrecedingFollowing::new(doc);

        let result = execute(Preceding, midpoint);

        assert_eq!(result, ordered_nodes![c[2], c[1], c[0], b[0]]);
    }

    #[test]
    fn following_selects_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();
        let PrecedingFollowing { b, c, midpoint } = PrecedingFollowing::new(doc);

        let result = execute(Following, midpoint);

        assert_eq!(result, ordered_nodes![c[4], b[2], c[5], c[6]]);
    }
}
