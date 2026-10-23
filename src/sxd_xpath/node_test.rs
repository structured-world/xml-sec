#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use std::fmt;

use sxd_document_no_unsafe::QName;

use crate::context;
use crate::expression::Error;
use crate::nodeset;
#[cfg(test)]
use crate::nodeset::OrderedNodes;

pub trait NodeTest: fmt::Debug {
    fn validate(&self, _context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        Ok(())
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error>;

    #[cfg(test)]
    fn test<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        result: &mut OrderedNodes<'d>,
    ) -> Result<(), Error> {
        if self.matches(context)? {
            result
                .add_metered(context, context.node.clone())
                .map_err(|source| Error::FunctionEvaluation { source })?;
        }
        Ok(())
    }
}

impl<T: ?Sized> NodeTest for Box<T>
where
    T: NodeTest,
{
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        (**self).validate(context)
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        (**self).matches(context)
    }
}

// XPath 1.0 §2.3 defines a closed set of node tests. Store that grammar
// directly in each path step rather than allocating a trait object per step.
// https://www.w3.org/TR/1999/REC-xpath-19991116/#node-tests
#[derive(Debug)]
pub enum SubNodeTest<T = String> {
    Node,
    Text,
    Comment,
    ProcessingInstruction(ProcessingInstruction<T>),
    Attribute(Attribute<T>),
    Element(Element<T>),
    Namespace(Namespace<T>),
}

impl<T> From<super::grammar::Test<T>> for SubNodeTest<T> {
    fn from(test: super::grammar::Test<T>) -> Self {
        use super::grammar::Test;
        use crate::axis::PrincipalNodeType;
        use crate::token::NodeTestName;
        match test {
            Test::Kind(NodeTestName::Node) => Self::Node,
            Test::Kind(NodeTestName::Text) => Self::Text,
            Test::Kind(NodeTestName::Comment) => Self::Comment,
            Test::Kind(NodeTestName::ProcessingInstruction(target)) => {
                Self::ProcessingInstruction(ProcessingInstruction::for_target(target))
            }
            Test::Name(PrincipalNodeType::Attribute, name) => Self::Attribute(Attribute::new(name)),
            Test::Name(PrincipalNodeType::Element, name) => Self::Element(Element::new(name)),
            Test::Name(PrincipalNodeType::Namespace, name) => Self::Namespace(Namespace::new(name)),
        }
    }
}

impl<T: AsRef<str> + std::fmt::Debug> NodeTest for SubNodeTest<T> {
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        match self {
            Self::Attribute(test) => test.validate(context),
            Self::Element(test) => test.validate(context),
            Self::Namespace(test) => test.validate(context),
            Self::Node | Self::Text | Self::Comment | Self::ProcessingInstruction(_) => Ok(()),
        }
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        match self {
            Self::Node => Node.matches(context),
            Self::Text => Text.matches(context),
            Self::Comment => Comment.matches(context),
            Self::ProcessingInstruction(test) => test.matches(context),
            Self::Attribute(test) => test.matches(context),
            Self::Element(test) => test.matches(context),
            Self::Namespace(test) => test.matches(context),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NameTest<T = String> {
    pub prefix: Option<T>,
    pub local_part: T,
}

impl<T: AsRef<str>> NameTest<T> {
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        if let Some(prefix) = &self.prefix
            && context
                .namespace_for(prefix.as_ref())
                .map_err(|source| Error::FunctionEvaluation { source })?
                .is_none()
        {
            return Err(Error::UnknownNamespace {
                prefix: prefix.as_ref().to_owned(),
            });
        }
        Ok(())
    }

    fn matches(
        &self,
        context: &context::Evaluation<'_, '_>,
        node_name: QName<'_>,
    ) -> Result<bool, Error> {
        let is_wildcard = self.local_part.as_ref() == "*";

        let test_uri = self
            .prefix
            .as_ref()
            .map(|prefix| {
                context
                    .namespace_for(prefix.as_ref())
                    .map_err(|source| Error::FunctionEvaluation { source })?
                    .ok_or_else(|| Error::UnknownNamespace {
                        prefix: prefix.as_ref().to_owned(),
                    })
            })
            .transpose()?;

        Ok(match (is_wildcard, test_uri) {
            (true, None) => true,
            (true, Some(..)) => test_uri == node_name.namespace_uri(),
            _ => {
                test_uri == node_name.namespace_uri()
                    && self.local_part.as_ref() == node_name.local_part()
            }
        })
    }
}

#[derive(Debug)]
pub struct Attribute<T = String> {
    name_test: NameTest<T>,
}

impl<T> Attribute<T> {
    pub fn new(name: NameTest<T>) -> Self {
        Attribute { name_test: name }
    }
}

impl<T: AsRef<str> + std::fmt::Debug> NodeTest for Attribute<T> {
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        self.name_test.validate(context)
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        if let nodeset::Node::Attribute(ref a) = context.node {
            return self
                .name_test
                .matches(context, sxd_document_no_unsafe::as_qname!(a.name()));
        }
        Ok(false)
    }
}

#[derive(Debug)]
pub struct Namespace<T = String> {
    name_test: NameTest<T>,
}

impl<T> Namespace<T> {
    pub fn new(name: NameTest<T>) -> Self {
        Namespace { name_test: name }
    }
}

impl<T: AsRef<str> + std::fmt::Debug> NodeTest for Namespace<T> {
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        self.name_test.validate(context)
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        if let nodeset::Node::Namespace(ref ns) = context.node {
            return self.name_test.matches(context, QName::new(ns.prefix()));
        }
        Ok(false)
    }
}

#[derive(Debug)]
pub struct Element<T = String> {
    name_test: NameTest<T>,
}

impl<T> Element<T> {
    pub fn new(name: NameTest<T>) -> Self {
        Element { name_test: name }
    }
}

impl<T: AsRef<str> + std::fmt::Debug> NodeTest for Element<T> {
    fn validate(&self, context: &context::Evaluation<'_, '_>) -> Result<(), Error> {
        self.name_test.validate(context)
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        if let nodeset::Node::Element(ref e) = context.node {
            return self
                .name_test
                .matches(context, sxd_document_no_unsafe::as_qname!(e.name()));
        }
        Ok(false)
    }
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct Node;

impl NodeTest for Node {
    fn matches(&self, _: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        Ok(true)
    }
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct Text;

impl NodeTest for Text {
    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        Ok(matches!(context.node, nodeset::Node::Text(_)))
    }
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct Comment;

impl NodeTest for Comment {
    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        Ok(matches!(context.node, nodeset::Node::Comment(_)))
    }
}

#[derive(Debug)]
pub struct ProcessingInstruction<T = String> {
    target: Option<T>,
}

impl<T> ProcessingInstruction<T> {
    fn for_target(target: Option<T>) -> Self {
        ProcessingInstruction { target }
    }
}

impl<T: AsRef<str> + std::fmt::Debug> NodeTest for ProcessingInstruction<T> {
    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        if let nodeset::Node::ProcessingInstruction(pi) = &context.node {
            return Ok(self
                .target
                .as_ref()
                .is_none_or(|name| name.as_ref() == sxd_document_no_unsafe::as_str!(pi.target())));
        }
        Ok(false)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::ToOwned;

    use sxd_document_no_unsafe::dom::{self, Document};
    use sxd_document_no_unsafe::{Package, QName};

    use crate::context::{self, Context};
    use crate::nodeset::OrderedNodes;

    use super::*;

    struct Setup<'d> {
        doc: Document<'d>,
        context: Context<'d>,
    }

    impl<'d> Setup<'d> {
        fn new(package: &'d Package) -> Setup<'d> {
            Setup {
                doc: package.as_document(),
                context: Context::without_core_functions(),
            }
        }

        fn register_prefix(&mut self, prefix: &str, namespace_uri: &str) {
            self.context.set_namespace(prefix, namespace_uri);
        }

        fn context_for_attribute<'n, N>(
            &self,
            name: N,
            val: &str,
        ) -> (dom::Attribute<'d>, context::Evaluation<'_, 'd>)
        where
            N: Into<QName<'n>>,
        {
            let e = self.doc.create_element("element");
            let a = e.set_attribute_value(name, val);
            let c = context::Evaluation::new(&self.context, a.into());
            (a, c)
        }

        fn context_for_ns_attribute(
            &mut self,
            prefix: &str,
            nsuri: &str,
            local: &str,
            value: &str,
        ) -> (dom::Attribute<'d>, context::Evaluation<'_, 'd>) {
            self.register_prefix(prefix, nsuri);
            self.context_for_attribute((nsuri, local), value)
        }

        fn context_for_element<'n, N>(
            &self,
            name: N,
        ) -> (dom::Element<'d>, context::Evaluation<'_, 'd>)
        where
            N: Into<QName<'n>>,
        {
            let e = self.doc.create_element(name);
            let c = context::Evaluation::new(&self.context, e.into());
            (e, c)
        }

        fn context_for_ns_element(
            &mut self,
            prefix: &str,
            nsuri: &str,
            local: &str,
        ) -> (dom::Element<'d>, context::Evaluation<'_, 'd>) {
            self.register_prefix(prefix, nsuri);
            self.context_for_element((nsuri, local))
        }
    }

    fn run_attribute<'d>(
        context: &context::Evaluation<'_, 'd>,
        prefix: Option<&str>,
        local: &str,
    ) -> OrderedNodes<'d> {
        let mut result = OrderedNodes::new();
        let name = NameTest {
            prefix: prefix.map(str::to_owned),
            local_part: local.to_owned(),
        };
        let test = Attribute::new(name);
        test.test(context, &mut result)
            .expect("node test evaluates");
        result
    }

    #[test]
    fn attribute_test_selects_attributes_with_matching_names() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (attribute, context) = setup.context_for_attribute("hello", "world");

        let result = run_attribute(&context, None, "hello");
        assert_eq!(ordered_nodes![attribute], result);
    }

    #[test]
    fn attribute_test_does_not_select_other_names() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (_, context) = setup.context_for_attribute("goodbye", "world");

        let result = run_attribute(&context, None, "hello");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn attribute_test_supports_a_wildcard_match() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (attribute, context) = setup.context_for_attribute("whatever", "value");

        let result = run_attribute(&context, None, "*");
        assert_eq!(ordered_nodes![attribute], result);
    }

    #[test]
    fn attribute_test_matches_on_namespace_and_name() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.register_prefix("another", "different-uri");
        let (attribute, context) =
            setup.context_for_ns_attribute("prefix", "namespace", "name", "value");

        let result = run_attribute(&context, Some("prefix"), "name");
        assert_eq!(ordered_nodes![attribute], result);

        let result = run_attribute(&context, Some("prefix"), "wrong-name");
        assert_eq!(ordered_nodes![], result);

        let result = run_attribute(&context, Some("another"), "name");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn attribute_test_matches_on_namespace_when_wildcard_with_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.register_prefix("another", "different-uri");
        let (attribute, context) =
            setup.context_for_ns_attribute("prefix", "namespace", "name", "value");

        let result = run_attribute(&context, Some("prefix"), "*");
        assert_eq!(ordered_nodes![attribute], result);

        let result = run_attribute(&context, Some("another"), "*");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn attribute_test_ignores_namespace_when_wildcard_without_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let (attribute, context) =
            setup.context_for_ns_attribute("prefix", "namespace", "name", "value");

        let result = run_attribute(&context, None, "*");
        assert_eq!(ordered_nodes![attribute], result);
    }

    #[test]
    fn attribute_test_does_not_match_when_attribute_has_namespace_but_without_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let (_, context) = setup.context_for_ns_attribute("prefix", "namespace", "name", "value");

        let result = run_attribute(&context, None, "name");
        assert_eq!(ordered_nodes![], result);
    }

    fn run_element<'d>(
        context: &context::Evaluation<'_, 'd>,
        prefix: Option<&str>,
        local: &str,
    ) -> OrderedNodes<'d> {
        let mut result = OrderedNodes::new();
        let name = NameTest {
            prefix: prefix.map(str::to_owned),
            local_part: local.to_owned(),
        };
        let test = Element::new(name);
        test.test(context, &mut result)
            .expect("node test evaluates");
        result
    }

    #[test]
    fn element_test_selects_nodes_with_matching_names() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (element, context) = setup.context_for_element("hello");

        let result = run_element(&context, None, "hello");
        assert_eq!(ordered_nodes![element], result);
    }

    #[test]
    fn element_test_does_not_select_other_names() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (_, context) = setup.context_for_element("goodbye");

        let result = run_element(&context, None, "hello");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn element_test_supports_a_wildcard_match() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let (element, context) = setup.context_for_element("hello");

        let result = run_element(&context, None, "*");
        assert_eq!(ordered_nodes![element], result);
    }

    #[test]
    fn element_test_matches_on_namespace_and_name() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.register_prefix("another", "different-uri");
        let (element, context) = setup.context_for_ns_element("prefix", "uri", "name");

        let result = run_element(&context, Some("prefix"), "name");
        assert_eq!(ordered_nodes![element], result);

        let result = run_element(&context, Some("prefix"), "wrong-name");
        assert_eq!(ordered_nodes![], result);

        let result = run_element(&context, Some("another"), "name");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn element_test_matches_on_namespace_when_wildcard_with_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.register_prefix("another", "different-uri");
        let (element, context) = setup.context_for_ns_element("prefix", "uri", "name");

        let result = run_element(&context, Some("prefix"), "*");
        assert_eq!(ordered_nodes![element], result);

        let result = run_element(&context, Some("another"), "*");
        assert_eq!(ordered_nodes![], result);
    }

    #[test]
    fn element_test_ignores_namespace_when_wildcard_without_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let (element, context) = setup.context_for_ns_element("prefix", "uri", "name");

        let result = run_element(&context, None, "*");
        assert_eq!(ordered_nodes![element], result);
    }

    #[test]
    fn element_test_does_not_match_when_element_has_namespace_but_without_prefix() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let (_, context) = setup.context_for_ns_element("prefix", "uri", "name");

        let result = run_element(&context, None, "name");
        assert_eq!(ordered_nodes![], result);
    }
}
