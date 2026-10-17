//! Storage-specific construction behind the single mirror traversal.

use super::{QName, dom};
use crate::c14n::C14nError;

pub(crate) trait Construction<'d> {
    fn element(&self, name: QName<'_>) -> Result<dom::Element<'d>, C14nError>;
    fn attribute(
        &self,
        parent: dom::Element<'d>,
        name: QName<'_>,
        value: &str,
    ) -> Result<dom::Attribute<'d>, C14nError>;
    fn text(&self, value: &str) -> Result<dom::Text<'d>, C14nError>;
    fn comment(&self, value: &str) -> Result<dom::Comment<'d>, C14nError>;
    fn pi(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Result<dom::ProcessingInstruction<'d>, C14nError>;
    fn append_root(&self, child: dom::ChildOfRoot<'d>) -> Result<(), C14nError>;
    fn append_element(
        &self,
        parent: dom::Element<'d>,
        child: dom::ChildOfElement<'d>,
    ) -> Result<(), C14nError>;
    fn element_prefix(
        &self,
        element: dom::Element<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError>;
    fn attribute_prefix(
        &self,
        attribute: dom::Attribute<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError>;
    fn declarations<'a>(
        &self,
        element: dom::Element<'d>,
        declarations: impl Iterator<Item = (Option<&'a str>, &'a str)>,
    ) -> Result<(), C14nError>;
}

impl<'d> Construction<'d> for dom::Document<'d> {
    fn element(&self, name: QName<'_>) -> Result<dom::Element<'d>, C14nError> {
        Ok(self.create_element(name))
    }
    fn attribute(
        &self,
        parent: dom::Element<'d>,
        name: QName<'_>,
        value: &str,
    ) -> Result<dom::Attribute<'d>, C14nError> {
        Ok(parent.set_attribute_value(name, value))
    }
    fn text(&self, value: &str) -> Result<dom::Text<'d>, C14nError> {
        Ok(self.create_text(value))
    }
    fn comment(&self, value: &str) -> Result<dom::Comment<'d>, C14nError> {
        Ok(self.create_comment(value))
    }
    fn pi(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Result<dom::ProcessingInstruction<'d>, C14nError> {
        Ok(self.create_processing_instruction(target, value))
    }
    fn append_root(&self, child: dom::ChildOfRoot<'d>) -> Result<(), C14nError> {
        self.root().append_child(child);
        Ok(())
    }
    fn append_element(
        &self,
        parent: dom::Element<'d>,
        child: dom::ChildOfElement<'d>,
    ) -> Result<(), C14nError> {
        parent.append_child(child);
        Ok(())
    }
    fn element_prefix(
        &self,
        element: dom::Element<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError> {
        element.set_preferred_prefix(prefix);
        Ok(())
    }
    fn attribute_prefix(
        &self,
        attribute: dom::Attribute<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError> {
        attribute.set_preferred_prefix(prefix);
        Ok(())
    }
    fn declarations<'a>(
        &self,
        element: dom::Element<'d>,
        declarations: impl Iterator<Item = (Option<&'a str>, &'a str)>,
    ) -> Result<(), C14nError> {
        for (prefix, uri) in declarations {
            match prefix {
                Some(prefix) => element.register_prefix(prefix, uri),
                None if uri.is_empty() => {
                    // XPath 1.0 §5.4 excludes an empty default namespace node,
                    // not the declaration that shadows an ancestor binding.
                    // https://www.w3.org/TR/1999/REC-xpath-19991116/#namespace-nodes
                    element.set_default_namespace_uri(None);
                    element.register_prefix("", "");
                }
                None => {
                    element.set_default_namespace_uri(Some(uri));
                    element.register_prefix("", uri);
                }
            }
        }
        Ok(())
    }
}

impl<'d, W: structured_asn1::memory::Work> Construction<'d> for dom::current::Builder<'d, '_, W> {
    fn element(&self, name: QName<'_>) -> Result<dom::Element<'d>, C14nError> {
        self.element(name).map_err(Into::into)
    }
    fn attribute(
        &self,
        parent: dom::Element<'d>,
        name: QName<'_>,
        value: &str,
    ) -> Result<dom::Attribute<'d>, C14nError> {
        self.attribute(parent, name, value).map_err(Into::into)
    }
    fn text(&self, value: &str) -> Result<dom::Text<'d>, C14nError> {
        self.text(value).map_err(Into::into)
    }
    fn comment(&self, value: &str) -> Result<dom::Comment<'d>, C14nError> {
        self.comment(value).map_err(Into::into)
    }
    fn pi(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Result<dom::ProcessingInstruction<'d>, C14nError> {
        self.pi(target, value).map_err(Into::into)
    }
    fn append_root(&self, child: dom::ChildOfRoot<'d>) -> Result<(), C14nError> {
        self.append_root(child).map_err(Into::into)
    }
    fn append_element(
        &self,
        parent: dom::Element<'d>,
        child: dom::ChildOfElement<'d>,
    ) -> Result<(), C14nError> {
        self.append_element(parent, child).map_err(Into::into)
    }
    fn element_prefix(
        &self,
        element: dom::Element<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError> {
        self.element_prefix(element, prefix).map_err(Into::into)
    }
    fn attribute_prefix(
        &self,
        attribute: dom::Attribute<'d>,
        prefix: Option<&str>,
    ) -> Result<(), C14nError> {
        self.attribute_prefix(attribute, prefix).map_err(Into::into)
    }
    fn declarations<'a>(
        &self,
        element: dom::Element<'d>,
        declarations: impl Iterator<Item = (Option<&'a str>, &'a str)>,
    ) -> Result<(), C14nError> {
        self.namespace_declarations(element, declarations)
            .map_err(Into::into)
    }
}
