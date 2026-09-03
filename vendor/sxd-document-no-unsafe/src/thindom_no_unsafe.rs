use std::{fmt, hash, marker::PhantomData};

use super::{QName, raw};
use crate::string_pool::InternedString;

pub struct Storage<'d> {
    storage: &'d raw::Storage,
}

impl<'d> Storage<'d> {
    pub fn new(storage: &raw::Storage) -> Storage<'_> {
        Storage { storage }
    }

    pub fn create_element<'n, N>(&'d self, name: N) -> Element<'d>
    where
        N: Into<QName<'n>>,
    {
        Element::wrap(self.storage.create_element(name))
    }

    pub fn create_attribute<'n, N>(&'d self, name: N, value: &str) -> Attribute<'d>
    where
        N: Into<QName<'n>>,
    {
        Attribute::wrap(self.storage.create_attribute(name, value))
    }

    pub fn create_text(&'d self, text: &str) -> Text<'d> {
        Text::wrap(self.storage.create_text(text))
    }

    pub fn create_comment(&'d self, text: &str) -> Comment<'d> {
        Comment::wrap(self.storage.create_comment(text))
    }

    pub fn create_processing_instruction(
        &'d self,
        target: &str,
        value: Option<&str>,
    ) -> ProcessingInstruction<'d> {
        ProcessingInstruction::wrap(self.storage.create_processing_instruction(target, value))
    }

    pub fn element_set_name<'n, N>(&self, element: Element<'_>, name: N)
    where
        N: Into<QName<'n>>,
    {
        self.storage.element_set_name(element.node, name)
    }

    pub fn text_set_text(&self, text: Text<'_>, new_text: &str) {
        self.storage.text_set_text(text.node, new_text)
    }

    pub fn comment_set_text(&self, comment: Comment<'_>, new_text: &str) {
        self.storage.comment_set_text(comment.node, new_text)
    }

    pub fn processing_instruction_set_target(
        &self,
        pi: ProcessingInstruction<'_>,
        new_target: &str,
    ) {
        self.storage
            .processing_instruction_set_target(pi.node, new_target)
    }

    pub fn processing_instruction_set_value(
        &self,
        pi: ProcessingInstruction<'_>,
        new_value: Option<&str>,
    ) {
        self.storage
            .processing_instruction_set_value(pi.node, new_value)
    }
}

pub struct Connections<'d> {
    connections: &'d raw::Connections,
    storage: &'d raw::Storage,
}

impl<'d> Connections<'d> {
    pub fn new(connections: &'d raw::Connections, storage: &'d raw::Storage) -> Connections<'d> {
        Connections {
            connections,
            storage,
        }
    }

    pub fn root(&self) -> Root<'d> {
        Root::wrap(self.connections.root())
    }

    pub fn element_parent(&self, child: Element<'d>) -> Option<ParentOfChild<'d>> {
        self.connections
            .element_parent(self.storage, child.node)
            .map(ParentOfChild::wrap)
    }

    pub fn text_parent(&self, child: Text<'d>) -> Option<Element<'d>> {
        self.connections
            .text_parent(self.storage, child.node)
            .map(Element::wrap)
    }

    pub fn comment_parent(&self, child: Comment<'d>) -> Option<ParentOfChild<'d>> {
        self.connections
            .comment_parent(self.storage, child.node)
            .map(ParentOfChild::wrap)
    }

    pub fn processing_instruction_parent(
        &self,
        child: ProcessingInstruction<'d>,
    ) -> Option<ParentOfChild<'d>> {
        self.connections
            .processing_instruction_parent(self.storage, child.node)
            .map(ParentOfChild::wrap)
    }

    pub fn append_root_child<C>(&mut self, child: C)
    where
        C: Into<ChildOfRoot<'d>>,
    {
        let child = child.into();
        self.connections
            .append_root_child(self.storage, child.as_raw())
    }

    pub fn append_element_child<C>(&mut self, parent: Element<'d>, child: C)
    where
        C: Into<ChildOfElement<'d>>,
    {
        let child = child.into();
        self.connections
            .append_element_child(self.storage, parent.node, child.as_raw())
    }

    pub fn root_children(&self) -> Vec<ChildOfRoot<'d>> {
        self.connections
            .root_children(self.storage)
            .into_iter()
            .map(ChildOfRoot::wrap)
            .collect()
    }

    pub fn element_children(&self, parent: Element<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .element_children(self.storage, parent.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn element_preceding_siblings(&self, element: Element<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .element_preceding_siblings(self.storage, element.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn element_following_siblings(&self, element: Element<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .element_following_siblings(self.storage, element.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn text_preceding_siblings(&self, text: Text<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .text_preceding_siblings(self.storage, text.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn text_following_siblings(&self, text: Text<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .text_following_siblings(self.storage, text.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn comment_preceding_siblings(&self, comment: Comment<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .comment_preceding_siblings(self.storage, comment.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn comment_following_siblings(&self, comment: Comment<'_>) -> Vec<ChildOfElement<'d>> {
        self.connections
            .comment_following_siblings(self.storage, comment.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn processing_instruction_preceding_siblings(
        &self,
        pi: ProcessingInstruction<'_>,
    ) -> Vec<ChildOfElement<'d>> {
        self.connections
            .processing_instruction_preceding_siblings(self.storage, pi.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn processing_instruction_following_siblings(
        &self,
        pi: ProcessingInstruction<'_>,
    ) -> Vec<ChildOfElement<'d>> {
        self.connections
            .processing_instruction_following_siblings(self.storage, pi.node)
            .into_iter()
            .map(ChildOfElement::wrap)
            .collect()
    }

    pub fn attribute_parent(&self, attribute: Attribute<'d>) -> Option<Element<'d>> {
        self.connections
            .attribute_parent(self.storage, attribute.node)
            .map(Element::wrap)
    }

    pub fn attributes(&self, parent: Element<'d>) -> Vec<Attribute<'d>> {
        self.connections
            .attributes(self.storage, parent.node)
            .into_iter()
            .map(Attribute::wrap)
            .collect()
    }

    pub fn set_attribute(&mut self, parent: Element<'d>, attribute: Attribute<'d>) {
        self.connections
            .set_attribute(self.storage, parent.node, attribute.node);
    }

    pub fn attribute_value(&self, parent: Element<'d>, name: &str) -> Option<InternedString> {
        self.connections
            .attribute(self.storage, parent.node, name)
            .map(|a| self.storage.attribute_value(a))
    }
}

macro_rules! node(
    ($name:ident, $raw:ty) => (
        #[derive(Copy, Clone)]
        pub struct $name<'d> {
            node: raw::Index<$raw>,
            lifetime: PhantomData<Storage<'d>>,
        }

        impl<'d> $name<'d> {
            fn wrap(node: raw::Index<$raw>) -> $name<'d> {
                $name {
                    node,
                    lifetime: PhantomData,
                }
            }
        }

        impl<'d> PartialEq for $name<'d> {
            fn eq(&self, other: &$name<'d>) -> bool {
                self.node == other.node
            }
        }

        impl<'d> Eq for $name<'d> {}

        impl<'d> hash::Hash for $name<'d> {
            fn hash<H>(&self, state: &mut H)
                where H: hash::Hasher
            {
                self.node.hash(state)
            }
        }
    )
);

node!(Root, raw::Root);

impl<'d> fmt::Debug for Root<'d> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Root")
    }
}

node!(Element, raw::Element);

impl<'d> Element<'d> {
    pub fn name(self, storage: &Storage<'_>) -> raw::QNameValue {
        storage.storage.element_name(self.node)
    }
}

impl<'d> fmt::Debug for Element<'d> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Element {{ idx: {:?} }}", self.node)
    }
}

node!(Attribute, raw::Attribute);

impl<'d> Attribute<'d> {
    pub fn name(&self, storage: &Storage<'_>) -> raw::QNameValue {
        storage.storage.attribute_name(self.node)
    }
    pub fn value(&self, storage: &Storage<'_>) -> InternedString {
        storage.storage.attribute_value(self.node)
    }
}

impl<'d> fmt::Debug for Attribute<'d> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Attribute {{ idx: {:?} }}", self.node)
    }
}

node!(Text, raw::Text);

impl<'d> Text<'d> {
    pub fn text(&self, storage: &Storage<'_>) -> InternedString {
        storage.storage.text_text(self.node)
    }
}

impl<'d> fmt::Debug for Text<'d> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Text {{ idx: {:?} }}", self.node)
    }
}

node!(Comment, raw::Comment);

impl<'d> Comment<'d> {
    pub fn text(&self, storage: &Storage<'_>) -> InternedString {
        storage.storage.comment_text(self.node)
    }
}

impl<'d> fmt::Debug for Comment<'d> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Comment {{ idx: {:?} }}", self.node)
    }
}

node!(ProcessingInstruction, raw::ProcessingInstruction);

impl<'d> ProcessingInstruction<'d> {
    pub fn target(self, storage: &Storage<'_>) -> InternedString {
        storage.storage.pi_target(self.node)
    }
    pub fn value(self, storage: &Storage<'_>) -> Option<InternedString> {
        storage.storage.pi_value(self.node)
    }
}

impl<'d> fmt::Debug for ProcessingInstruction<'d> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProcessingInstruction {{ idx: {:?} }}", self.node)
    }
}

macro_rules! unpack(
    ($enum_name:ident, $name:ident, $wrapper:ident, $inner:ident) => (
        pub fn $name(self) -> Option<$inner<'d>> {
            match self {
                $enum_name::$wrapper(n) => Some(n),
                _ => None,
            }
        }
    )
);

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ChildOfRoot<'d> {
    Element(Element<'d>),
    Comment(Comment<'d>),
    ProcessingInstruction(ProcessingInstruction<'d>),
}

impl<'d> ChildOfRoot<'d> {
    unpack!(ChildOfRoot, element, Element, Element);
    unpack!(ChildOfRoot, comment, Comment, Comment);
    unpack!(
        ChildOfRoot,
        processing_instruction,
        ProcessingInstruction,
        ProcessingInstruction
    );

    pub fn wrap(node: raw::ChildOfRoot) -> ChildOfRoot<'d> {
        match node {
            raw::ChildOfRoot::Element(n) => ChildOfRoot::Element(Element::wrap(n)),
            raw::ChildOfRoot::Comment(n) => ChildOfRoot::Comment(Comment::wrap(n)),
            raw::ChildOfRoot::ProcessingInstruction(n) => {
                ChildOfRoot::ProcessingInstruction(ProcessingInstruction::wrap(n))
            }
        }
    }

    pub fn as_raw(&self) -> raw::ChildOfRoot {
        match *self {
            ChildOfRoot::Element(n) => raw::ChildOfRoot::Element(n.node),
            ChildOfRoot::Comment(n) => raw::ChildOfRoot::Comment(n.node),
            ChildOfRoot::ProcessingInstruction(n) => {
                raw::ChildOfRoot::ProcessingInstruction(n.node)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ChildOfElement<'d> {
    Element(Element<'d>),
    Text(Text<'d>),
    Comment(Comment<'d>),
    ProcessingInstruction(ProcessingInstruction<'d>),
}

impl<'d> ChildOfElement<'d> {
    unpack!(ChildOfElement, element, Element, Element);
    unpack!(ChildOfElement, text, Text, Text);
    unpack!(ChildOfElement, comment, Comment, Comment);
    unpack!(
        ChildOfElement,
        processing_instruction,
        ProcessingInstruction,
        ProcessingInstruction
    );

    pub fn wrap(node: raw::ChildOfElement) -> ChildOfElement<'d> {
        match node {
            raw::ChildOfElement::Element(n) => ChildOfElement::Element(Element::wrap(n)),
            raw::ChildOfElement::Text(n) => ChildOfElement::Text(Text::wrap(n)),
            raw::ChildOfElement::Comment(n) => ChildOfElement::Comment(Comment::wrap(n)),
            raw::ChildOfElement::ProcessingInstruction(n) => {
                ChildOfElement::ProcessingInstruction(ProcessingInstruction::wrap(n))
            }
        }
    }

    pub fn as_raw(&self) -> raw::ChildOfElement {
        match *self {
            ChildOfElement::Element(n) => raw::ChildOfElement::Element(n.node),
            ChildOfElement::Text(n) => raw::ChildOfElement::Text(n.node),
            ChildOfElement::Comment(n) => raw::ChildOfElement::Comment(n.node),
            ChildOfElement::ProcessingInstruction(n) => {
                raw::ChildOfElement::ProcessingInstruction(n.node)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ParentOfChild<'d> {
    Root(Root<'d>),
    Element(Element<'d>),
}

impl<'d> ParentOfChild<'d> {
    unpack!(ParentOfChild, root, Root, Root);
    unpack!(ParentOfChild, element, Element, Element);

    pub fn wrap(node: raw::ParentOfChild) -> ParentOfChild<'d> {
        match node {
            raw::ParentOfChild::Root(n) => ParentOfChild::Root(Root::wrap(n)),
            raw::ParentOfChild::Element(n) => ParentOfChild::Element(Element::wrap(n)),
        }
    }
}

macro_rules! conversion_trait(
    ($res_type:ident, {
        $($leaf_type:ident => $variant:expr),*
    }) => (
        $(impl<'d> From<$leaf_type<'d>> for $res_type<'d>{
            fn from(other: $leaf_type<'d>) -> $res_type<'d> {
                $variant(other)
            }
        })*
    )
);

conversion_trait!(
    ChildOfRoot, {
        Element               => ChildOfRoot::Element,
        Comment               => ChildOfRoot::Comment,
        ProcessingInstruction => ChildOfRoot::ProcessingInstruction
    }
);

conversion_trait!(
    ChildOfElement, {
        Element               => ChildOfElement::Element,
        Text                  => ChildOfElement::Text,
        Comment               => ChildOfElement::Comment,
        ProcessingInstruction => ChildOfElement::ProcessingInstruction
    }
);

impl<'d> From<ChildOfRoot<'d>> for ChildOfElement<'d> {
    fn from(val: ChildOfRoot<'d>) -> Self {
        match val {
            ChildOfRoot::Element(n) => ChildOfElement::Element(n),
            ChildOfRoot::Comment(n) => ChildOfElement::Comment(n),
            ChildOfRoot::ProcessingInstruction(n) => ChildOfElement::ProcessingInstruction(n),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{Package, QName},
        ChildOfElement, ChildOfRoot, ParentOfChild,
    };

    macro_rules! assert_qname_eq(
        ($l:expr, $r:expr) => (assert_eq!($l.get(), Into::<QName<'_>>::into($r)));
    );

    #[test]
    fn root_can_have_element_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("alpha");
        c.append_root_child(element);
        let children = c.root_children();
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfRoot::Element(element));
    }

    #[test]
    fn root_child_knows_its_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let alpha = s.create_element("alpha");
        c.append_root_child(alpha);
        assert_eq!(Some(ParentOfChild::Root(c.root())), c.element_parent(alpha));
    }

    #[test]
    fn elements_can_have_element_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let alpha = s.create_element("alpha");
        let beta = s.create_element("beta");
        c.append_element_child(alpha, beta);
        let children = c.element_children(alpha);
        assert_eq!(children[0], ChildOfElement::Element(beta));
    }

    #[test]
    fn elements_can_be_renamed() {
        let package = Package::new();
        let (s, _c) = package.as_thin_document();
        let alpha = s.create_element("alpha");
        s.element_set_name(alpha, "beta");
        assert_qname_eq!(alpha.name(&s), "beta");
    }

    #[test]
    fn elements_have_attributes() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let attr = s.create_attribute("hello", "world");
        c.set_attribute(element, attr);
        assert_eq!(&*c.attribute_value(element, "hello").unwrap(), "world");
    }

    #[test]
    fn text_can_be_changed() {
        let package = Package::new();
        let (s, _c) = package.as_thin_document();
        let text = s.create_text("Now is the winter of our discontent.");
        s.text_set_text(text, "Made glorious summer by this sun of York");
        assert_eq!(&*text.text(&s), "Made glorious summer by this sun of York");
    }

    #[test]
    fn can_return_a_populated_package() {
        fn populate() -> Package {
            let package = Package::new();
            {
                let (s, mut c) = package.as_thin_document();
                let element = s.create_element("hello");
                c.append_root_child(element);
            }
            package
        }
        let package = populate();
        let (s, c) = package.as_thin_document();
        let children = c.root_children();
        let element = children[0].element().unwrap();
        assert_qname_eq!(element.name(&s), "hello");
    }

    #[test]
    fn root_has_maximum_of_one_element_child() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let alpha = s.create_element("alpha");
        let beta = s.create_element("beta");
        c.append_root_child(alpha);
        c.append_root_child(beta);
        let children = c.root_children();
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfRoot::Element(beta));
    }

    #[test]
    fn root_can_have_comment_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let comment = s.create_comment("Now is the winter of our discontent.");
        c.append_root_child(comment);
        let children = c.root_children();
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfRoot::Comment(comment));
    }

    #[test]
    fn root_can_have_processing_instruction_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let pi = s.create_processing_instruction("device", None);
        c.append_root_child(pi);
        let children = c.root_children();
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfRoot::ProcessingInstruction(pi));
    }

    #[test]
    fn element_children_are_ordered() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let greek = s.create_element("greek");
        let alpha = s.create_element("alpha");
        let omega = s.create_element("omega");
        c.append_element_child(greek, alpha);
        c.append_element_child(greek, omega);
        let children = c.element_children(greek);
        assert_eq!(children[0], ChildOfElement::Element(alpha));
        assert_eq!(children[1], ChildOfElement::Element(omega));
    }

    #[test]
    fn element_children_know_their_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let alpha = s.create_element("alpha");
        let beta = s.create_element("beta");
        c.append_element_child(alpha, beta);
        assert_eq!(Some(ParentOfChild::Element(alpha)), c.element_parent(beta));
    }

    #[test]
    fn elements_know_preceding_siblings() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let parent = s.create_element("parent");
        let a = s.create_element("a");
        let b = s.create_element("b");
        c.append_element_child(parent, a);
        c.append_element_child(parent, b);
        let preceding = c.element_preceding_siblings(b);
        assert_eq!(vec![ChildOfElement::Element(a)], preceding);
    }

    #[test]
    fn changing_parent_of_element_removes_element_from_original_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let parent1 = s.create_element("parent1");
        let parent2 = s.create_element("parent2");
        let child = s.create_element("child");
        c.append_element_child(parent1, child);
        c.append_element_child(parent2, child);
        assert_eq!(0, c.element_children(parent1).len());
        assert_eq!(1, c.element_children(parent2).len());
    }

    #[test]
    fn attributes_know_their_element() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let attr = s.create_attribute("hello", "world");
        c.set_attribute(element, attr);
        assert_eq!(Some(element), c.attribute_parent(attr));
    }

    #[test]
    fn attributes_belong_to_one_element() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element1 = s.create_element("element1");
        let element2 = s.create_element("element2");
        let attr = s.create_attribute("hello", "world");
        c.set_attribute(element1, attr);
        c.set_attribute(element2, attr);
        assert_eq!(0, c.attributes(element1).len());
        assert_eq!(1, c.attributes(element2).len());
    }

    #[test]
    fn attributes_can_be_reset() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let attr1 = s.create_attribute("hello", "world");
        let attr2 = s.create_attribute("hello", "galaxy");
        c.set_attribute(element, attr1);
        c.set_attribute(element, attr2);
        assert_eq!(
            c.attribute_value(element, "hello").as_deref(),
            Some("galaxy")
        );
    }

    #[test]
    fn attributes_can_be_iterated() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let attr1 = s.create_attribute("name1", "value1");
        let attr2 = s.create_attribute("name2", "value2");
        c.set_attribute(element, attr1);
        c.set_attribute(element, attr2);
        let mut attrs = c.attributes(element);
        attrs.sort_by(|a, b| {
            a.name(&s)
                .get()
                .namespace_uri()
                .cmp(&b.name(&s).get().namespace_uri())
        });
        assert_eq!(2, attrs.len());
        assert_qname_eq!(attrs[0].name(&s), "name1");
        assert_eq!(&*attrs[0].value(&s), "value1");
        assert_qname_eq!(attrs[1].name(&s), "name2");
        assert_eq!(&*attrs[1].value(&s), "value2");
    }

    #[test]
    fn elements_can_have_text_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let sentence = s.create_element("sentence");
        let text = s.create_text("Now is the winter of our discontent.");
        c.append_element_child(sentence, text);
        let children = c.element_children(sentence);
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfElement::Text(text));
    }

    #[test]
    fn text_knows_its_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let sentence = s.create_element("sentence");
        let text = s.create_text("Now is the winter of our discontent.");
        c.append_element_child(sentence, text);
        assert_eq!(c.text_parent(text), Some(sentence));
    }

    #[test]
    fn elements_can_have_comment_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let sentence = s.create_element("sentence");
        let comment = s.create_comment("Now is the winter of our discontent.");
        c.append_element_child(sentence, comment);
        let children = c.element_children(sentence);
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfElement::Comment(comment));
    }

    #[test]
    fn comment_knows_its_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let sentence = s.create_element("sentence");
        let comment = s.create_comment("Now is the winter of our discontent.");
        c.append_element_child(sentence, comment);
        assert_eq!(
            c.comment_parent(comment),
            Some(ParentOfChild::Element(sentence))
        );
    }

    #[test]
    fn comment_can_be_changed() {
        let package = Package::new();
        let (s, _c) = package.as_thin_document();
        let comment = s.create_comment("Now is the winter of our discontent.");
        s.comment_set_text(comment, "Made glorious summer by this sun of York");
        assert_eq!(
            &*comment.text(&s),
            "Made glorious summer by this sun of York"
        );
    }

    #[test]
    fn elements_can_have_processing_instruction_children() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let pi = s.create_processing_instruction("device", None);
        c.append_element_child(element, pi);
        let children = c.element_children(element);
        assert_eq!(1, children.len());
        assert_eq!(children[0], ChildOfElement::ProcessingInstruction(pi));
    }

    #[test]
    fn processing_instruction_knows_its_parent() {
        let package = Package::new();
        let (s, mut c) = package.as_thin_document();
        let element = s.create_element("element");
        let pi = s.create_processing_instruction("device", None);
        c.append_element_child(element, pi);
        assert_eq!(
            c.processing_instruction_parent(pi),
            Some(ParentOfChild::Element(element))
        );
    }

    #[test]
    fn processing_instruction_can_be_changed() {
        let package = Package::new();
        let (s, _c) = package.as_thin_document();
        let pi = s.create_processing_instruction("device", None);
        s.processing_instruction_set_target(pi, "output");
        s.processing_instruction_set_value(pi, Some("full-screen"));
        assert_eq!(&*pi.target(&s), "output");
        assert_eq!(pi.value(&s).as_deref(), Some("full-screen"));
    }
}
