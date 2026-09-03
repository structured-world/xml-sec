use super::{QName, lazy_hash_map::LazyHashMap};

use crate::string_pool::{InternedString, StringPool};
use std::{cell::RefCell, marker::PhantomData};

// --- Typed index handle ---

pub struct Index<T> {
    idx: usize,
    _marker: PhantomData<T>,
}

impl<T> Copy for Index<T> {}
impl<T> Clone for Index<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> PartialEq for Index<T> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}
impl<T> Eq for Index<T> {}
impl<T> std::hash::Hash for Index<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.idx.hash(state)
    }
}
impl<T> std::fmt::Debug for Index<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Index({})", self.idx)
    }
}

impl<T> Index<T> {
    fn new(idx: usize) -> Self {
        Index {
            idx,
            _marker: PhantomData,
        }
    }
}

// --- Interned QName ---

struct InternedQName {
    namespace_uri: Option<InternedString>,
    local_part: InternedString,
}

impl InternedQName {
    fn as_qname(&self) -> QName<'_> {
        QName {
            namespace_uri: self.namespace_uri.as_deref(),
            local_part: &self.local_part,
        }
    }
}

impl Clone for InternedQName {
    fn clone(&self) -> Self {
        InternedQName {
            namespace_uri: self.namespace_uri.clone(),
            local_part: self.local_part.clone(),
        }
    }
}

// --- Public owned QName wrapper ---

pub struct QNameValue {
    namespace_uri: Option<InternedString>,
    local_part: InternedString,
}

impl QNameValue {
    pub fn get(&self) -> QName<'_> {
        QName {
            namespace_uri: self.namespace_uri.as_deref(),
            local_part: &self.local_part,
        }
    }

    pub fn local_part_clone(&self) -> InternedString {
        self.local_part.clone()
    }
}

impl std::fmt::Debug for QNameValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

// --- Node types ---

pub struct Root {
    children: Vec<ChildOfRoot>,
}

pub struct Element {
    name: InternedQName,
    default_namespace_uri: Option<InternedString>,
    preferred_prefix: Option<InternedString>,
    children: Vec<ChildOfElement>,
    parent: Option<ParentOfChild>,
    attributes: Vec<Index<Attribute>>,
    prefix_to_namespace: LazyHashMap<InternedString, InternedString>,
}

pub struct Attribute {
    name: InternedQName,
    preferred_prefix: Option<InternedString>,
    value: InternedString,
    parent: Option<Index<Element>>,
}

pub struct Text {
    text: InternedString,
    parent: Option<Index<Element>>,
}

pub struct Comment {
    text: InternedString,
    parent: Option<ParentOfChild>,
}

pub struct ProcessingInstruction {
    target: InternedString,
    value: Option<InternedString>,
    parent: Option<ParentOfChild>,
}

// --- Child/Parent enums ---

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ChildOfRoot {
    Element(Index<Element>),
    Comment(Index<Comment>),
    ProcessingInstruction(Index<ProcessingInstruction>),
}

impl ChildOfRoot {
    fn is_element(&self) -> bool {
        matches!(self, ChildOfRoot::Element(_))
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ChildOfElement {
    Element(Index<Element>),
    Text(Index<Text>),
    Comment(Index<Comment>),
    ProcessingInstruction(Index<ProcessingInstruction>),
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ParentOfChild {
    Root(Index<Root>),
    Element(Index<Element>),
}

// --- Conversion traits ---

macro_rules! conversion_trait(
    ($res_type:ident, {
        $($leaf_type:ident => $variant:expr),*
    }) => (
        $(impl From<Index<$leaf_type>> for $res_type {
            fn from(v: Index<$leaf_type>) -> $res_type {
                $variant(v)
            }
        })*
    )
);

conversion_trait!(
    ChildOfElement, {
        Element               => ChildOfElement::Element,
        Text                  => ChildOfElement::Text,
        Comment               => ChildOfElement::Comment,
        ProcessingInstruction => ChildOfElement::ProcessingInstruction
    }
);

conversion_trait!(
    ChildOfRoot, {
        Element               => ChildOfRoot::Element,
        Comment               => ChildOfRoot::Comment,
        ProcessingInstruction => ChildOfRoot::ProcessingInstruction
    }
);

impl From<ChildOfRoot> for ChildOfElement {
    fn from(v: ChildOfRoot) -> ChildOfElement {
        match v {
            ChildOfRoot::Element(n) => ChildOfElement::Element(n),
            ChildOfRoot::Comment(n) => ChildOfElement::Comment(n),
            ChildOfRoot::ProcessingInstruction(n) => ChildOfElement::ProcessingInstruction(n),
        }
    }
}

// --- Storage ---

pub struct Storage {
    strings: StringPool,
    pub(crate) roots: RefCell<Vec<Root>>,
    pub(crate) elements: RefCell<Vec<Element>>,
    pub(crate) attributes: RefCell<Vec<Attribute>>,
    pub(crate) texts: RefCell<Vec<Text>>,
    pub(crate) comments: RefCell<Vec<Comment>>,
    pub(crate) processing_instructions: RefCell<Vec<ProcessingInstruction>>,
}

impl Default for Storage {
    fn default() -> Storage {
        Storage {
            strings: StringPool::new(),
            roots: RefCell::new(Vec::new()),
            elements: RefCell::new(Vec::new()),
            attributes: RefCell::new(Vec::new()),
            texts: RefCell::new(Vec::new()),
            comments: RefCell::new(Vec::new()),
            processing_instructions: RefCell::new(Vec::new()),
        }
    }
}

impl Storage {
    pub fn new() -> Storage {
        Self::default()
    }

    fn intern(&self, s: &str) -> InternedString {
        self.strings.intern(s)
    }

    fn intern_qname(&self, q: QName<'_>) -> InternedQName {
        InternedQName {
            namespace_uri: q.namespace_uri.map(|p| self.intern(p)),
            local_part: self.intern(q.local_part),
        }
    }

    pub fn create_root(&self) -> Index<Root> {
        let mut roots = self.roots.borrow_mut();
        let idx = roots.len();
        roots.push(Root {
            children: Vec::new(),
        });
        Index::new(idx)
    }

    pub fn create_element<'n, N>(&self, name: N) -> Index<Element>
    where
        N: Into<QName<'n>>,
    {
        let name = self.intern_qname(name.into());
        let mut elements = self.elements.borrow_mut();
        let idx = elements.len();
        elements.push(Element {
            name,
            default_namespace_uri: None,
            preferred_prefix: None,
            children: Vec::new(),
            parent: None,
            attributes: Vec::new(),
            prefix_to_namespace: LazyHashMap::new(),
        });
        Index::new(idx)
    }

    pub fn create_attribute<'n, N>(&self, name: N, value: &str) -> Index<Attribute>
    where
        N: Into<QName<'n>>,
    {
        let name = self.intern_qname(name.into());
        let value = self.intern(value);
        let mut attributes = self.attributes.borrow_mut();
        let idx = attributes.len();
        attributes.push(Attribute {
            name,
            preferred_prefix: None,
            value,
            parent: None,
        });
        Index::new(idx)
    }

    pub fn create_text(&self, text: &str) -> Index<Text> {
        let text = self.intern(text);
        let mut texts = self.texts.borrow_mut();
        let idx = texts.len();
        texts.push(Text { text, parent: None });
        Index::new(idx)
    }

    pub fn create_comment(&self, text: &str) -> Index<Comment> {
        let text = self.intern(text);
        let mut comments = self.comments.borrow_mut();
        let idx = comments.len();
        comments.push(Comment { text, parent: None });
        Index::new(idx)
    }

    pub fn create_processing_instruction(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Index<ProcessingInstruction> {
        let target = self.intern(target);
        let value = value.map(|v| self.intern(v));
        let mut pis = self.processing_instructions.borrow_mut();
        let idx = pis.len();
        pis.push(ProcessingInstruction {
            target,
            value,
            parent: None,
        });
        Index::new(idx)
    }

    pub fn element_set_name<'n, N>(&self, element: Index<Element>, name: N)
    where
        N: Into<QName<'n>>,
    {
        let name = self.intern_qname(name.into());
        self.elements.borrow_mut()[element.idx].name = name;
    }

    pub fn element_register_prefix(
        &self,
        element: Index<Element>,
        prefix: &str,
        namespace_uri: &str,
    ) {
        let prefix = self.intern(prefix);
        let namespace_uri = self.intern(namespace_uri);
        self.elements.borrow_mut()[element.idx]
            .prefix_to_namespace
            .insert(prefix, namespace_uri);
    }

    pub fn element_set_default_namespace_uri(
        &self,
        element: Index<Element>,
        namespace_uri: Option<&str>,
    ) {
        let namespace_uri = namespace_uri.map(|p| self.intern(p));
        self.elements.borrow_mut()[element.idx].default_namespace_uri = namespace_uri;
    }

    pub fn element_set_preferred_prefix(&self, element: Index<Element>, prefix: Option<&str>) {
        let prefix = prefix.map(|p| self.intern(p));
        self.elements.borrow_mut()[element.idx].preferred_prefix = prefix;
    }

    pub fn attribute_set_preferred_prefix(
        &self,
        attribute: Index<Attribute>,
        prefix: Option<&str>,
    ) {
        let prefix = prefix.map(|p| self.intern(p));
        self.attributes.borrow_mut()[attribute.idx].preferred_prefix = prefix;
    }

    pub fn text_set_text(&self, text: Index<Text>, new_text: &str) {
        let new_text = self.intern(new_text);
        self.texts.borrow_mut()[text.idx].text = new_text;
    }

    pub fn comment_set_text(&self, comment: Index<Comment>, new_text: &str) {
        let new_text = self.intern(new_text);
        self.comments.borrow_mut()[comment.idx].text = new_text;
    }

    pub fn processing_instruction_set_target(
        &self,
        pi: Index<ProcessingInstruction>,
        new_target: &str,
    ) {
        let new_target = self.intern(new_target);
        self.processing_instructions.borrow_mut()[pi.idx].target = new_target;
    }

    pub fn processing_instruction_set_value(
        &self,
        pi: Index<ProcessingInstruction>,
        new_value: Option<&str>,
    ) {
        let new_value = new_value.map(|v| self.intern(v));
        self.processing_instructions.borrow_mut()[pi.idx].value = new_value;
    }

    // --- Accessors that clone data out of RefCells ---

    pub fn element_name(&self, element: Index<Element>) -> QNameValue {
        let elements = self.elements.borrow();
        let e = &elements[element.idx];
        QNameValue {
            namespace_uri: e.name.namespace_uri.clone(),
            local_part: e.name.local_part.clone(),
        }
    }

    pub fn element_default_namespace_uri(&self, element: Index<Element>) -> Option<InternedString> {
        self.elements.borrow()[element.idx]
            .default_namespace_uri
            .clone()
    }

    pub fn element_preferred_prefix(&self, element: Index<Element>) -> Option<InternedString> {
        self.elements.borrow()[element.idx].preferred_prefix.clone()
    }

    pub fn attribute_name(&self, attribute: Index<Attribute>) -> QNameValue {
        let attributes = self.attributes.borrow();
        let a = &attributes[attribute.idx];
        QNameValue {
            namespace_uri: a.name.namespace_uri.clone(),
            local_part: a.name.local_part.clone(),
        }
    }

    pub fn attribute_value(&self, attribute: Index<Attribute>) -> InternedString {
        self.attributes.borrow()[attribute.idx].value.clone()
    }

    pub fn attribute_preferred_prefix(
        &self,
        attribute: Index<Attribute>,
    ) -> Option<InternedString> {
        self.attributes.borrow()[attribute.idx]
            .preferred_prefix
            .clone()
    }

    pub fn text_text(&self, text: Index<Text>) -> InternedString {
        self.texts.borrow()[text.idx].text.clone()
    }

    pub fn comment_text(&self, comment: Index<Comment>) -> InternedString {
        self.comments.borrow()[comment.idx].text.clone()
    }

    pub fn pi_target(&self, pi: Index<ProcessingInstruction>) -> InternedString {
        self.processing_instructions.borrow()[pi.idx].target.clone()
    }

    pub fn pi_value(&self, pi: Index<ProcessingInstruction>) -> Option<InternedString> {
        self.processing_instructions.borrow()[pi.idx].value.clone()
    }
}

// --- Connections ---

pub struct Connections {
    root: Index<Root>,
}

impl Connections {
    pub fn new(root: Index<Root>) -> Connections {
        Connections { root }
    }

    pub fn root(&self) -> Index<Root> {
        self.root
    }

    // --- Parent accessors ---

    pub fn element_parent(
        &self,
        storage: &Storage,
        child: Index<Element>,
    ) -> Option<ParentOfChild> {
        storage.elements.borrow()[child.idx].parent
    }

    pub fn text_parent(&self, storage: &Storage, child: Index<Text>) -> Option<Index<Element>> {
        storage.texts.borrow()[child.idx].parent
    }

    pub fn comment_parent(
        &self,
        storage: &Storage,
        child: Index<Comment>,
    ) -> Option<ParentOfChild> {
        storage.comments.borrow()[child.idx].parent
    }

    pub fn processing_instruction_parent(
        &self,
        storage: &Storage,
        child: Index<ProcessingInstruction>,
    ) -> Option<ParentOfChild> {
        storage.processing_instructions.borrow()[child.idx].parent
    }

    // --- Child management ---

    pub fn append_root_child<C>(&self, storage: &Storage, child: C)
    where
        C: Into<ChildOfRoot>,
    {
        let child = child.into();
        self.replace_root_child_parent(storage, child);
        storage.roots.borrow_mut()[self.root.idx]
            .children
            .push(child);
    }

    pub fn append_element_child<C>(&self, storage: &Storage, parent: Index<Element>, child: C)
    where
        C: Into<ChildOfElement>,
    {
        let child = child.into();
        self.replace_element_child_parent(storage, parent, child);
        storage.elements.borrow_mut()[parent.idx]
            .children
            .push(child);
    }

    pub fn remove_root_child<C>(&self, storage: &Storage, child: C)
    where
        C: Into<ChildOfRoot>,
    {
        let child = child.into();
        self.clear_child_parent(storage, child.into());
        storage.roots.borrow_mut()[self.root.idx]
            .children
            .retain(|&x| x != child);
    }

    pub fn remove_element_child<C>(&self, storage: &Storage, parent: Index<Element>, child: C)
    where
        C: Into<ChildOfElement>,
    {
        let child = child.into();
        self.clear_child_parent(storage, child);
        storage.elements.borrow_mut()[parent.idx]
            .children
            .retain(|&x| x != child);
    }

    pub fn clear_root_children(&self, storage: &Storage) {
        let children: Vec<ChildOfRoot> = storage.roots.borrow()[self.root.idx].children.clone();
        for c in &children {
            self.clear_child_parent(storage, (*c).into());
        }
        storage.roots.borrow_mut()[self.root.idx].children.clear();
    }

    pub fn clear_element_children(&self, storage: &Storage, parent: Index<Element>) {
        let children: Vec<ChildOfElement> = storage.elements.borrow()[parent.idx].children.clone();
        for c in &children {
            self.clear_child_parent(storage, *c);
        }
        storage.elements.borrow_mut()[parent.idx].children.clear();
    }

    // --- Parent removal ---

    pub fn remove_element_from_parent(&self, storage: &Storage, child: Index<Element>) {
        let parent = storage.elements.borrow()[child.idx].parent;
        match parent {
            Some(ParentOfChild::Root(_)) => self.remove_root_child(storage, child),
            Some(ParentOfChild::Element(p)) => self.remove_element_child(storage, p, child),
            None => {}
        }
    }

    pub fn remove_attribute_from_parent(&self, storage: &Storage, child: Index<Attribute>) {
        let parent = storage.attributes.borrow()[child.idx].parent;
        if let Some(parent_idx) = parent {
            self.remove_attribute_x(storage, parent_idx, |idx| idx == child);
        }
    }

    pub fn remove_text_from_parent(&self, storage: &Storage, child: Index<Text>) {
        let parent = storage.texts.borrow()[child.idx].parent;
        if let Some(parent_idx) = parent {
            self.remove_element_child(storage, parent_idx, child);
        }
    }

    pub fn remove_comment_from_parent(&self, storage: &Storage, child: Index<Comment>) {
        let parent = storage.comments.borrow()[child.idx].parent;
        match parent {
            Some(ParentOfChild::Root(_)) => self.remove_root_child(storage, child),
            Some(ParentOfChild::Element(p)) => self.remove_element_child(storage, p, child),
            None => {}
        }
    }

    pub fn remove_processing_instruction_from_parent(
        &self,
        storage: &Storage,
        child: Index<ProcessingInstruction>,
    ) {
        let parent = storage.processing_instructions.borrow()[child.idx].parent;
        match parent {
            Some(ParentOfChild::Root(_)) => self.remove_root_child(storage, child),
            Some(ParentOfChild::Element(p)) => self.remove_element_child(storage, p, child),
            None => {}
        }
    }

    // --- Children/sibling accessors ---

    pub fn root_children(&self, storage: &Storage) -> Vec<ChildOfRoot> {
        storage.roots.borrow()[self.root.idx].children.clone()
    }

    pub fn root_children_len(&self, storage: &Storage) -> usize {
        storage.roots.borrow()[self.root.idx].children.len()
    }

    pub fn element_children(
        &self,
        storage: &Storage,
        parent: Index<Element>,
    ) -> Vec<ChildOfElement> {
        storage.elements.borrow()[parent.idx].children.clone()
    }

    pub fn element_children_len(&self, storage: &Storage, parent: Index<Element>) -> usize {
        storage.elements.borrow()[parent.idx].children.len()
    }

    pub fn element_preceding_siblings(
        &self,
        storage: &Storage,
        element: Index<Element>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.elements.borrow()[element.idx].parent;
        self.preceding_siblings_impl(storage, parent, ChildOfElement::Element(element))
    }

    pub fn element_following_siblings(
        &self,
        storage: &Storage,
        element: Index<Element>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.elements.borrow()[element.idx].parent;
        self.following_siblings_impl(storage, parent, ChildOfElement::Element(element))
    }

    pub fn text_preceding_siblings(
        &self,
        storage: &Storage,
        text: Index<Text>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.texts.borrow()[text.idx]
            .parent
            .map(ParentOfChild::Element);
        self.preceding_siblings_impl(storage, parent, ChildOfElement::Text(text))
    }

    pub fn text_following_siblings(
        &self,
        storage: &Storage,
        text: Index<Text>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.texts.borrow()[text.idx]
            .parent
            .map(ParentOfChild::Element);
        self.following_siblings_impl(storage, parent, ChildOfElement::Text(text))
    }

    pub fn comment_preceding_siblings(
        &self,
        storage: &Storage,
        comment: Index<Comment>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.comments.borrow()[comment.idx].parent;
        self.preceding_siblings_impl(storage, parent, ChildOfElement::Comment(comment))
    }

    pub fn comment_following_siblings(
        &self,
        storage: &Storage,
        comment: Index<Comment>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.comments.borrow()[comment.idx].parent;
        self.following_siblings_impl(storage, parent, ChildOfElement::Comment(comment))
    }

    pub fn processing_instruction_preceding_siblings(
        &self,
        storage: &Storage,
        pi: Index<ProcessingInstruction>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.processing_instructions.borrow()[pi.idx].parent;
        self.preceding_siblings_impl(storage, parent, ChildOfElement::ProcessingInstruction(pi))
    }

    pub fn processing_instruction_following_siblings(
        &self,
        storage: &Storage,
        pi: Index<ProcessingInstruction>,
    ) -> Vec<ChildOfElement> {
        let parent = storage.processing_instructions.borrow()[pi.idx].parent;
        self.following_siblings_impl(storage, parent, ChildOfElement::ProcessingInstruction(pi))
    }

    fn preceding_siblings_impl(
        &self,
        storage: &Storage,
        parent: Option<ParentOfChild>,
        child: ChildOfElement,
    ) -> Vec<ChildOfElement> {
        match parent {
            Some(ParentOfChild::Root(root_idx)) => {
                let roots = storage.roots.borrow();
                let children = &roots[root_idx.idx].children;
                let child_as_root = match child {
                    ChildOfElement::Element(n) => ChildOfRoot::Element(n),
                    ChildOfElement::Comment(n) => ChildOfRoot::Comment(n),
                    ChildOfElement::ProcessingInstruction(n) => {
                        ChildOfRoot::ProcessingInstruction(n)
                    }
                    _ => return Vec::new(),
                };
                let pos = children.iter().position(|c| *c == child_as_root).unwrap();
                children[..pos].iter().map(|&c| c.into()).collect()
            }
            Some(ParentOfChild::Element(parent_idx)) => {
                let elements = storage.elements.borrow();
                let children = &elements[parent_idx.idx].children;
                let pos = children.iter().position(|c| *c == child).unwrap();
                children[..pos].to_vec()
            }
            None => Vec::new(),
        }
    }

    fn following_siblings_impl(
        &self,
        storage: &Storage,
        parent: Option<ParentOfChild>,
        child: ChildOfElement,
    ) -> Vec<ChildOfElement> {
        match parent {
            Some(ParentOfChild::Root(root_idx)) => {
                let roots = storage.roots.borrow();
                let children = &roots[root_idx.idx].children;
                let child_as_root = match child {
                    ChildOfElement::Element(n) => ChildOfRoot::Element(n),
                    ChildOfElement::Comment(n) => ChildOfRoot::Comment(n),
                    ChildOfElement::ProcessingInstruction(n) => {
                        ChildOfRoot::ProcessingInstruction(n)
                    }
                    _ => return Vec::new(),
                };
                let pos = children.iter().position(|c| *c == child_as_root).unwrap();
                children[pos + 1..].iter().map(|&c| c.into()).collect()
            }
            Some(ParentOfChild::Element(parent_idx)) => {
                let elements = storage.elements.borrow();
                let children = &elements[parent_idx.idx].children;
                let pos = children.iter().position(|c| *c == child).unwrap();
                children[pos + 1..].to_vec()
            }
            None => Vec::new(),
        }
    }

    // --- Attribute management ---

    pub fn attribute_parent(
        &self,
        storage: &Storage,
        attribute: Index<Attribute>,
    ) -> Option<Index<Element>> {
        storage.attributes.borrow()[attribute.idx].parent
    }

    pub fn attributes(&self, storage: &Storage, parent: Index<Element>) -> Vec<Index<Attribute>> {
        storage.elements.borrow()[parent.idx].attributes.clone()
    }

    pub fn attribute<'n, N>(
        &self,
        storage: &Storage,
        element: Index<Element>,
        name: N,
    ) -> Option<Index<Attribute>>
    where
        N: Into<QName<'n>>,
    {
        let name = name.into();
        let elements = storage.elements.borrow();
        let attributes = storage.attributes.borrow();
        elements[element.idx]
            .attributes
            .iter()
            .find(|&&a_idx| attributes[a_idx.idx].name.as_qname() == name)
            .copied()
    }

    pub fn remove_attribute<'n, N>(&self, storage: &Storage, element: Index<Element>, name: N)
    where
        N: Into<QName<'n>>,
    {
        let name = name.into();
        self.remove_attribute_x(storage, element, |a_idx| {
            storage.attributes.borrow()[a_idx.idx].name.as_qname() == name
        })
    }

    pub fn remove_attribute_x<F>(&self, storage: &Storage, element: Index<Element>, mut pred: F)
    where
        F: FnMut(Index<Attribute>) -> bool,
    {
        let attr_indices: Vec<Index<Attribute>> =
            storage.elements.borrow()[element.idx].attributes.clone();
        let mut to_keep = Vec::new();
        for a_idx in attr_indices {
            if pred(a_idx) {
                storage.attributes.borrow_mut()[a_idx.idx].parent = None;
            } else {
                to_keep.push(a_idx);
            }
        }
        storage.elements.borrow_mut()[element.idx].attributes = to_keep;
    }

    pub fn set_attribute(
        &self,
        storage: &Storage,
        parent: Index<Element>,
        attribute: Index<Attribute>,
    ) {
        let prev_parent = storage.attributes.borrow()[attribute.idx].parent;
        if let Some(prev_parent_idx) = prev_parent {
            storage.elements.borrow_mut()[prev_parent_idx.idx]
                .attributes
                .retain(|&a| a != attribute);
        }

        let attr_name = {
            let attrs = storage.attributes.borrow();
            attrs[attribute.idx].name.clone()
        };
        {
            let mut elements = storage.elements.borrow_mut();
            let attrs_ref = storage.attributes.borrow();
            elements[parent.idx]
                .attributes
                .retain(|&a| attrs_ref[a.idx].name.as_qname() != attr_name.as_qname());
        }
        storage.elements.borrow_mut()[parent.idx]
            .attributes
            .push(attribute);
        storage.attributes.borrow_mut()[attribute.idx].parent = Some(parent);
    }

    // --- Namespace resolution ---

    pub fn element_namespace_uri_for_prefix(
        &self,
        storage: &Storage,
        element: Index<Element>,
        prefix: &str,
    ) -> Option<InternedString> {
        let mut current = Some(element);
        while let Some(elem_idx) = current {
            let elements = storage.elements.borrow();
            let elem = &elements[elem_idx.idx];
            if let Some(uri) = elem.prefix_to_namespace.get(prefix) {
                return Some(uri.clone());
            }
            current = match elem.parent {
                Some(ParentOfChild::Element(p)) => Some(p),
                _ => None,
            };
        }
        None
    }

    pub fn element_prefix_for_namespace_uri(
        &self,
        storage: &Storage,
        element: Index<Element>,
        namespace_uri: &str,
        preferred_prefix: Option<&str>,
    ) -> Option<InternedString> {
        let mut current = Some(element);
        while let Some(elem_idx) = current {
            let elements = storage.elements.borrow();
            let elem = &elements[elem_idx.idx];

            let prefixes: Vec<InternedString> = elem
                .prefix_to_namespace
                .iter()
                .filter_map(|(prefix, ns_uri)| {
                    if &**ns_uri == namespace_uri {
                        Some(prefix.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if let Some(preferred) = preferred_prefix
                && let Some(p) = prefixes.iter().find(|p| &***p == preferred)
            {
                return Some(p.clone());
            }
            if let Some(p) = prefixes.first() {
                return Some(p.clone());
            }

            current = match elem.parent {
                Some(ParentOfChild::Element(p)) => Some(p),
                _ => None,
            };
        }
        None
    }

    pub fn element_namespaces_in_scope(
        &self,
        storage: &Storage,
        element: Index<Element>,
    ) -> NamespacesInScope {
        let mut namespaces: Vec<(String, String)> = Vec::new();
        namespaces.push((
            crate::XML_NS_PREFIX.to_owned(),
            crate::XML_NS_URI.to_owned(),
        ));

        let mut current = Some(element);
        while let Some(elem_idx) = current {
            let elements = storage.elements.borrow();
            let elem = &elements[elem_idx.idx];
            for (prefix, uri) in elem.prefix_to_namespace.iter() {
                let ns = (prefix.to_string(), uri.to_string());
                if !namespaces.iter().any(|n| n.0 == ns.0) {
                    namespaces.push(ns);
                }
            }
            current = match elem.parent {
                Some(ParentOfChild::Element(p)) => Some(p),
                _ => None,
            };
        }

        NamespacesInScope {
            iter: namespaces.into_iter(),
        }
    }

    pub fn element_recursive_default_namespace_uri(
        &self,
        storage: &Storage,
        element: Index<Element>,
    ) -> Option<InternedString> {
        let mut current = Some(element);
        while let Some(elem_idx) = current {
            let elements = storage.elements.borrow();
            let elem = &elements[elem_idx.idx];
            if elem.default_namespace_uri.is_some() {
                return elem.default_namespace_uri.clone();
            }
            current = match elem.parent {
                Some(ParentOfChild::Element(p)) => Some(p),
                _ => None,
            };
        }
        None
    }

    // --- Internal helpers ---

    fn replace_root_child_parent(&self, storage: &Storage, child: ChildOfRoot) {
        match child {
            ChildOfRoot::Element(n) => {
                // Root may only have one element child; remove existing elements
                storage.roots.borrow_mut()[self.root.idx]
                    .children
                    .retain(|c| !c.is_element());

                // Remove from previous parent
                let old_parent = storage.elements.borrow()[n.idx].parent;
                self.detach_from_old_parent(storage, ChildOfRoot::Element(n).into(), old_parent);
                storage.elements.borrow_mut()[n.idx].parent = Some(ParentOfChild::Root(self.root));
            }
            ChildOfRoot::Comment(n) => {
                let old_parent = storage.comments.borrow()[n.idx].parent;
                self.detach_from_old_parent(storage, ChildOfRoot::Comment(n).into(), old_parent);
                storage.comments.borrow_mut()[n.idx].parent = Some(ParentOfChild::Root(self.root));
            }
            ChildOfRoot::ProcessingInstruction(n) => {
                let old_parent = storage.processing_instructions.borrow()[n.idx].parent;
                self.detach_from_old_parent(
                    storage,
                    ChildOfRoot::ProcessingInstruction(n).into(),
                    old_parent,
                );
                storage.processing_instructions.borrow_mut()[n.idx].parent =
                    Some(ParentOfChild::Root(self.root));
            }
        }
    }

    fn replace_element_child_parent(
        &self,
        storage: &Storage,
        new_parent: Index<Element>,
        child: ChildOfElement,
    ) {
        match child {
            ChildOfElement::Element(n) => {
                let old_parent = storage.elements.borrow()[n.idx].parent;
                self.detach_from_old_parent(storage, child, old_parent);
                storage.elements.borrow_mut()[n.idx].parent =
                    Some(ParentOfChild::Element(new_parent));
            }
            ChildOfElement::Text(n) => {
                let old_parent = storage.texts.borrow()[n.idx]
                    .parent
                    .map(ParentOfChild::Element);
                self.detach_from_old_parent(storage, child, old_parent);
                storage.texts.borrow_mut()[n.idx].parent = Some(new_parent);
            }
            ChildOfElement::Comment(n) => {
                let old_parent = storage.comments.borrow()[n.idx].parent;
                self.detach_from_old_parent(storage, child, old_parent);
                storage.comments.borrow_mut()[n.idx].parent =
                    Some(ParentOfChild::Element(new_parent));
            }
            ChildOfElement::ProcessingInstruction(n) => {
                let old_parent = storage.processing_instructions.borrow()[n.idx].parent;
                self.detach_from_old_parent(storage, child, old_parent);
                storage.processing_instructions.borrow_mut()[n.idx].parent =
                    Some(ParentOfChild::Element(new_parent));
            }
        }
    }

    fn detach_from_old_parent(
        &self,
        storage: &Storage,
        child: ChildOfElement,
        old_parent: Option<ParentOfChild>,
    ) {
        match old_parent {
            Some(ParentOfChild::Root(r)) => {
                let child_as_root = match child {
                    ChildOfElement::Element(n) => ChildOfRoot::Element(n),
                    ChildOfElement::Comment(n) => ChildOfRoot::Comment(n),
                    ChildOfElement::ProcessingInstruction(n) => {
                        ChildOfRoot::ProcessingInstruction(n)
                    }
                    ChildOfElement::Text(_) => return,
                };
                storage.roots.borrow_mut()[r.idx]
                    .children
                    .retain(|c| *c != child_as_root);
            }
            Some(ParentOfChild::Element(e)) => {
                storage.elements.borrow_mut()[e.idx]
                    .children
                    .retain(|c| *c != child);
            }
            None => {}
        }
    }

    fn clear_child_parent(&self, storage: &Storage, child: ChildOfElement) {
        match child {
            ChildOfElement::Element(n) => {
                storage.elements.borrow_mut()[n.idx].parent = None;
            }
            ChildOfElement::Text(n) => {
                storage.texts.borrow_mut()[n.idx].parent = None;
            }
            ChildOfElement::Comment(n) => {
                storage.comments.borrow_mut()[n.idx].parent = None;
            }
            ChildOfElement::ProcessingInstruction(n) => {
                storage.processing_instructions.borrow_mut()[n.idx].parent = None;
            }
        }
    }
}

// --- NamespacesInScope iterator ---

pub struct NamespacesInScope {
    iter: std::vec::IntoIter<(String, String)>,
}

impl Iterator for NamespacesInScope {
    type Item = (String, String);

    fn next(&mut self) -> Option<(String, String)> {
        self.iter.next()
    }
}
