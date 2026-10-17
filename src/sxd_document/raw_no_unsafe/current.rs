//! Fallible construction of a private, read-only XPath mirror.

use super::*;
use crate::sxd_document::string_pool::AccountedStringPool;
use structured_asn1::memory::{MemoryError, Work};

pub(crate) fn storage(work: &impl Work) -> Result<(Storage, Index<Root>), MemoryError> {
    let storage = Storage {
        strings: StringPool::new(),
        roots: RefCell::new(Values::current()),
        elements: RefCell::new(Values::current()),
        attributes: RefCell::new(Values::current()),
        texts: RefCell::new(Values::current()),
        comments: RefCell::new(Values::current()),
        processing_instructions: RefCell::new(Values::current()),
    };
    storage.roots.borrow_mut().try_push(
        Root {
            children: Values::current(),
        },
        work,
    )?;
    Ok((storage, Index::new(0)))
}

pub(crate) struct Builder<'d, 'w, W: Work> {
    storage: &'d Storage,
    connections: &'d Connections,
    strings: AccountedStringPool<'w, W>,
    work: &'w W,
}

impl<'d, 'w, W: Work> Builder<'d, 'w, W> {
    pub(crate) fn new(storage: &'d Storage, connections: &'d Connections, work: &'w W) -> Self {
        Self {
            storage,
            connections,
            strings: AccountedStringPool::new(work),
            work,
        }
    }

    fn intern(&self, text: &str) -> Result<InternedString, MemoryError> {
        self.strings.intern(text).map(InternedString::into_retained)
    }

    fn name(&self, name: QName<'_>) -> Result<InternedQName, MemoryError> {
        Ok(InternedQName {
            namespace_uri: name
                .namespace_uri()
                .map(|text| self.intern(text))
                .transpose()?,
            local_part: self.intern(name.local_part())?,
        })
    }

    pub(crate) fn element(&self, name: QName<'_>) -> Result<Index<Element>, MemoryError> {
        let name = self.name(name)?;
        let mut elements = self.storage.elements.borrow_mut();
        let index = Index::new(elements.len());
        elements.try_push(
            Element {
                name,
                default_namespace_uri: None,
                preferred_prefix: None,
                children: Values::current(),
                parent: None,
                attributes: Values::current(),
                prefix_to_namespace: Bindings::Current(None),
            },
            self.work,
        )?;
        Ok(index)
    }

    pub(crate) fn attribute(
        &self,
        name: QName<'_>,
        value: &str,
    ) -> Result<Index<Attribute>, MemoryError> {
        let name = self.name(name)?;
        let value = self.intern(value)?;
        let mut attributes = self.storage.attributes.borrow_mut();
        let index = Index::new(attributes.len());
        attributes.try_push(
            Attribute {
                name,
                preferred_prefix: None,
                value,
                parent: None,
            },
            self.work,
        )?;
        Ok(index)
    }

    pub(crate) fn text(&self, value: &str) -> Result<Index<Text>, MemoryError> {
        let text = self.intern(value)?;
        let mut texts = self.storage.texts.borrow_mut();
        let index = Index::new(texts.len());
        texts.try_push(Text { text, parent: None }, self.work)?;
        Ok(index)
    }

    pub(crate) fn comment(&self, value: &str) -> Result<Index<Comment>, MemoryError> {
        let text = self.intern(value)?;
        let mut comments = self.storage.comments.borrow_mut();
        let index = Index::new(comments.len());
        comments.try_push(Comment { text, parent: None }, self.work)?;
        Ok(index)
    }

    pub(crate) fn pi(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Result<Index<ProcessingInstruction>, MemoryError> {
        let target = self.intern(target)?;
        let value = value.map(|value| self.intern(value)).transpose()?;
        let mut instructions = self.storage.processing_instructions.borrow_mut();
        let index = Index::new(instructions.len());
        instructions.try_push(
            ProcessingInstruction {
                target,
                value,
                parent: None,
            },
            self.work,
        )?;
        Ok(index)
    }

    pub(crate) fn preferred_element_prefix(
        &self,
        element: Index<Element>,
        prefix: Option<&str>,
    ) -> Result<(), MemoryError> {
        let prefix = prefix.map(|value| self.intern(value)).transpose()?;
        self.storage.elements.borrow_mut()[element.idx].preferred_prefix = prefix;
        Ok(())
    }

    pub(crate) fn preferred_attribute_prefix(
        &self,
        attribute: Index<Attribute>,
        prefix: Option<&str>,
    ) -> Result<(), MemoryError> {
        let prefix = prefix.map(|value| self.intern(value)).transpose()?;
        self.storage.attributes.borrow_mut()[attribute.idx].preferred_prefix = prefix;
        Ok(())
    }

    pub(crate) fn default_namespace(
        &self,
        element: Index<Element>,
        uri: Option<&str>,
    ) -> Result<(), MemoryError> {
        let uri = uri.map(|value| self.intern(value)).transpose()?;
        self.storage.elements.borrow_mut()[element.idx].default_namespace_uri = uri;
        Ok(())
    }

    pub(crate) fn namespace_declarations<'a>(
        &self,
        element: Index<Element>,
        declarations: impl Iterator<Item = (Option<&'a str>, &'a str)>,
    ) -> Result<(), MemoryError> {
        let mut bindings = self.work.map();
        let mut default_namespace = None;
        for (prefix, uri) in declarations {
            let uri = self.intern(uri)?;
            if prefix.is_none() && !uri.is_empty() {
                default_namespace = Some(uri.clone());
            }
            // Keep empty undeclarations as shadow entries. The XPath namespace
            // visitor omits their nodes, rather than reviving an ancestor URI.
            // https://www.w3.org/TR/1999/REC-xpath-19991116/#namespace-nodes (§5.4)
            bindings.try_insert(self.intern(prefix.unwrap_or(""))?, uri)?;
        }
        let mut elements = self.storage.elements.borrow_mut();
        let element = &mut elements[element.idx];
        element.default_namespace_uri = default_namespace;
        element.prefix_to_namespace = Bindings::Current(if bindings.is_empty() {
            None
        } else {
            Some(bindings.into_owned())
        });
        Ok(())
    }

    /// Only fresh nodes from the validated source mirror enter this builder;
    /// unlike the mutable native API there is no reparenting or replacement.
    pub(crate) fn append_root(&self, child: ChildOfRoot) -> Result<(), MemoryError> {
        self.work.charge_work(1)?;
        self.storage.roots.borrow_mut()[self.connections.root.idx]
            .children
            .try_push(child, self.work)?;
        let parent = Some(ParentOfChild::Root(self.connections.root));
        match child {
            ChildOfRoot::Element(node) => {
                let mut elements = self.storage.elements.borrow_mut();
                debug_assert!(elements[node.idx].parent.is_none());
                elements[node.idx].parent = parent;
            }
            ChildOfRoot::Comment(node) => {
                let mut comments = self.storage.comments.borrow_mut();
                debug_assert!(comments[node.idx].parent.is_none());
                comments[node.idx].parent = parent;
            }
            ChildOfRoot::ProcessingInstruction(node) => {
                let mut instructions = self.storage.processing_instructions.borrow_mut();
                debug_assert!(instructions[node.idx].parent.is_none());
                instructions[node.idx].parent = parent;
            }
        }
        Ok(())
    }

    pub(crate) fn append_element(
        &self,
        parent: Index<Element>,
        child: ChildOfElement,
    ) -> Result<(), MemoryError> {
        self.work.charge_work(1)?;
        self.storage.elements.borrow_mut()[parent.idx]
            .children
            .try_push(child, self.work)?;
        // The shared parent-link kernel observes the fresh child's empty old
        // parent and therefore neither scans nor reallocates another edge list.
        self.connections
            .replace_element_child_parent(self.storage, parent, child);
        Ok(())
    }

    pub(crate) fn attach_attribute(
        &self,
        parent: Index<Element>,
        child: Index<Attribute>,
    ) -> Result<(), MemoryError> {
        self.work.charge_work(1)?;
        self.storage.elements.borrow_mut()[parent.idx]
            .attributes
            .try_push(child, self.work)?;
        let mut attributes = self.storage.attributes.borrow_mut();
        debug_assert!(attributes[child.idx].parent.is_none());
        attributes[child.idx].parent = Some(parent);
        Ok(())
    }
}
