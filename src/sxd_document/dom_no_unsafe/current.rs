//! Construction-only access to a current-owned mirror arena.

use super::*;
use structured_asn1::memory::{MemoryError, Work};

pub(crate) struct Builder<'d, 'w, W: Work> {
    document: Document<'d>,
    raw: raw::current::Builder<'d, 'w, W>,
}

impl<'d, 'w, W: Work> Builder<'d, 'w, W> {
    pub(crate) fn new(document: Document<'d>, work: &'w W) -> Self {
        Self {
            document,
            raw: raw::current::Builder::new(document.storage, document.connections, work),
        }
    }

    pub(crate) fn element(&self, name: QName<'_>) -> Result<Element<'d>, MemoryError> {
        self.raw
            .element(name)
            .map(|node| self.document.wrap_element(node))
    }

    pub(crate) fn attribute(
        &self,
        parent: Element<'d>,
        name: QName<'_>,
        value: &str,
    ) -> Result<Attribute<'d>, MemoryError> {
        let node = self.raw.attribute(name, value)?;
        self.raw.attach_attribute(parent.node, node)?;
        Ok(self.document.wrap_attribute(node))
    }

    pub(crate) fn text(&self, value: &str) -> Result<Text<'d>, MemoryError> {
        self.raw
            .text(value)
            .map(|node| self.document.wrap_text(node))
    }

    pub(crate) fn comment(&self, value: &str) -> Result<Comment<'d>, MemoryError> {
        self.raw
            .comment(value)
            .map(|node| self.document.wrap_comment(node))
    }

    pub(crate) fn pi(
        &self,
        target: &str,
        value: Option<&str>,
    ) -> Result<ProcessingInstruction<'d>, MemoryError> {
        self.raw
            .pi(target, value)
            .map(|node| self.document.wrap_pi(node))
    }

    pub(crate) fn append_root(&self, child: ChildOfRoot<'d>) -> Result<(), MemoryError> {
        assert_eq!(child.document(), self.document);
        self.raw.append_root(child.as_raw())
    }

    pub(crate) fn append_element(
        &self,
        parent: Element<'d>,
        child: ChildOfElement<'d>,
    ) -> Result<(), MemoryError> {
        assert_eq!(parent.document, self.document);
        assert_eq!(child.document(), self.document);
        self.raw.append_element(parent.node, child.as_raw())
    }

    pub(crate) fn element_prefix(
        &self,
        element: Element<'d>,
        prefix: Option<&str>,
    ) -> Result<(), MemoryError> {
        self.raw.preferred_element_prefix(element.node, prefix)
    }

    pub(crate) fn attribute_prefix(
        &self,
        attribute: Attribute<'d>,
        prefix: Option<&str>,
    ) -> Result<(), MemoryError> {
        self.raw.preferred_attribute_prefix(attribute.node, prefix)
    }

    pub(crate) fn default_namespace(
        &self,
        element: Element<'d>,
        uri: Option<&str>,
    ) -> Result<(), MemoryError> {
        self.raw.default_namespace(element.node, uri)
    }

    pub(crate) fn namespace_declarations<'a>(
        &self,
        element: Element<'d>,
        declarations: impl Iterator<Item = (Option<&'a str>, &'a str)>,
    ) -> Result<(), MemoryError> {
        self.raw.namespace_declarations(element.node, declarations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[test]
    fn current_arena_owns_nodes_edges_attributes_and_interned_labels() {
        // Retained node handles keep reading the same arena after the interner
        // is dropped; only the arena's actual allocations remain charged.
        let work = Memory::new(Arc::new(MemoryAccount::new(65536, 1 << 20)));
        let package = crate::sxd_document::Package::try_current(&work).unwrap();
        let document = package.as_document();
        {
            let builder = Builder::new(document, &work);
            let root = builder.element(QName::new("root")).unwrap();
            builder.append_root(root.into()).unwrap();
            let attribute = builder.attribute(root, QName::new("id"), "value").unwrap();
            builder.attribute_prefix(attribute, None).unwrap();
            builder.element_prefix(root, None).unwrap();
            builder.default_namespace(root, None).unwrap();
            builder
                .append_element(root, builder.text("text").unwrap().into())
                .unwrap();
            builder
                .append_element(root, builder.comment("comment").unwrap().into())
                .unwrap();
            builder
                .append_root(builder.pi("target", Some("value")).unwrap().into())
                .unwrap();
            assert_eq!(root.attributes_len(), 1);
            assert_eq!(root.children_len(), 2);
        }
        let root = document.root().child_at(0).unwrap().element().unwrap();
        assert_eq!(&*root.name().local_part_clone(), "root");
        assert_eq!(&*root.attribute_value("id").unwrap(), "value");
        assert_eq!(&*root.child_at(0).unwrap().text().unwrap().text(), "text");
        assert!(work.used() > 0);
        drop(package);
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn current_arena_refuses_before_storage_or_edge_growth() {
        // Exhausted capacity never starts a native arena as a fallback.
        let empty = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert!(matches!(
            crate::sxd_document::Package::try_current(&empty),
            Err(MemoryError::LimitExceeded)
        ));
        assert_eq!(empty.used(), 0);
    }
}
