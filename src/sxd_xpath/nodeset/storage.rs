//! Native compatibility storage and the current query's retained table.

#[cfg(feature = "embedded")]
use super::Nodeset;
use super::{Node, Set};

#[derive(Debug)]
pub(crate) enum Storage<'d> {
    Native(Set<Node<'d>>),
    #[cfg(feature = "embedded")]
    Current(structured_asn1::memory::OwnedMap<Node<'d>, ()>),
}

impl Default for Storage<'_> {
    fn default() -> Self {
        Self::Native(Set::new())
    }
}

impl Clone for Storage<'_> {
    fn clone(&self) -> Self {
        Self::Native(self.native().clone())
    }
}

impl PartialEq for Storage<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.native() == other.native()
    }
}

impl<'d> Storage<'d> {
    #[expect(
        clippy::mutable_key_type,
        reason = "node keys hash immutable arena/slot identity, not mutable DOM contents"
    )]
    pub(super) fn native(&self) -> &Set<Node<'d>> {
        match self {
            Self::Native(nodes) => nodes,
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current node-set reads require their execution"),
        }
    }

    #[expect(
        clippy::mutable_key_type,
        reason = "node keys hash immutable arena/slot identity, not mutable DOM contents"
    )]
    pub(super) fn native_mut(&mut self) -> &mut Set<Node<'d>> {
        match self {
            Self::Native(nodes) => nodes,
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current node-set growth requires its execution"),
        }
    }

    #[expect(
        clippy::mutable_key_type,
        reason = "moving the set preserves immutable node identities and namespace labels"
    )]
    pub(super) fn into_native(self) -> Set<Node<'d>> {
        match self {
            Self::Native(nodes) => nodes,
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current node-sets use borrowed funded traversal"),
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Native(nodes) => nodes.len(),
            #[cfg(feature = "embedded")]
            Self::Current(nodes) => nodes.len(),
        }
    }
}

#[cfg(feature = "embedded")]
impl<'d> Nodeset<'d> {
    pub(crate) fn current(nodes: structured_asn1::memory::OwnedMap<Node<'d>, ()>) -> Self {
        Self {
            nodes: Storage::Current(nodes),
        }
    }

    pub(crate) fn into_storage(self) -> Storage<'d> {
        self.nodes
    }

    pub(crate) fn iter_current<'a, W: structured_asn1::memory::Work>(
        &'a self,
        work: &W,
    ) -> Result<impl Iterator<Item = &'a Node<'d>> + 'a, structured_asn1::memory::MemoryError> {
        let (native, current) = match &self.nodes {
            Storage::Native(nodes) => {
                use crate::collections::Table as _;
                work.charge_work(nodes.entry_capacity() as u64)?;
                (Some(nodes.iter()), None)
            }
            Storage::Current(nodes) => (None, Some(nodes.try_iter(work)?)),
        };
        Ok(native
            .into_iter()
            .flatten()
            .chain(current.into_iter().flatten().map(|(node, ())| node)))
    }
}
