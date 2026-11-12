//! The ID table of an [`OwnedTree`](super::OwnedTree): each ID value names
//! the attribute that carries it, so an edit of that attribute finds and
//! updates its entry, as libxml2 ties an ID to its attribute.

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::TreeNode;

/// The attribute an ID value belongs to: an element and the attribute's
/// expanded name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct IdSource {
    pub(super) element: TreeNode,
    pub(super) name: String,
    pub(super) namespace: Option<String>,
}

impl IdSource {
    /// Whether this is the attribute `name` in `namespace` of `element`.
    pub(super) fn is(&self, element: TreeNode, name: &str, namespace: Option<&str>) -> bool {
        self.element == element && self.name == name && self.namespace.as_deref() == namespace
    }
}

/// ID values and the attributes that carry them, indexed both ways, with the
/// further attributes that carried a value another one already held when
/// they arrived (a repeated `xml:id` in a parse, a copy, a replacement).
/// Those stay unregistered, as libxml2 leaves them, but a lookup sees them,
/// so a value two linked elements carry names neither.
#[derive(Default)]
pub(super) struct IdTable {
    by_value: BTreeMap<String, IdSource>,
    by_source: BTreeMap<IdSource, String>,
    shadowed: BTreeMap<String, Vec<IdSource>>,
}

impl IdTable {
    /// The attribute `value` names.
    pub(super) fn get(&self, value: &str) -> Option<&IdSource> {
        self.by_value.get(value)
    }

    /// Make `value` name `source`, which then carries no other value; the
    /// attribute `value` named before is returned.
    pub(super) fn insert(&mut self, value: String, source: IdSource) -> Option<IdSource> {
        self.remove_source(&source);
        let previous = self.by_value.insert(value.clone(), source.clone());
        if let Some(previous) = &previous {
            self.by_source.remove(previous);
        }
        self.by_source.insert(source, value);
        previous
    }

    /// Records `source` as a further carrier of `value`, which another
    /// attribute holds.
    pub(super) fn shadow(&mut self, value: String, source: IdSource) {
        let carriers = self.shadowed.entry(value).or_default();
        if !carriers.contains(&source) {
            carriers.push(source);
        }
    }

    /// The further carriers recorded for `value`; some may no longer carry
    /// it or no longer be live.
    pub(super) fn shadowed(&self, value: &str) -> &[IdSource] {
        self.shadowed.get(value).map_or(&[], Vec::as_slice)
    }

    /// The attributes of `element` that carry an ID, with their values.
    pub(super) fn of_element(&self, element: TreeNode) -> impl Iterator<Item = (&IdSource, &str)> {
        let first = IdSource {
            element,
            name: String::new(),
            namespace: None,
        };
        self.by_source
            .range(first..)
            .take_while(move |(source, _)| source.element == element)
            .map(|(source, value)| (source, value.as_str()))
    }

    /// Whether `source` carries an ID.
    pub(super) fn carries(&self, source: &IdSource) -> bool {
        self.by_source.contains_key(source)
    }

    /// Drop the entry of `value`.
    pub(super) fn remove(&mut self, value: &str) {
        if let Some(source) = self.by_value.remove(value) {
            self.by_source.remove(&source);
        }
    }

    /// Drop the entry `source` carries; its value is returned.
    pub(super) fn remove_source(&mut self, source: &IdSource) -> Option<String> {
        let value = self.by_source.remove(source)?;
        self.by_value.remove(&value);
        Some(value)
    }
}
