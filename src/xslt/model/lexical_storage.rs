//! Opening-tag workspace for the existing lexical scanner.

use std::cell::Cell;
use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

#[cfg(feature = "embedded")]
use crate::xml_input_shared as input;
#[cfg(not(feature = "embedded"))]
use xml_sec_xml_input as input;

use super::{BudgetKind, Error, Result, ensure};
use input::lexical::storage::{AttributeBuffer, Storage as ScannerStorage};
use input::lexical::{Attribute, Name};

#[derive(Clone, Copy)]
pub(super) struct Storage<'s> {
    pub limit: usize,
    pub held: &'s Cell<usize>,
    pub temporary: &'s Cell<usize>,
}

impl Storage<'_> {
    fn admit_bytes(self, bytes: usize) -> Result<()> {
        ensure(
            BudgetKind::OwnedBytes,
            self.limit,
            self.held
                .get()
                .saturating_add(self.temporary.get())
                .saturating_add(bytes),
        )
    }
    fn refused(self) -> Error {
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: self.limit,
            actual: usize::MAX,
        }
    }
}

impl<'s> ScannerStorage for Storage<'s> {
    type Label = String;
    type Refusal = Error;
    type Attributes<'a> = Attributes<'a, 's>;

    fn attributes<'a>(&self) -> Self::Attributes<'a> {
        Attributes {
            values: Vec::new(),
            storage: *self,
        }
    }
    fn admit(&self, _: usize) -> Result<()> {
        // The enclosing parser admits each complete text pass before scanning.
        Ok(())
    }
    fn qualified_name(&self, name: Name<'_>) -> Result<String> {
        let bytes = name.local().len() + name.prefix().map_or(0, |p| p.len() + 1);
        // The retained label and its formatted diagnostic coexist on refusal.
        self.admit_bytes(
            bytes
                .saturating_mul(2)
                .saturating_add("XML lexical error: duplicate attribute ``".len()),
        )?;
        input::lexical::storage::Native
            .qualified_name(name)
            .map_err(|_| self.refused())
    }
}

pub(super) struct Attributes<'a, 's> {
    values: Vec<Attribute<'a>>,
    storage: Storage<'s>,
}

impl Attributes<'_, '_> {
    pub fn bytes(&self) -> usize {
        self.values.capacity() * std::mem::size_of::<Attribute<'_>>()
    }
}

impl<'a> Deref for Attributes<'a, '_> {
    type Target = [Attribute<'a>];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl DerefMut for Attributes<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}
impl Drop for Attributes<'_, '_> {
    fn drop(&mut self) {
        self.storage
            .temporary
            .set(self.storage.temporary.get() - self.bytes());
    }
}

impl<'a, 's> AttributeBuffer<'a, Storage<'s>> for Attributes<'a, 's> {
    fn clear(&mut self) {
        self.values.clear();
    }
    fn push(&mut self, attribute: Attribute<'a>) -> Result<()> {
        if self.values.len() == self.values.capacity() {
            let capacity = self
                .values
                .capacity()
                .checked_mul(2)
                .ok_or_else(|| self.storage.refused())?
                .max(4);
            let requested = capacity
                .checked_mul(std::mem::size_of::<Attribute<'a>>())
                .ok_or_else(|| self.storage.refused())?;
            // Existing capacity is already temporary; admit the replacement
            // too before reserve/copy, and release the old block afterwards.
            self.storage.admit_bytes(requested)?;
            let old = self.bytes();
            self.values
                .try_reserve_exact(capacity - self.values.len())
                .map_err(|_| self.storage.refused())?;
            self.storage
                .temporary
                .set(self.storage.temporary.get() + self.bytes() - old);
            self.storage.admit_bytes(0)?;
        }
        self.values.push(attribute);
        Ok(())
    }
    fn sort(
        &mut self,
        mut compare: impl FnMut(&Attribute<'a>, &Attribute<'a>) -> Result<Ordering>,
    ) -> Result<()> {
        let mut failure = None;
        self.values.sort_unstable_by(|left, right| {
            if failure.is_some() {
                return Ordering::Equal;
            }
            match compare(left, right) {
                Ok(ordering) => ordering,
                Err(error) => {
                    failure = Some(error);
                    Ordering::Equal
                }
            }
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_admits_both_blocks_and_drop_releases_only_its_own() {
        // Two live opening tags share the same temporary total. Refusing a
        // replacement must preserve both tags and their original capacities.
        let unit = std::mem::size_of::<Attribute<'_>>();
        let held = Cell::new(0);
        let temporary = Cell::new(0);
        let storage = Storage {
            limit: 8 * unit,
            held: &held,
            temporary: &temporary,
        };
        let mut first = storage.attributes();
        let mut second = storage.attributes();
        let attribute = input::lexical::Scanner::new("<a x='v'/>")
            .next_event()
            .expect("fixed opening tag is valid")
            .and_then(|event| match event {
                input::lexical::Event::Empty(tag) => tag.attributes.into_iter().next(),
                _ => None,
            })
            .expect("fixed opening tag contains an attribute");
        for _ in 0..4 {
            first.push(attribute.clone()).expect("first buffer fits");
        }
        second.push(attribute.clone()).expect("both buffers fit");
        assert_eq!(temporary.get(), 8 * unit);
        assert!(matches!(first.push(attribute), Err(Error::Budget {
            kind: BudgetKind::OwnedBytes, limit, actual,
        }) if limit == 8 * unit && actual == 16 * unit));
        assert_eq!(first.len(), 4);
        assert_eq!(temporary.get(), 8 * unit);
        drop(first);
        assert_eq!(temporary.get(), 4 * unit);
        drop(second);
        assert_eq!(temporary.get(), 0);
    }
}
