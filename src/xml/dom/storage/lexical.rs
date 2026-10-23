//! Scoped storage for the existing parser-neutral lexical scanner.

use core::cmp::Ordering;

use structured_asn1::memory::{MemoryError, OwnedText, OwnedVec, SortError, TextErrorKind, Work};

use super::Accounted;
use crate::xml_input::lexical::{
    Attribute, Name,
    storage::{AttributeBuffer, Storage},
};

impl<W: Work> Storage for Accounted<'_, W> {
    type Label = OwnedText<W>;
    type Refusal = MemoryError;
    type Attributes<'a> = OwnedVec<Attribute<'a>, W>;

    fn attributes<'a>(&self) -> Self::Attributes<'a> {
        self.0.vector()
    }
    fn admit(&self, units: usize) -> Result<(), MemoryError> {
        self.0
            .charge_work(u64::try_from(units).map_err(|_| MemoryError::WorkExceeded)?)
    }
    fn qualified_name(&self, name: Name<'_>) -> Result<OwnedText<W>, MemoryError> {
        let Some(prefix) = name.prefix() else {
            return OwnedText::try_from_str(name.local(), self.0);
        };
        let capacity = prefix
            .len()
            .checked_add(name.local().len())
            .and_then(|n| n.checked_add(1))
            .ok_or(MemoryError::LimitExceeded)?;
        let mut bytes = self.0.vector();
        bytes.try_reserve_exact(capacity)?;
        bytes.try_extend_from_slice(prefix.as_bytes())?;
        bytes.try_push(b':')?;
        bytes.try_extend_from_slice(name.local().as_bytes())?;
        OwnedText::from_utf8(bytes).map_err(|error| match error.kind() {
            TextErrorKind::Resource(error) => error,
            TextErrorKind::Utf8(_) => unreachable!("a QName consists of valid UTF-8 parts"),
        })
    }
}

impl<'a, W: Work> AttributeBuffer<'a, Accounted<'_, W>> for OwnedVec<Attribute<'a>, W> {
    fn push(&mut self, attribute: Attribute<'a>) -> Result<(), MemoryError> {
        self.try_push(attribute)
    }
    fn sort(
        &mut self,
        compare: impl FnMut(&Attribute<'a>, &Attribute<'a>) -> Result<Ordering, MemoryError>,
    ) -> Result<(), MemoryError> {
        self.try_sort_unstable_by(compare)
            .map_err(|error| match error {
                SortError::Resource(error) | SortError::Comparison(error) => error,
            })
    }
}
