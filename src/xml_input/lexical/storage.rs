//! Allocation vocabulary for the one lexical scanner.

use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
};

use super::{Attribute, Name};

/// Scanner construction boundary, not an XML acceptance policy.
pub trait Storage: Copy {
    /// A completed diagnostic's retained text.
    type Label: Debug + Display;
    /// A storage or execution refusal.
    type Refusal: Debug + Display;
    /// Attributes retained in their original source order.
    type Attributes<'a>: AttributeBuffer<'a, Self>;
    /// Start an empty attribute buffer.
    fn attributes<'a>(&self) -> Self::Attributes<'a>;
    /// Admit scanner/comparison work before executing it.
    fn admit(&self, units: usize) -> Result<(), Self::Refusal>;
    /// Retain a diagnostic `QName`, allocating only on the cold failure path.
    fn qualified_name(&self, name: Name<'_>) -> Result<Self::Label, Self::Refusal>;
}

/// Fallible storage for one complete opening tag's attributes.
pub trait AttributeBuffer<'a, S: Storage>: Deref<Target = [Attribute<'a>]> + DerefMut {
    /// Append one borrowed attribute, admitting actual growth first.
    fn push(&mut self, attribute: Attribute<'a>) -> Result<(), S::Refusal>;
    /// Empty the buffer for the next tag, or release it when its capacity
    /// would stay charged against an operation's memory budget.
    fn into_reusable(self) -> Option<Self>
    where
        Self: Sized;
    /// In-place ordering without a second allocation.
    fn sort(
        &mut self,
        compare: impl FnMut(&Attribute<'a>, &Attribute<'a>) -> Result<Ordering, S::Refusal>,
    ) -> Result<(), S::Refusal>;
}

/// Native standalone specialization, with fallible allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Native;

impl Storage for Native {
    type Label = String;
    type Refusal = TryReserveError;
    type Attributes<'a> = Vec<Attribute<'a>>;

    fn attributes<'a>(&self) -> Self::Attributes<'a> {
        Vec::new()
    }
    fn admit(&self, _: usize) -> Result<(), TryReserveError> {
        Ok(())
    }
    fn qualified_name(&self, name: Name<'_>) -> Result<String, TryReserveError> {
        let mut label = String::new();
        // Both parts borrow one actual QName in the bounded source input.
        label.try_reserve_exact(
            name.prefix.len() + name.local.len() + usize::from(!name.prefix.is_empty()),
        )?;
        if !name.prefix.is_empty() {
            label.push_str(name.prefix);
            label.push(':');
        }
        label.push_str(name.local);
        Ok(label)
    }
}

impl<'a, S: Storage<Refusal = TryReserveError>> AttributeBuffer<'a, S> for Vec<Attribute<'a>> {
    fn push(&mut self, attribute: Attribute<'a>) -> Result<(), TryReserveError> {
        self.try_reserve(1)?;
        Vec::push(self, attribute);
        Ok(())
    }
    fn into_reusable(mut self) -> Option<Self> {
        // No budget can refuse later work here, and capacity is bounded by the input.
        Vec::clear(&mut self);
        Some(self)
    }
    fn sort(
        &mut self,
        mut compare: impl FnMut(&Attribute<'a>, &Attribute<'a>) -> Result<Ordering, TryReserveError>,
    ) -> Result<(), TryReserveError> {
        // Native admission cannot refuse comparisons. Keep the callback's
        // first refusal if a caller supplies one through this generic API.
        let mut failure = None;
        self.sort_unstable_by(|left, right| {
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
