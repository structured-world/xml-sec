//! Concrete arena ownership behind the stable SXD node handles.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "embedded")]
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

pub(crate) enum Values<T> {
    Native(Vec<T>),
    #[cfg(feature = "embedded")]
    Current(Option<OwnedVec<T>>),
}

impl<T> Values<T> {
    pub(crate) fn new() -> Self {
        Self::Native(Vec::new())
    }

    #[cfg(feature = "embedded")]
    pub(crate) fn current() -> Self {
        Self::Current(None)
    }

    pub(crate) fn push(&mut self, value: T) {
        match self {
            Self::Native(values) => values.push(value),
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current arena growth requires its execution"),
        }
    }

    #[cfg(feature = "embedded")]
    pub(crate) fn try_push<W: Work>(&mut self, value: T, work: &W) -> Result<(), MemoryError> {
        // Move the actual allocation through the execution boundary, never its
        // bytes. Restore it even if a downstream allocator unwinds.
        struct Restore<'a, T, W: Work> {
            target: &'a mut Option<OwnedVec<T>>,
            values: Option<OwnedVec<T, W>>,
        }
        impl<T, W: Work> Drop for Restore<'_, T, W> {
            fn drop(&mut self) {
                *self.target = Some(self.values.take().expect("live arena owner").into_owned());
            }
        }
        let Self::Current(values) = self else {
            unreachable!("current construction requires an execution-owned arena")
        };
        let execution = match values.take() {
            None => work.vector(),
            Some(retained) => match retained.with_execution(work) {
                Ok(values) => values,
                Err(retained) => {
                    *values = Some(retained);
                    return Err(MemoryError::WorkExceeded);
                }
            },
        };
        let mut restore = Restore {
            target: values,
            values: Some(execution),
        };
        restore
            .values
            .as_mut()
            .expect("live arena owner")
            .try_push(value)
    }

    pub(crate) fn clear(&mut self) {
        match self {
            Self::Native(values) => values.clear(),
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current arenas are immutable after construction"),
        }
    }

    pub(crate) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        match self {
            Self::Native(values) => values.retain(keep),
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current arenas are immutable after construction"),
        }
    }
}

impl<T: Clone> Values<T> {
    pub(crate) fn clone(&self) -> Vec<T> {
        match self {
            Self::Native(values) => values.clone(),
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current queries use borrowed arena accessors"),
        }
    }
}

impl<T> From<Vec<T>> for Values<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Native(value)
    }
}

impl<T> Deref for Values<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Self::Native(values) => values,
            #[cfg(feature = "embedded")]
            Self::Current(values) => values.as_ref().map_or(&[], |values| &**values),
        }
    }
}

impl<T> DerefMut for Values<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            Self::Native(values) => values,
            #[cfg(feature = "embedded")]
            Self::Current(values) => values.as_mut().map_or(&mut [], |values| &mut **values),
        }
    }
}

impl<'a, T> IntoIterator for &'a Values<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
