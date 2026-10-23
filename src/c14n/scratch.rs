//! Storage strategy for the one canonicalization kernel. The ordinary API
//! retains native storage; scoped `XMLDSig` uses the caller's actual execution.

use std::{cmp::Ordering, collections::HashMap, ops::Deref};

use super::C14nError;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NamespaceKey<'a> {
    pub prefix: &'a str,
    pub utilizer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NamespaceState<'a> {
    Absent,
    Excluded,
    Bound(&'a str),
}

impl<'a> NamespaceState<'a> {
    fn binding(entry: Option<&'a str>) -> Self {
        match entry {
            None => Self::Excluded,
            Some(uri) => Self::Bound(uri),
        }
    }

    pub(crate) fn uri(self) -> Option<&'a str> {
        match self {
            Self::Bound(uri) => Some(uri),
            Self::Absent | Self::Excluded => None,
        }
    }

    pub(crate) fn is_present(self) -> bool {
        self != Self::Absent
    }
}

pub(crate) trait NamespaceMap<'a>: Sized {
    fn get(&self, prefix: &str, utilizer: bool) -> Result<NamespaceState<'a>, C14nError>;
    fn insert(
        &mut self,
        prefix: &'a str,
        utilizer: bool,
        value: Option<&'a str>,
    ) -> Result<(), C14nError>;
    fn remove(&mut self, prefix: &'a str) -> Result<(), C14nError>;
    fn copy(&self) -> Result<Self, C14nError>;
}

pub(crate) trait List<T>: Deref<Target = [T]> + std::ops::DerefMut {
    #[cfg(feature = "xmldsig")]
    fn capacity(&self) -> usize;
    #[cfg(feature = "xmldsig")]
    fn reserve_exact(&mut self, additional: usize) -> Result<(), C14nError>;
    fn push(&mut self, value: T) -> Result<(), C14nError>;
    fn sort(
        &mut self,
        compare: impl FnMut(&T, &T) -> Result<Ordering, C14nError>,
    ) -> Result<(), C14nError>;
    fn pop(&mut self) -> Option<T>;
}

pub(crate) trait Text {
    fn view(&self) -> Result<&str, C14nError>;
}

pub(crate) trait TextBuilder {
    type Text: Text + Deref<Target = str>;
    fn append(&mut self, text: &str) -> Result<(), C14nError>;
    fn reserve(&mut self, bytes: usize) -> Result<(), C14nError>;
    fn last_byte(&self) -> Option<u8>;
    fn finish(self) -> Result<Self::Text, C14nError>;
}

#[cfg(feature = "xmldsig")]
pub(crate) trait Bytes: Deref<Target = [u8]> + std::ops::DerefMut {
    fn capacity(&self) -> usize;
    fn reserve(&mut self, additional: usize) -> Result<(), C14nError>;
    fn append(&mut self, bytes: &[u8]) -> Result<(), C14nError>;
    fn append_filtered(
        &mut self,
        bytes: &[u8],
        keep: impl FnMut(u8) -> bool,
    ) -> Result<(), C14nError>;
    fn zeros(&mut self, length: usize) -> Result<(), C14nError>;
    fn truncate(&mut self, length: usize);
}

#[cfg(feature = "xmldsig")]
impl Bytes for Vec<u8> {
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
    fn reserve(&mut self, additional: usize) -> Result<(), C14nError> {
        Vec::reserve(self, additional);
        Ok(())
    }
    fn append_filtered(
        &mut self,
        bytes: &[u8],
        mut keep: impl FnMut(u8) -> bool,
    ) -> Result<(), C14nError> {
        self.extend(bytes.iter().copied().filter(|byte| keep(*byte)));
        Ok(())
    }
    fn zeros(&mut self, length: usize) -> Result<(), C14nError> {
        self.resize(length, 0);
        Ok(())
    }
    fn truncate(&mut self, length: usize) {
        Vec::truncate(self, length);
    }
}

impl Text for String {
    fn view(&self) -> Result<&str, C14nError> {
        Ok(self)
    }
}

impl TextBuilder for String {
    type Text = String;
    fn reserve(&mut self, bytes: usize) -> Result<(), C14nError> {
        self.reserve_exact(bytes);
        Ok(())
    }
    fn last_byte(&self) -> Option<u8> {
        self.as_bytes().last().copied()
    }
    fn finish(self) -> Result<String, C14nError> {
        Ok(self)
    }
    fn append(&mut self, text: &str) -> Result<(), C14nError> {
        self.push_str(text);
        Ok(())
    }
}

pub(crate) trait Scratch {
    #[cfg(feature = "xmldsig")]
    const ACCOUNTED: bool;
    type Values<T>: List<T>;
    #[cfg(feature = "xmldsig")]
    type Bytes: Bytes;
    type Namespaces<'a>: NamespaceMap<'a>;
    type Text: Text + Deref<Target = str>;
    type Builder: TextBuilder<Text = Self::Text>;
    fn builder(&self) -> Self::Builder;
    fn values<T>(&self) -> Self::Values<T>;
    #[cfg(feature = "xmldsig")]
    fn bytes(&self) -> Self::Bytes;
    fn namespaces<'a>(&self) -> Self::Namespaces<'a>;
    fn charge(&self, bytes: usize) -> Result<(), C14nError>;
    fn text(&self, parts: &[&str]) -> Result<Self::Text, C14nError>;
}

pub(crate) type NamespaceRendering<'a, S> = (
    <S as Scratch>::Values<(&'a str, &'a str)>,
    <S as Scratch>::Namespaces<'a>,
);

pub(crate) struct Native;

impl<T> List<T> for Vec<T> {
    #[cfg(feature = "xmldsig")]
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    #[cfg(feature = "xmldsig")]
    fn reserve_exact(&mut self, additional: usize) -> Result<(), C14nError> {
        self.try_reserve_exact(additional).map_err(|_| {
            C14nError::SharedExecution(structured_asn1::memory::MemoryError::OutOfMemory)
        })
    }
    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }
    fn push(&mut self, value: T) -> Result<(), C14nError> {
        Vec::push(self, value);
        Ok(())
    }
    fn sort(
        &mut self,
        mut compare: impl FnMut(&T, &T) -> Result<Ordering, C14nError>,
    ) -> Result<(), C14nError> {
        let mut failure = None;
        self.sort_unstable_by(|left, right| {
            if failure.is_some() {
                return Ordering::Equal;
            }
            match compare(left, right) {
                Ok(order) => order,
                Err(error) => {
                    failure = Some(error);
                    Ordering::Equal
                }
            }
        });
        failure.map_or(Ok(()), Err)
    }
}

#[derive(Clone, Default)]
pub(crate) struct NativeNamespaces<'a>(HashMap<NamespaceKey<'a>, Option<&'a str>>);

#[cfg(test)]
impl<'a> NativeNamespaces<'a> {
    pub(super) fn into_pairs(self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.0.into_iter().filter_map(|(key, value)| {
            if key.utilizer {
                None
            } else {
                value.map(|uri| (key.prefix, uri))
            }
        })
    }
}

impl<'a> NamespaceMap<'a> for NativeNamespaces<'a> {
    fn get(&self, prefix: &str, utilizer: bool) -> Result<NamespaceState<'a>, C14nError> {
        Ok(self
            .0
            .get(&NamespaceKey { prefix, utilizer })
            .copied()
            .map_or(NamespaceState::Absent, NamespaceState::binding))
    }
    fn insert(
        &mut self,
        prefix: &'a str,
        utilizer: bool,
        value: Option<&'a str>,
    ) -> Result<(), C14nError> {
        self.0.insert(NamespaceKey { prefix, utilizer }, value);
        Ok(())
    }
    fn remove(&mut self, prefix: &'a str) -> Result<(), C14nError> {
        self.0.remove(&NamespaceKey {
            prefix,
            utilizer: false,
        });
        Ok(())
    }
    fn copy(&self) -> Result<Self, C14nError> {
        Ok(self.clone())
    }
}

impl Scratch for Native {
    #[cfg(feature = "xmldsig")]
    const ACCOUNTED: bool = false;
    type Values<T> = Vec<T>;
    #[cfg(feature = "xmldsig")]
    type Bytes = Vec<u8>;
    type Namespaces<'a> = NativeNamespaces<'a>;
    type Text = String;
    type Builder = String;
    fn builder(&self) -> String {
        String::new()
    }
    fn values<T>(&self) -> Vec<T> {
        Vec::new()
    }
    #[cfg(feature = "xmldsig")]
    fn bytes(&self) -> Self::Bytes {
        Vec::new()
    }
    fn namespaces<'a>(&self) -> NativeNamespaces<'a> {
        NativeNamespaces::default()
    }
    fn charge(&self, _bytes: usize) -> Result<(), C14nError> {
        Ok(())
    }
    fn text(&self, parts: &[&str]) -> Result<String, C14nError> {
        Ok(parts.concat())
    }
}

#[cfg(feature = "xmldsig")]
mod accounted {
    use super::{
        Bytes, C14nError, List, NamespaceKey, NamespaceMap, NamespaceState, Ordering, Scratch,
        Text, TextBuilder,
    };
    use structured_asn1::memory::{
        HashWork, MemoryError, OwnedMap, OwnedText, OwnedVec, SortError, TextErrorKind, Work,
    };

    pub(crate) struct Accounted<'w, W: Work>(pub &'w W);

    impl HashWork for NamespaceKey<'_> {
        fn hash_work(&self) -> Result<u64, MemoryError> {
            u64::try_from(self.prefix.len())
                .ok()
                .and_then(|n| n.checked_add(2))
                .ok_or(MemoryError::WorkExceeded)
        }
    }

    impl<T, W: Work> List<T> for OwnedVec<T, W> {
        fn capacity(&self) -> usize {
            OwnedVec::capacity(self)
        }
        fn reserve_exact(&mut self, additional: usize) -> Result<(), C14nError> {
            Ok(self.try_reserve_exact(additional)?)
        }
        fn pop(&mut self) -> Option<T> {
            OwnedVec::pop(self)
        }
        fn push(&mut self, value: T) -> Result<(), C14nError> {
            Ok(self.try_push(value)?)
        }
        fn sort(
            &mut self,
            compare: impl FnMut(&T, &T) -> Result<Ordering, C14nError>,
        ) -> Result<(), C14nError> {
            self.try_sort_unstable_by(compare)
                .map_err(|error| match error {
                    SortError::Resource(error) => C14nError::SharedExecution(error),
                    SortError::Comparison(error) => error,
                })
        }
    }

    impl<W: Work> Bytes for OwnedVec<u8, W> {
        fn capacity(&self) -> usize {
            OwnedVec::capacity(self)
        }
        fn append(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
            Ok(self.try_extend_from_slice(bytes)?)
        }
        fn reserve(&mut self, additional: usize) -> Result<(), C14nError> {
            Ok(self.try_reserve_exact(additional)?)
        }
        fn append_filtered(
            &mut self,
            bytes: &[u8],
            mut keep: impl FnMut(u8) -> bool,
        ) -> Result<(), C14nError> {
            let mut chunk = [0; 1024];
            let mut used = 0;
            for byte in bytes {
                if !keep(*byte) {
                    continue;
                }
                chunk[used] = *byte;
                used += 1;
                if used == chunk.len() {
                    self.try_extend_from_slice(&chunk)?;
                    used = 0;
                }
            }
            Ok(self.try_extend_from_slice(&chunk[..used])?)
        }
        fn zeros(&mut self, length: usize) -> Result<(), C14nError> {
            self.try_reserve_exact(length)?;
            while self.len() < length {
                let remaining = length - self.len();
                self.try_extend_from_slice(&[0; 256][..remaining.min(256)])?;
            }
            Ok(())
        }
        fn truncate(&mut self, length: usize) {
            while self.len() > length {
                self.pop();
            }
        }
    }

    pub(crate) struct AccountedNamespaces<'w, 'a, W: Work> {
        values: OwnedMap<NamespaceKey<'a>, Option<&'a str>, W>,
        work: &'w W,
    }

    pub(crate) struct AccountedTextBuilder<W: Work> {
        bytes: OwnedVec<u8, W>,
    }
    impl<W: Work> Text for OwnedText<W> {
        fn view(&self) -> Result<&str, C14nError> {
            Ok(self.as_str())
        }
    }
    impl<W: Work> TextBuilder for AccountedTextBuilder<W> {
        type Text = OwnedText<W>;
        fn reserve(&mut self, bytes: usize) -> Result<(), C14nError> {
            Ok(self.bytes.try_reserve_exact(bytes)?)
        }
        fn last_byte(&self) -> Option<u8> {
            self.bytes.last().copied()
        }
        fn finish(self) -> Result<Self::Text, C14nError> {
            OwnedText::from_utf8(self.bytes).map_err(|error| match error.kind() {
                TextErrorKind::Resource(cause) => cause.into(),
                TextErrorKind::Utf8(_) => unreachable!("only UTF-8 fragments are appended"),
            })
        }
        fn append(&mut self, text: &str) -> Result<(), C14nError> {
            Ok(self.bytes.try_extend_from_slice(text.as_bytes())?)
        }
    }

    impl<'a, W: Work> NamespaceMap<'a> for AccountedNamespaces<'_, 'a, W> {
        fn get(&self, prefix: &str, utilizer: bool) -> Result<NamespaceState<'a>, C14nError> {
            Ok(self
                .values
                .get(&NamespaceKey { prefix, utilizer }, self.work)?
                .copied()
                .map_or(NamespaceState::Absent, NamespaceState::binding))
        }
        fn insert(
            &mut self,
            prefix: &'a str,
            utilizer: bool,
            value: Option<&'a str>,
        ) -> Result<(), C14nError> {
            self.values
                .try_insert(NamespaceKey { prefix, utilizer }, value)?;
            Ok(())
        }
        fn remove(&mut self, prefix: &'a str) -> Result<(), C14nError> {
            self.values.remove(
                &NamespaceKey {
                    prefix,
                    utilizer: false,
                },
                self.work,
            )?;
            Ok(())
        }
        fn copy(&self) -> Result<Self, C14nError> {
            let mut values = self.work.map();
            for (key, value) in self.values.try_iter(self.work)? {
                values.try_insert(*key, *value)?;
            }
            Ok(Self {
                values,
                work: self.work,
            })
        }
    }

    impl<'w, W: Work> Scratch for Accounted<'w, W> {
        const ACCOUNTED: bool = true;
        type Values<T> = OwnedVec<T, W>;
        type Bytes = OwnedVec<u8, W>;
        type Namespaces<'a> = AccountedNamespaces<'w, 'a, W>;
        type Text = OwnedText<W>;
        type Builder = AccountedTextBuilder<W>;
        fn builder(&self) -> Self::Builder {
            AccountedTextBuilder {
                bytes: self.0.vector(),
            }
        }
        fn values<T>(&self) -> Self::Values<T> {
            self.0.vector()
        }
        fn bytes(&self) -> Self::Bytes {
            self.0.vector()
        }
        fn namespaces<'a>(&self) -> Self::Namespaces<'a> {
            AccountedNamespaces {
                values: self.0.map(),
                work: self.0,
            }
        }
        fn charge(&self, bytes: usize) -> Result<(), C14nError> {
            self.0
                .charge_work(u64::try_from(bytes).map_err(|_| MemoryError::WorkExceeded)?)?;
            Ok(())
        }
        fn text(&self, parts: &[&str]) -> Result<Self::Text, C14nError> {
            if let [text] = parts {
                return Ok(OwnedText::try_from_str(text, self.0)?);
            }
            let mut text = self.builder();
            let length = parts
                .iter()
                .try_fold(0usize, |n, part| n.checked_add(part.len()))
                .ok_or(MemoryError::CapacityOverflow)?;
            text.reserve(length)?;
            for part in parts {
                text.append(part)?;
            }
            text.finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};

        #[test]
        fn refused_uri_text_validation_releases_buffer_and_preserves_cause() {
            // Exhaust the local query after construction: freezing must refuse
            // before scanning and release the consumed builder's allocation.
            use structured_asn1::{Encoding, Limits, Parser};
            let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 20)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: 4096,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).expect("empty query carrier");
            let work = reader.execution();
            let mut builder = Accounted(&work).builder();
            builder.append("fragment").expect("first URI fragment fits");
            builder.append("/tail").expect("second URI fragment fits");
            assert!(
                memory.used() > 0,
                "unfinished builder retains actual capacity"
            );
            work.charge_work((4096 - memory.work_used()) as u64)
                .expect("exhaust local query work");
            let before = memory.work_used();
            assert!(matches!(
                builder.finish(),
                Err(C14nError::SharedExecution(MemoryError::WorkExceeded))
            ));
            assert_eq!(memory.work_used(), before, "no scan before admission");
            assert_eq!(memory.used(), 0);
        }

        #[test]
        fn repeated_uri_text_views_do_not_rescan_or_copy_utf8() {
            // URI resolution reads completed fragments several times. Each
            // immutable view must reuse validation and the same allocation.
            let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 20)));
            let mut builder = Accounted(&memory).builder();
            builder.reserve(16).expect("fixed URI capacity fits");
            builder.append("urn:").expect("URI scheme fits");
            builder.append("example").expect("URI path fits");
            builder.append("/next").expect("URI suffix fits");
            let original_pointer = builder.bytes.as_ptr();
            let capacity = memory.used();
            let text = builder.finish().expect("complete UTF-8 URI");
            assert_eq!(
                text.as_bytes().as_ptr(),
                original_pointer,
                "zero-copy finish"
            );
            assert_eq!(memory.used(), capacity, "finishing does not allocate");
            let pointer = text.view().expect("first UTF-8 view").as_ptr();
            let work = memory.work_used();
            assert_eq!(text.view().expect("repeated view"), "urn:example/next");
            assert_eq!(text.view().expect("same allocation").as_ptr(), pointer);
            assert_eq!(memory.work_used(), work, "no repeated UTF-8 scan");
            assert_eq!(memory.used(), capacity, "no view allocation");
            drop(text);
            assert_eq!(memory.used(), 0, "final storage owner releases capacity");
        }
    }
}

#[cfg(feature = "xmldsig")]
pub(crate) use accounted::Accounted;

#[cfg(test)]
mod namespace_tests;
