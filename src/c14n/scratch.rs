//! Storage strategy for the one canonicalization kernel. The ordinary API
//! retains native storage; scoped XMLDSig uses the caller's actual execution.

use std::{cmp::Ordering, collections::HashMap, ops::Deref};

use super::C14nError;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NamespaceKey<'a> {
    pub prefix: &'a str,
    pub utilizer: bool,
}

pub(crate) trait NamespaceMap<'a>: Sized {
    fn get(&self, prefix: &str, utilizer: bool) -> Result<Option<Option<&'a str>>, C14nError>;
    fn insert(
        &mut self,
        prefix: &'a str,
        utilizer: bool,
        value: Option<&'a str>,
    ) -> Result<(), C14nError>;
    fn remove(&mut self, prefix: &'a str) -> Result<(), C14nError>;
    fn copy(&self) -> Result<Self, C14nError>;
}

pub(crate) trait List<T>: Deref<Target = [T]> {
    fn push(&mut self, value: T) -> Result<(), C14nError>;
    fn sort(
        &mut self,
        compare: impl FnMut(&T, &T) -> Result<Ordering, C14nError>,
    ) -> Result<(), C14nError>;
    fn pop(&mut self) -> Option<T>;
}

pub(crate) trait Text {
    fn view(&self) -> Result<&str, C14nError>;
    fn append(&mut self, text: &str) -> Result<(), C14nError>;
    fn reserve(&mut self, bytes: usize) -> Result<(), C14nError>;
}

impl Text for String {
    fn reserve(&mut self, bytes: usize) -> Result<(), C14nError> {
        self.reserve_exact(bytes);
        Ok(())
    }
    fn view(&self) -> Result<&str, C14nError> {
        Ok(self)
    }
    fn append(&mut self, text: &str) -> Result<(), C14nError> {
        self.push_str(text);
        Ok(())
    }
}

pub(crate) trait Scratch {
    type Values<T>: List<T>;
    type Namespaces<'a>: NamespaceMap<'a>;
    type Text: Text;
    fn values<T>(&self) -> Self::Values<T>;
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
    fn get(&self, prefix: &str, utilizer: bool) -> Result<Option<Option<&'a str>>, C14nError> {
        Ok(self.0.get(&NamespaceKey { prefix, utilizer }).copied())
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
    type Values<T> = Vec<T>;
    type Namespaces<'a> = NativeNamespaces<'a>;
    type Text = String;
    fn values<T>(&self) -> Vec<T> {
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
    use super::*;
    use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, SortError, Work};

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

    pub(crate) struct AccountedNamespaces<'w, 'a, W: Work> {
        values: OwnedMap<NamespaceKey<'a>, Option<&'a str>, W>,
        work: &'w W,
    }

    pub(crate) struct AccountedText<'w, W: Work> {
        bytes: OwnedVec<u8, W>,
        work: &'w W,
    }
    impl<W: Work> Text for AccountedText<'_, W> {
        fn reserve(&mut self, bytes: usize) -> Result<(), C14nError> {
            Ok(self.bytes.try_reserve_exact(bytes)?)
        }
        fn view(&self) -> Result<&str, C14nError> {
            self.work.charge_work(self.bytes.len() as u64)?;
            Ok(std::str::from_utf8(&self.bytes).expect("only UTF-8 fragments are appended"))
        }
        fn append(&mut self, text: &str) -> Result<(), C14nError> {
            Ok(self.bytes.try_extend_from_slice(text.as_bytes())?)
        }
    }

    impl<'a, W: Work> NamespaceMap<'a> for AccountedNamespaces<'_, 'a, W> {
        fn get(&self, prefix: &str, utilizer: bool) -> Result<Option<Option<&'a str>>, C14nError> {
            Ok(self
                .values
                .get(&NamespaceKey { prefix, utilizer }, self.work)?
                .copied())
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
        type Values<T> = OwnedVec<T, W>;
        type Namespaces<'a> = AccountedNamespaces<'w, 'a, W>;
        type Text = AccountedText<'w, W>;
        fn values<T>(&self) -> Self::Values<T> {
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
            let mut text = AccountedText {
                bytes: self.0.vector(),
                work: self.0,
            };
            let length = parts
                .iter()
                .try_fold(0usize, |n, part| n.checked_add(part.len()))
                .ok_or(MemoryError::CapacityOverflow)?;
            text.bytes.try_reserve_exact(length)?;
            for part in parts {
                text.append(part)?;
            }
            Ok(text)
        }
    }
}

#[cfg(feature = "xmldsig")]
pub(crate) use accounted::Accounted;
