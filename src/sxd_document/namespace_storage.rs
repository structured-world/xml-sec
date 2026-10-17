//! Namespace tables retain their actual allocator; queries bring current work.

use super::{lazy_hash_map, string_pool::InternedString};

pub(crate) enum Bindings {
    Native(lazy_hash_map::LazyHashMap<InternedString, InternedString>),
    #[cfg(feature = "embedded")]
    Current(Option<structured_asn1::memory::OwnedMap<InternedString, InternedString>>),
}

impl Bindings {
    pub(crate) fn new() -> Self {
        Self::Native(lazy_hash_map::LazyHashMap::new())
    }

    fn native(&self) -> &lazy_hash_map::LazyHashMap<InternedString, InternedString> {
        match self {
            Self::Native(map) => map,
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current namespace reads require their execution"),
        }
    }

    pub(crate) fn get(&self, prefix: &str) -> Option<&InternedString> {
        self.native().get(prefix)
    }

    pub(crate) fn insert(
        &mut self,
        prefix: InternedString,
        uri: InternedString,
    ) -> Option<InternedString> {
        match self {
            Self::Native(map) => map.insert(prefix, uri),
            #[cfg(feature = "embedded")]
            Self::Current(_) => unreachable!("current declarations use their scoped builder"),
        }
    }

    pub(crate) fn iter(&self) -> lazy_hash_map::Iter<'_, InternedString, InternedString> {
        self.native().iter()
    }

    #[cfg(feature = "embedded")]
    pub(crate) fn visit<E>(
        &self,
        work: &impl structured_asn1::memory::Work,
        mut visit: impl FnMut(
            crate::sxd_document::string_pool::Label<'_>,
            crate::sxd_document::string_pool::Label<'_>,
        ) -> Result<(), E>,
    ) -> Result<Result<(), E>, structured_asn1::memory::MemoryError> {
        match self {
            Self::Native(map) => {
                work.charge_work(map.capacity() as u64)?;
                for (prefix, uri) in map.iter() {
                    if let Err(cause) = visit(prefix.label(), uri.label()) {
                        return Ok(Err(cause));
                    }
                }
            }
            Self::Current(Some(map)) => {
                for (prefix, uri) in map.try_iter(work)? {
                    if let Err(cause) = visit(prefix.label(), uri.label()) {
                        return Ok(Err(cause));
                    }
                }
            }
            Self::Current(None) => {}
        }
        Ok(Ok(()))
    }
}
