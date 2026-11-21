use alloc::{borrow::ToOwned, rc::Rc, string::String};
use core::borrow::Borrow;
use core::str::FromStr;
use core::{cell::RefCell, fmt, hash, ops::Deref};
use structured_asn1::memory::{MemoryError, OwnedMap, SharedString, Work};

use crate::collections::Set;

#[cfg(not(feature = "embedded"))]
pub type StorageText = Rc<str>;

/// Retained labels keep the storage owner chosen when their arena was built.
#[cfg(feature = "embedded")]
#[derive(Clone)]
pub enum StorageText {
    Native(Rc<str>),
    Current(SharedString),
}

#[cfg(feature = "embedded")]
impl From<Rc<str>> for StorageText {
    fn from(value: Rc<str>) -> Self {
        Self::Native(value)
    }
}

#[cfg(feature = "embedded")]
impl Deref for StorageText {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            Self::Native(value) => value,
            Self::Current(value) => value,
        }
    }
}

/// A callback-scoped view preserves retained label ownership without a copy.
#[cfg(feature = "embedded")]
#[derive(Clone, Copy)]
pub enum Label<'a> {
    Borrowed(&'a str),
    Static(&'static str),
    Current(&'a SharedString),
}

#[cfg(feature = "embedded")]
impl<'a> Label<'a> {
    pub fn as_str(self) -> &'a str {
        match self {
            Self::Borrowed(text) | Self::Static(text) => text,
            Self::Current(text) => text,
        }
    }
}

#[cfg(feature = "embedded")]
impl Deref for Label<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(feature = "embedded")]
impl<'a> From<&'a str> for Label<'a> {
    fn from(text: &'a str) -> Self {
        Self::Borrowed(text)
    }
}

fn native_text(value: Rc<str>) -> StorageText {
    #[cfg(feature = "embedded")]
    {
        StorageText::Native(value)
    }
    #[cfg(not(feature = "embedded"))]
    {
        value
    }
}

#[derive(Clone)]
pub struct InternedString<S: Deref<Target = str> = StorageText>(S);

#[cfg(feature = "embedded")]
impl<S: Deref<Target = str>> structured_asn1::memory::HashWork for InternedString<S> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        structured_asn1::memory::HashWork::hash_work(&**self)
    }
}

impl InternedString {
    #[cfg(feature = "embedded")]
    pub(crate) fn label(&self) -> Label<'_> {
        match &self.0 {
            StorageText::Native(text) => Label::Borrowed(text),
            StorageText::Current(text) => Label::Current(text),
        }
    }
    #[allow(clippy::should_implement_trait)] // We implement FromStr; this is a convenience that returns T directly
    #[must_use]
    pub fn from_str(s: &str) -> InternedString {
        InternedString(native_text(Rc::<str>::from(s)))
    }
}

impl FromStr for InternedString {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(InternedString::from_str(s))
    }
}

impl<S: Deref<Target = str>> fmt::Debug for InternedString<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<S: Deref<Target = str>> fmt::Display for InternedString<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<S: Deref<Target = str>> PartialEq for InternedString<S> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

// Text order, consistent with the text equality above.
impl<S: Deref<Target = str>> PartialOrd for InternedString<S> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: Deref<Target = str>> Ord for InternedString<S> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (*self.0).cmp(&*other.0)
    }
}

impl<S: Deref<Target = str>> PartialEq<str> for InternedString<S> {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl<S: Deref<Target = str>> PartialEq<&str> for InternedString<S> {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl<S: Deref<Target = str>> PartialEq<InternedString<S>> for &str {
    fn eq(&self, other: &InternedString<S>) -> bool {
        *self == &*other.0
    }
}

impl<S: Deref<Target = str>> Eq for InternedString<S> {}

impl<S: Deref<Target = str>> hash::Hash for InternedString<S> {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        (*self.0).hash(state);
    }
}

impl<S: Deref<Target = str>> Borrow<str> for InternedString<S> {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<S: Deref<Target = str>> Deref for InternedString<S> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl<S: Deref<Target = str>> From<InternedString<S>> for String {
    fn from(s: InternedString<S>) -> String {
        s.deref().to_owned()
    }
}

impl<S: Deref<Target = str>> PartialEq<String> for InternedString<S> {
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other.as_str()
    }
}

trait PoolStorage {
    type Text: Clone + Deref<Target = str>;
    type Error;
    fn find(&self, text: &str) -> Result<Option<Self::Text>, Self::Error>;
    fn create(&self, text: &str) -> Result<Self::Text, Self::Error>;
    fn insert(&mut self, text: Self::Text) -> Result<(), Self::Error>;
}

// Both storage strategies use one lookup-before-create interning algorithm.
// In particular, a failed duplicate lookup cannot trigger a temporary string.
fn intern<S: PoolStorage>(
    storage: &RefCell<S>,
    text: &str,
) -> Result<InternedString<S::Text>, S::Error> {
    let mut storage = storage.borrow_mut();
    if let Some(existing) = storage.find(text)? {
        return Ok(InternedString(existing));
    }
    let value = storage.create(text)?;
    storage.insert(value.clone())?;
    Ok(InternedString(value))
}

#[derive(Default)]
struct NativePool(Set<Rc<str>>);
impl PoolStorage for NativePool {
    type Text = Rc<str>;
    type Error = core::convert::Infallible;
    fn find(&self, text: &str) -> Result<Option<Rc<str>>, Self::Error> {
        Ok(self.0.get(text).cloned())
    }
    fn create(&self, text: &str) -> Result<Rc<str>, Self::Error> {
        Ok(Rc::from(text))
    }
    fn insert(&mut self, text: Rc<str>) -> Result<(), Self::Error> {
        self.0.insert(text);
        Ok(())
    }
}

pub struct StringPool {
    index: RefCell<NativePool>,
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

impl StringPool {
    #[must_use]
    pub fn new() -> StringPool {
        StringPool {
            index: RefCell::new(NativePool::default()),
        }
    }

    pub fn intern(&self, s: &str) -> InternedString {
        if s.is_empty() {
            return InternedString::from_str("");
        }
        match intern(&self.index, s) {
            Ok(value) => InternedString(native_text(value.0)),
            Err(never) => match never {},
        }
    }
}

#[cfg(feature = "embedded")]
impl InternedString<SharedString> {
    pub(crate) fn into_retained(self) -> InternedString {
        InternedString(StorageText::Current(self.0))
    }
}

struct PaidPool<'w, W: Work> {
    index: OwnedMap<SharedString, (), W>,
    work: &'w W,
}
impl<W: Work> PoolStorage for PaidPool<'_, W> {
    type Text = SharedString;
    type Error = MemoryError;
    fn find(&self, text: &str) -> Result<Option<SharedString>, MemoryError> {
        Ok(self
            .index
            .get_key_value_borrowed(text, self.work)?
            .map(|(key, ())| key.clone()))
    }
    fn create(&self, text: &str) -> Result<SharedString, MemoryError> {
        SharedString::try_from_str(text, self.work)
    }
    fn insert(&mut self, text: SharedString) -> Result<(), MemoryError> {
        self.index.try_insert(text, ())?;
        Ok(())
    }
}

/// XML-owned interning with independently retained, fallibly created strings.
pub struct AccountedStringPool<'w, W: Work> {
    index: RefCell<PaidPool<'w, W>>,
}
impl<'w, W: Work> AccountedStringPool<'w, W> {
    /// Creates an empty interner without allocating storage.
    pub fn new(work: &'w W) -> Self {
        Self {
            index: RefCell::new(PaidPool {
                index: work.map(),
                work,
            }),
        }
    }
    /// Finds or creates a canonical string using this pool's current execution.
    ///
    /// # Errors
    /// Returns the pool's work, capacity or allocator refusal before storing
    /// a new entry; duplicate lookup still pays the current comparison work.
    pub fn intern(&self, text: &str) -> Result<InternedString<SharedString>, MemoryError> {
        intern(&self.index, text)
    }
    /// Reads retained strings using the supplied query, without rebinding growth.
    ///
    /// # Errors
    /// Returns a work refusal if the supplied query cannot fund lookup.
    pub fn find(
        &self,
        text: &str,
        current: &impl Work,
    ) -> Result<Option<InternedString<SharedString>>, MemoryError> {
        Ok(self
            .index
            .borrow()
            .index
            .get_key_value_borrowed(text, current)?
            .map(|(key, ())| InternedString(key.clone())))
    }
}

#[cfg(test)]
mod test {
    use super::StringPool;

    #[test]
    fn accounted_interning_retains_one_canonical_allocation() {
        // A borrowed duplicate lookup must not create a temporary shared string;
        // its canonical handle survives both source input and pool destruction.
        use structured_asn1::memory::{Memory, MemoryAccount, SharedString};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(8192, 65536)));
        let pool = super::AccountedStringPool::new(&memory);
        let first = pool
            .intern(&String::from("namespace"))
            .expect("initial intern");
        let used = memory.used();
        let second = pool.intern("namespace").expect("duplicate intern");
        assert_eq!(memory.used(), used);
        assert!(SharedString::ptr_eq(&first.0, &second.0));
        drop(pool);
        assert_eq!(&*first, "namespace");
        assert_eq!(memory.used(), first.0.allocated_bytes());
        drop(first);
        assert_eq!(&*second, "namespace");
        drop(second);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn retained_intern_lookup_uses_current_work_without_allocating() {
        // Original storage is not a licence to charge a completed producer;
        // a fresh query can clone the canonical key without any new capacity.
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError, Work},
        };
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(8192, 65536)));
        let producer = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 4096,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = producer.read(&[], 0).expect("empty producer");
        let work = reader.execution();
        let pool = super::AccountedStringPool::new(&work);
        let first = pool.intern("namespace").expect("initial intern");
        for shift in (0..=12).rev() {
            while work.charge_work(1 << shift).is_ok() {}
        }
        let held_capacity = memory
            .reserve(memory.limit() - memory.used())
            .expect("hold all remaining capacity");
        let query = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 65536)));
        let second = pool
            .find("namespace", &query)
            .expect("current lookup")
            .expect("canonical value");
        assert!(structured_asn1::memory::SharedString::ptr_eq(
            &first.0, &second.0
        ));
        assert_eq!(query.used(), 0);
        assert!(query.work_used() > 0);
        assert_eq!(
            pool.find("namespace", &work),
            Err(MemoryError::WorkExceeded)
        );
        drop(second);
        drop(first);
        drop(pool);
        drop(held_capacity);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn accounted_interning_refuses_storage_before_insertion() {
        // Failed string/table admission cannot leave a partially inserted key
        // or a leaked capacity charge in an otherwise empty interner.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 65536)));
        let pool = super::AccountedStringPool::new(&memory);
        assert_eq!(pool.intern("namespace"), Err(MemoryError::LimitExceeded));
        assert_eq!(pool.find("namespace", &memory).expect("empty lookup"), None);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn keeps_the_same_string() {
        let s = StringPool::new();
        let interned = s.intern("hello");
        assert_eq!(&*interned, "hello");
    }

    #[test]
    fn reuses_rc_for_repeated_input() {
        let s = StringPool::new();
        let interned1 = s.intern("world");
        let interned2 = s.intern("world");
        assert_eq!(&*interned1, &*interned2);
    }

    #[test]
    fn ignores_the_lifetime_of_the_input_string() {
        let s = StringPool::new();
        let interned = {
            let allocated_string = "green".to_owned();
            s.intern(&allocated_string)
        };
        assert_eq!(&*interned, "green");
    }

    #[test]
    fn can_be_dropped_immediately() {
        drop(StringPool::new());
    }

    #[test]
    fn does_not_reuse_the_pointer_of_the_input() {
        let s = StringPool::new();
        let input = "hello";
        let interned = s.intern(input);
        assert!(input.as_bytes().as_ptr() != interned.as_bytes().as_ptr());
    }

    #[test]
    fn can_return_storage_populated_with_values() {
        fn return_populated_storage() -> StringPool {
            let s = StringPool::new();
            s.intern("hello");
            s
        }
        let s = return_populated_storage();
        let interned = s.intern("hello");
        assert_eq!(&*interned, "hello");
    }
}
