use std::borrow::Borrow;
use std::str::FromStr;
use std::{cell::RefCell, collections::HashSet, fmt, hash, ops::Deref, rc::Rc};

#[derive(Clone)]
pub struct InternedString(Rc<str>);

impl InternedString {
    #[allow(clippy::should_implement_trait)] // We implement FromStr; this is a convenience that returns T directly
    pub fn from_str(s: &str) -> InternedString {
        InternedString(Rc::from(s))
    }
}

impl FromStr for InternedString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(InternedString::from_str(s))
    }
}

impl fmt::Debug for InternedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for InternedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for InternedString {
    fn eq(&self, other: &InternedString) -> bool {
        *self.0 == *other.0
    }
}

impl PartialEq<str> for InternedString {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for InternedString {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl PartialEq<InternedString> for &str {
    fn eq(&self, other: &InternedString) -> bool {
        *self == &*other.0
    }
}

impl Eq for InternedString {}

impl hash::Hash for InternedString {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        (*self.0).hash(state)
    }
}

impl Borrow<str> for InternedString {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Deref for InternedString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<InternedString> for String {
    fn from(s: InternedString) -> String {
        s.0.as_ref().to_owned()
    }
}

impl PartialEq<String> for InternedString {
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other.as_str()
    }
}

pub struct StringPool {
    index: RefCell<HashSet<Rc<str>>>,
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

impl StringPool {
    pub fn new() -> StringPool {
        StringPool {
            index: RefCell::new(HashSet::new()),
        }
    }

    pub fn intern(&self, s: &str) -> InternedString {
        if s.is_empty() {
            return InternedString::from_str("");
        }

        let mut index = self.index.borrow_mut();
        if let Some(existing) = index.get(s) {
            return InternedString(Rc::clone(existing));
        }

        let rc: Rc<str> = Rc::from(s);
        index.insert(Rc::clone(&rc));
        InternedString(rc)
    }
}

#[cfg(test)]
mod test {
    use super::StringPool;

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
        StringPool::new();
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
