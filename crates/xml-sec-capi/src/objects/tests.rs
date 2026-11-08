use super::{Failure, KeyLookup, Keys, LookupScope};
use parking_lot::Mutex;
use std::sync::Arc;
use xml_sec::policy::ResourcePolicy;

const KW_AES128: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes128";

/// Imports an AES key under each name asked for, or under "found" when the
/// request names none, as an application store would; records every request.
#[derive(Default)]
struct Recording {
    asked: Mutex<Vec<(Vec<String>, String)>>,
}

impl KeyLookup for Recording {
    /// Record the request and import a key under every name it carries.
    fn lookup(&self, names: &[&str], method: &str, keys: &Arc<Keys>) -> Result<(), Failure> {
        self.asked.lock().push((
            names.iter().map(|name| (*name).to_owned()).collect(),
            method.to_owned(),
        ));
        let names = if names.is_empty() {
            &["found"][..]
        } else {
            names
        };
        for name in names {
            keys.add_symmetric(name, 2, &[7; 16], 8)?;
        }
        Ok(())
    }
}

/// A later request naming an imported key and a new one asks only for the
/// new one: asking again would make the store import the first key twice,
/// which the key manager refuses, and fail the whole call.
#[test]
fn a_lookup_is_asked_only_for_names_it_has_not_imported() {
    let store = Recording::default();
    let scope = LookupScope::new(&store);
    let resources = ResourcePolicy::default();
    let (_, imported) = scope.fill(&["a"], KW_AES128, &resources).unwrap();
    assert_eq!(imported, ["a"]);
    let (_, imported) = scope.fill(&["a", "b"], KW_AES128, &resources).unwrap();
    assert_eq!(imported, ["b"]);
    let (_, imported) = scope.fill(&["b", "a"], KW_AES128, &resources).unwrap();
    assert_eq!(imported, Vec::<String>::new());
    assert_eq!(
        *store.asked.lock(),
        [
            (vec!["a".to_owned()], KW_AES128.to_owned()),
            (vec!["b".to_owned()], KW_AES128.to_owned()),
        ]
    );
    assert!(scope.into_failure().is_none());
}

/// A `KeyInfo` may give one `KeyName` twice; the store must not be asked to
/// import that key twice, which the key manager refuses.
#[test]
fn a_name_the_document_repeats_is_asked_for_once() {
    let store = Recording::default();
    let scope = LookupScope::new(&store);
    let resources = ResourcePolicy::default();
    let (_, imported) = scope.fill(&["a", "a"], KW_AES128, &resources).unwrap();
    assert_eq!(imported, ["a"]);
    assert_eq!(
        *store.asked.lock(),
        [(vec!["a".to_owned()], KW_AES128.to_owned())]
    );
    assert!(scope.into_failure().is_none());
}

/// Two signatures without a `KeyName` and with one method are one request: the
/// store imported its key for the first, and asking again would import it a
/// second time and fail the call. The second request selects the key the
/// first one imported.
#[test]
fn an_unnamed_request_is_asked_once_per_method() {
    let store = Recording::default();
    let scope = LookupScope::new(&store);
    let resources = ResourcePolicy::default();
    let (_, imported) = scope.fill(&[], KW_AES128, &resources).unwrap();
    assert_eq!(imported, ["found"]);
    let (_, imported) = scope.fill(&[], KW_AES128, &resources).unwrap();
    assert_eq!(imported, ["found"]);
    assert_eq!(store.asked.lock().len(), 1);
    assert!(scope.into_failure().is_none());
}
