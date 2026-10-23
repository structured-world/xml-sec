use super::{NamespaceMap, NamespaceState, Native, Scratch};

fn check_namespace_states(mut namespaces: impl NamespaceMap<'static>) {
    assert_eq!(
        namespaces.get("p", false).expect("unseen prefix query"),
        NamespaceState::Absent
    );
    namespaces.insert("p", false, None).expect("exclude prefix");
    assert_eq!(
        namespaces.get("p", false).expect("excluded prefix query"),
        NamespaceState::Excluded
    );
    assert!(
        namespaces
            .get("p", false)
            .expect("presence query")
            .is_present()
    );
    assert_eq!(
        namespaces.get("p", true).expect("unseen utilizer query"),
        NamespaceState::Absent
    );
    namespaces
        .insert("p", true, Some("urn:p"))
        .expect("bind utilizer");
    assert_eq!(
        namespaces.get("p", true).expect("bound utilizer query"),
        NamespaceState::Bound("urn:p")
    );
    namespaces
        .insert("", false, Some(""))
        .expect("bind empty default URI");
    assert_eq!(
        namespaces.get("", false).expect("empty default URI query"),
        NamespaceState::Bound("")
    );
    let copied = namespaces.copy().expect("copy namespace bindings");
    assert_eq!(
        copied.get("p", false).expect("copied exclusion"),
        NamespaceState::Excluded
    );
    assert_eq!(
        copied.get("p", true).expect("copied utilizer").uri(),
        Some("urn:p")
    );
    assert_eq!(
        copied.get("", false).expect("copied empty URI").uri(),
        Some("")
    );
    namespaces.remove("p").expect("remove non-utilizer binding");
    assert_eq!(
        namespaces.get("p", false).expect("removed prefix query"),
        NamespaceState::Absent
    );
    assert_eq!(
        namespaces.get("p", true).expect("retained utilizer query"),
        NamespaceState::Bound("urn:p")
    );
}

#[test]
fn native_namespaces_keep_absent_excluded_and_empty_uri_distinct() {
    // Namespace rendering distinguishes excluded and unseen bindings,
    // and preserves an explicit empty default URI.
    check_namespace_states(Native.namespaces());
}

#[cfg(feature = "xmldsig")]
#[test]
fn accounted_namespaces_share_states_and_release_retained_capacity() {
    // The scoped map shares the three-state contract and releases both maps.
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 20)));
    check_namespace_states(super::Accounted(&memory).namespaces());
    assert_eq!(memory.used(), 0);
}
