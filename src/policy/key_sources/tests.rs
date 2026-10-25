use super::*;

fn subset(bits: u8) -> KeySourcePolicy {
    KeySourceKind::ALL
        .into_iter()
        .filter(|source| bits & *source as u8 != 0)
        .collect()
}

#[test]
fn default_preserves_every_existing_permission_without_allocation() {
    // The representation changes, not the six default grants or their independence.
    assert_eq!(core::mem::size_of::<KeySourcePolicy>(), 1);
    assert_eq!(KeySourcePolicy::default(), KeySourcePolicy::ALL);
    assert_eq!(KeySourcePolicy::from([]), KeySourcePolicy::NONE);
    for source in KeySourceKind::ALL {
        assert!(KeySourcePolicy::default().contains(source));
        assert!(!KeySourcePolicy::NONE.contains(source));
        let single = KeySourcePolicy::from([source, source]);
        for candidate in KeySourceKind::ALL {
            assert_eq!(single.contains(candidate), candidate == source);
        }
    }
}

#[test]
fn each_permission_changes_independently_for_every_subset() {
    // Toggling one permission must preserve every unrelated source decision.
    for bits in 0..64 {
        for source in KeySourceKind::ALL {
            let original = subset(bits);
            let mut changed = original;
            changed.insert(source);
            assert!(changed.contains(source));
            changed.remove(source);
            assert!(!changed.contains(source));
            for candidate in KeySourceKind::ALL {
                if candidate != source {
                    assert_eq!(changed.contains(candidate), original.contains(candidate));
                }
            }
            changed.set(source, original.contains(source));
            assert_eq!(changed, original);
        }
    }
}

#[test]
fn composition_matches_all_pairs_of_independent_source_decisions() {
    // Exhaust all source combinations so restrictive composition cannot add a grant.
    for left in 0..64 {
        for right in 0..64 {
            let a = subset(left);
            let b = subset(right);
            let composed = a.intersection(b);
            assert_eq!(composed, b.intersection(a));
            for source in KeySourceKind::ALL {
                assert_eq!(
                    composed.contains(source),
                    a.contains(source) && b.contains(source)
                );
            }
        }
    }
}
