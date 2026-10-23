use super::Document;

#[test]
fn namespace_iteration_consumes_the_same_range_from_both_ends() {
    // Mixed-ended namespace iteration must meet without repeating any binding.
    let document = Document::parse("<r xmlns:a='urn:a' xmlns:b='urn:b' xmlns:c='urn:c'/>")
        .expect("valid namespace declarations");
    let root = document.root_element();
    let forward: Vec<_> = root.namespaces().collect();
    assert!(forward.len() >= 3);
    assert_eq!(
        root.namespaces().rev().collect::<Vec<_>>(),
        forward.iter().rev().copied().collect::<Vec<_>>()
    );
    let mut mixed = root.namespaces();
    let mut front = 0;
    let mut back = forward.len();
    while front < back {
        assert_eq!(mixed.next(), Some(forward[front]));
        front += 1;
        if front < back {
            back -= 1;
            assert_eq!(mixed.next_back(), Some(forward[back]));
        }
    }
    assert_eq!(mixed.len(), 0);
    assert_eq!(mixed.next(), None);
    assert_eq!(mixed.next_back(), None);
}
