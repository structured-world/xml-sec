use super::*;

#[test]
fn fragmented_ingestion_has_bounded_geometric_growth() {
    // An adversarially short reader cannot induce quadratic buffer copies;
    // reaching the ceiling does not request a single extra heap byte.
    let mut bytes = Vec::new();
    let maximum = 16384;
    let mut growths = 0;
    for _ in 0..maximum {
        let before = bytes.capacity();
        reserve_input(&mut bytes, 1, maximum).unwrap();
        if before != bytes.capacity() {
            growths += 1;
        }
        bytes.push(b' ');
        assert!(bytes.capacity() <= maximum);
    }
    assert_eq!(growths, 3);
    let capacity = bytes.capacity();
    assert!(reserve_input(&mut bytes, 1, maximum).is_err());
    assert_eq!(capacity, bytes.capacity());
}
