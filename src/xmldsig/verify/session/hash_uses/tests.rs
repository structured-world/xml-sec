use super::*;

#[test]
fn every_advertised_method_has_explicit_message_hash_semantics() {
    // A newly advertised signature method must not silently disappear from
    // algorithm projection, including pure experimental suites.
    for algorithm in SignatureAlgorithm::ALL {
        assert!(
            !matches!(message_hash(algorithm), HashUseAlgorithm::Unsupported(_)),
            "{algorithm:?}"
        );
    }
}
