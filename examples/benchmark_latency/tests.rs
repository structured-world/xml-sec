#[test]
fn nearest_rank_handles_single_and_non_hundred_sample_counts() {
    // Tail percentiles use individual order statistics, including small smoke samples.
    assert_eq!(super::percentile(&[7], 99), 7);
    assert_eq!(super::percentile(&[10, 20, 30], 50), 20);
    assert_eq!(super::percentile(&[10, 20, 30], 95), 30);
    let values: Vec<_> = (1..=100).collect();
    assert_eq!(super::percentile(&values, 99), 99);
}

#[test]
fn no_backend_has_a_projection_phase() {
    // Every backend builds the semantic tree as it parses, so a projection
    // request is refused as an unknown operation for each of them.
    for backend in ["xmloxide", "roxmltree", "differential"] {
        let args = ["projection", "saml", "16", backend, "rustcrypto", "1"].map(String::from);
        let refusal = super::parse_request(&args)
            .err()
            .map(|error| error.to_string());
        assert_eq!(refusal.as_deref(), Some("unknown operation"), "{backend}");
    }
}
