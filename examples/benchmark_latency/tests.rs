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
fn projection_is_requested_only_from_a_backend_that_has_one() {
    // Only roxmltree builds a backend DOM to project; a projection request for
    // any other backend is refused before a sample is prepared.
    for backend in ["xmloxide", "roxmltree", "differential"] {
        let args = ["projection", "saml", "16", backend, "rustcrypto", "1"].map(String::from);
        assert_eq!(
            super::parse_request(&args).is_ok(),
            backend == "roxmltree",
            "{backend}"
        );
    }
}
