use super::profile::counted;

#[test]
fn peak_heap_counts_the_allocator_block_not_the_request() {
    // The C harness's glibc profile charges each block's usable size; a requested
    // size here would leave allocator rounding out of only the Rust engines' peak.
    let (block, allocations) = counted(|| Box::new(0_u8));
    drop(block);
    assert_eq!(allocations.calls, 1);
    assert_eq!(allocations.bytes, 1);
    assert!(
        allocations.peak_bytes > 1,
        "peak {} excludes allocator rounding",
        allocations.peak_bytes
    );
}
