use super::ValidatedXPointerFragment;

#[test]
fn truncated_multibyte_xpointer_escape_is_rejected_without_panicking() {
    // A complete leading UTF-8 octet still needs encoded continuation octets. The validator
    // must report a truncated fragment rather than indexing beyond the source buffer.
    for fragment in ["%C3", "%F0%9F"] {
        assert!(
            ValidatedXPointerFragment::new(fragment).is_err(),
            "accepted truncated XPointer fragment {fragment}"
        );
    }
}
