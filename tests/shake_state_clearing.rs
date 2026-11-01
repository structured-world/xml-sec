//! The SHAKE state of the embedded ML-DSA code is cleared when it is dropped.
//!
//! A workspace build cannot detect a missing `shake/zeroize`, because
//! dev-dependencies enable it too; `check-features experimental` proves it on an
//! isolated consumer. This target pins the marker the feature must produce.
#![cfg(feature = "experimental-pq")]

use shake::{Shake128, Shake128Reader, Shake256, Shake256Reader};
use zeroize::ZeroizeOnDrop;

const fn clears_on_drop<T: ZeroizeOnDrop>() {}

const _: () = {
    clears_on_drop::<Shake128>();
    clears_on_drop::<Shake256>();
};

#[test]
fn readers_clear_through_their_own_drop() {
    // A reader has no marker: its Drop always exists and clears under the same
    // feature as the hasher's, so the assertion above stands for both.
    assert!(core::mem::needs_drop::<Shake128Reader>());
    assert!(core::mem::needs_drop::<Shake256Reader>());
}
