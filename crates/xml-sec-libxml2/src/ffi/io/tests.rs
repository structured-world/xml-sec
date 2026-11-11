use super::*;

/// A sink that takes one byte per call, as a partial-writing stream may.
unsafe extern "C" fn one_byte(context: *mut c_void, bytes: *const c_char, length: c_int) -> c_int {
    assert!(length > 0);
    // SAFETY: the test passes a live `Vec<u8>` and at least one readable
    // byte.
    unsafe {
        let sink = &mut *context.cast::<Vec<u8>>();
        sink.push(bytes.cast::<u8>().read());
    }
    1
}

/// A sink that takes nothing and reports no error.
unsafe extern "C" fn stalled(_: *mut c_void, _: *const c_char, _: c_int) -> c_int {
    0
}

#[test]
fn a_short_write_is_retried_until_every_byte_is_taken() {
    let mut sink: Vec<u8> = Vec::new();
    let context = (&raw mut sink).cast::<c_void>();
    let out = output_with_callbacks(Some(one_byte), None, context);
    // SAFETY: the callback takes the context this test passed.
    unsafe {
        assert_eq!(output_write(out, b"abcdef"), 6);
        assert_eq!(output_close(out), 6);
    }
    assert_eq!(sink, b"abcdef");
}

#[test]
fn a_sink_that_takes_nothing_fails_the_write() {
    // Reporting the bytes as written would lose them silently.
    let out = output_with_callbacks(Some(stalled), None, std::ptr::null_mut());
    // SAFETY: the callback ignores its context.
    unsafe {
        assert_eq!(output_write(out, b"abc"), -1);
        assert_eq!(output_close(out), -1);
    }
}
