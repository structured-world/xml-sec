//! Error reporting against libxmlsec1's semantics: the reason table, the
//! callback priority, message formatting and truncation. Each test runs in
//! its own process, so the process-wide callbacks it sets are its own.

use super::{
    ErrorsCallback, MESSAGE_CAPACITY, R_ASSERTION, here, report, xmlSecError, xmlSecErrorsGetCode,
    xmlSecErrorsGetMsg, xmlSecErrorsSetCallback, xmlSecErrorsSetSystemCallback,
};
use std::ffi::{CStr, c_char, c_int};
use std::sync::Mutex;

/// One report as a callback received it.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    func: String,
    object: Option<String>,
    subject: Option<String>,
    reason: c_int,
    message: String,
}

static REPORTS: Mutex<Vec<Report>> = Mutex::new(Vec::new());

fn text(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the library passes null or NUL-terminated strings.
    let text = unsafe { CStr::from_ptr(value) };
    Some(text.to_string_lossy().into_owned())
}

unsafe extern "C" fn record(
    _file: *const c_char,
    _line: c_int,
    func: *const c_char,
    object: *const c_char,
    subject: *const c_char,
    reason: c_int,
    message: *const c_char,
) {
    REPORTS.lock().expect("reports").push(Report {
        func: text(func).unwrap_or_default(),
        object: text(object),
        subject: text(subject),
        reason,
        message: text(message).unwrap_or_default(),
    });
}

unsafe extern "C" fn other(
    _file: *const c_char,
    _line: c_int,
    _func: *const c_char,
    _object: *const c_char,
    _subject: *const c_char,
    _reason: c_int,
    _message: *const c_char,
) {
    REPORTS.lock().expect("reports").push(Report {
        func: "system".into(),
        object: None,
        subject: None,
        reason: 0,
        message: String::new(),
    });
}

fn take() -> Vec<Report> {
    std::mem::take(&mut *REPORTS.lock().expect("reports"))
}

/// The table holds libxmlsec1's codes and messages in order, and positions
/// past it hold code 0 and no message.
#[test]
fn reason_table_matches_libxmlsec1() {
    // SAFETY: the table functions take any position.
    unsafe {
        assert_eq!(xmlSecErrorsGetCode(0), 1);
        assert_eq!(
            text(xmlSecErrorsGetMsg(0)).as_deref(),
            Some("xmlsec library function failed")
        );
        assert_eq!(xmlSecErrorsGetCode(25), 28);
        assert_eq!(
            text(xmlSecErrorsGetMsg(25)).as_deref(),
            Some("node node found")
        );
        assert_eq!(xmlSecErrorsGetCode(52), 100);
        assert_eq!(xmlSecErrorsGetCode(53), 0);
        assert!(xmlSecErrorsGetMsg(53).is_null());
        assert_eq!(xmlSecErrorsGetCode(usize::MAX), 0);
    }
}

/// `xmlSecError` formats its message with printf semantics and passes every
/// field through unchanged.
#[test]
fn xml_sec_error_formats_the_message() {
    // SAFETY: the callback has the callback's signature; the format matches
    // its arguments.
    unsafe {
        xmlSecErrorsSetCallback(Some(record as ErrorsCallback));
        xmlSecError(
            c"f.c".as_ptr(),
            7,
            c"fn".as_ptr(),
            c"obj".as_ptr(),
            std::ptr::null(),
            12,
            c"size=%d;name=%s".as_ptr(),
            42 as c_int,
            c"x".as_ptr(),
        );
    }
    assert_eq!(
        take(),
        [Report {
            func: "fn".into(),
            object: Some("obj".into()),
            subject: None,
            reason: 12,
            message: "size=42;name=x".into(),
        }]
    );
}

/// The application's callback takes priority over the system one, and a
/// null application callback disables reporting although a system one is
/// set; a null message reports an empty one.
#[test]
fn user_callback_takes_priority_and_null_disables() {
    // SAFETY: the callbacks have the callback's signature.
    unsafe {
        xmlSecErrorsSetSystemCallback(Some(other as ErrorsCallback));
        report(here!("probe"), std::ptr::null(), std::ptr::null(), 1, "a");
        assert_eq!(take().len(), 1);
        xmlSecErrorsSetCallback(Some(record as ErrorsCallback));
        xmlSecError(
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            R_ASSERTION,
            std::ptr::null(),
        );
        let reports = take();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reason, R_ASSERTION);
        assert_eq!(reports[0].message, "");
        xmlSecErrorsSetCallback(None);
        report(here!("probe"), std::ptr::null(), std::ptr::null(), 1, "a");
        assert_eq!(take(), []);
    }
}

/// Messages are cut to 1023 bytes, as libxmlsec1's buffer cuts them, both
/// for `xmlSecError` and for the library's own reports.
#[test]
fn long_messages_are_truncated() {
    let long = "x".repeat(4000);
    let format = std::ffi::CString::new(long.clone()).expect("no NUL");
    // SAFETY: the callback has the callback's signature; the format has no
    // conversions.
    unsafe {
        xmlSecErrorsSetCallback(Some(record as ErrorsCallback));
        xmlSecError(
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            format.as_ptr(),
        );
    }
    report(here!("probe"), std::ptr::null(), std::ptr::null(), 1, &long);
    let reports = take();
    assert_eq!(reports.len(), 2);
    for report in reports {
        assert_eq!(report.message.len(), MESSAGE_CAPACITY - 1);
    }
}
