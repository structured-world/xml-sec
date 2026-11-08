//! Status codes every exported function returns, mirrored in `xml_sec.h`.
#![forbid(unsafe_code)]

/// The outcome of one call: `XS_OK` or the class of its failure.
pub type XsStatus = i32;

/// The call succeeded.
pub const XS_OK: XsStatus = 0;
/// A pointer, length, enumerator or byte string was not acceptable.
pub const XS_INVALID_ARGUMENT: XsStatus = 1;
/// The handle names an object of another type.
pub const XS_WRONG_HANDLE: XsStatus = 2;
/// The handle's slot now holds a newer object.
pub const XS_STALE_HANDLE: XsStatus = 3;
/// The handle's object was destroyed.
pub const XS_DESTROYED_HANDLE: XsStatus = 4;
/// The object is in use by a running call, or a document by another operation.
pub const XS_BUSY: XsStatus = 5;
/// The library's handle table has no free slot.
pub const XS_HANDLE_LIMIT: XsStatus = 6;
/// The compiled policy disables the requested operation.
pub const XS_OPERATION_DISABLED: XsStatus = 7;
/// The policy refused the input or the configuration.
pub const XS_POLICY: XsStatus = 8;
/// The policy configuration could not be read or compiled.
pub const XS_CONFIGURATION: XsStatus = 9;
/// XML parsing or document processing failed.
pub const XS_DOCUMENT: XsStatus = 10;
/// Key import or selection failed.
pub const XS_KEY: XsStatus = 11;
/// Verification could not complete. A signature that does not verify is
/// evidence, not this status.
pub const XS_VERIFICATION: XsStatus = 12;
/// Signature generation failed.
pub const XS_SIGNING: XsStatus = 13;
/// Encryption or decryption failed.
pub const XS_ENCRYPTION: XsStatus = 14;
/// Canonicalization failed.
pub const XS_CANONICALIZATION: XsStatus = 15;
/// The library failed internally; no Rust panic crossed the boundary.
pub const XS_INTERNAL: XsStatus = 16;
