//! The exported C functions: the crate's only `unsafe` code.
//!
//! Each function validates every pointer and length before using it, runs its
//! body under panic containment, and returns a status. `SAFETY.md` records the
//! invariants every `unsafe` block below relies on.

use crate::objects::{
    self, Audit, Decryptor, Encryptor, Failure, Grant, Keys, Object, PolicySource, Signer, Verifier,
};
use crate::status::{XS_BUSY, XS_INTERNAL, XS_INVALID_ARGUMENT, XS_OK, XS_WRONG_HANDLE, XsStatus};
use crate::table::{self, InUse, Kind};
use std::mem::MaybeUninit;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use xml_sec::policy::PolicyCompileContext;
use xml_sec::provider::{CryptoProvider, RustCryptoProvider};

#[cfg(test)]
mod tests;

/// The ABI revision of this library; a header declares the one it expects.
pub const XS_ABI_VERSION: u32 = 1;

/// A borrowed byte string: `ptr` may be null only when `len` is zero.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsBytes {
    /// First byte.
    pub ptr: *const u8,
    /// Number of bytes.
    pub len: usize,
}

/// Bytes the library allocated; release them with [`xs_buffer_free`].
#[repr(C)]
#[derive(Debug)]
pub struct XsBuffer {
    /// First byte.
    pub ptr: *mut u8,
    /// Number of bytes.
    pub len: usize,
}

macro_rules! handle_types {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name {
            /// Tag, slot and generation; zero names nothing.
            pub value: u64,
        }
    )*};
}

handle_types!(
    /// A cryptographic engine.
    XsProvider,
    /// The published policy of one configuration profile.
    XsPolicyStore,
    /// One immutable compiled policy snapshot.
    XsPolicy,
    /// A key manager.
    XsKeys,
    /// A retained XML document.
    XsDocument,
    /// A signing operation with its key.
    XsSigner,
    /// A verification operation.
    XsVerifier,
    /// An encryption operation with its recipient.
    XsEncryptor,
    /// A decryption operation with its key.
    XsDecryptor,
    /// The outcome of one verification.
    XsEvidence,
    /// What one operation's policy decided.
    XsAudit,
    /// The details of one failed call.
    XsError,
);

/// Promises the caller makes to every operation using the compiled policy.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsCompileContext {
    /// Nonzero: every applicable call supplies its external-resource map.
    pub external_resources: u8,
    /// Nonzero: every verification names its expected targets.
    pub target_evidence: u8,
}

/// An exception grant the application authenticated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsAuthorization {
    /// The application's audit record of the grant.
    pub authorization_id: XsBytes,
    /// The authenticated principal granting it.
    pub authority: XsBytes,
    /// Its non-secret justification.
    pub reason: XsBytes,
    /// Inclusive start, Unix seconds.
    pub not_before_seconds: i64,
    /// Inclusive start, nanoseconds.
    pub not_before_nanos: u32,
    /// Exclusive end, Unix seconds.
    pub expires_at_seconds: i64,
    /// Exclusive end, nanoseconds.
    pub expires_at_nanos: u32,
}

/// What a verification must establish.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsVerifyRequest {
    /// IDs of the elements that must be authenticated.
    pub expected_target_ids: *const XsBytes,
    /// Number of IDs.
    pub expected_target_count: usize,
    /// `XS_REQUIRE_ALL`, `XS_REQUIRE_AT_LEAST` or `XS_REQUIRE_EXACTLY`.
    pub requirement: u32,
    /// The signature count the requirement names.
    pub count: usize,
}

/// The outcome of one signature in an evidence handle.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XsSignatureOutcome {
    /// `XS_SIGNATURE_VALID`, `_INVALID` or `_FAILED`.
    pub outcome: u32,
    /// `XS_KEY_TRUST_*`; zero for a failed verification.
    pub key_trust: u32,
}

/// The published snapshot an operation enforced.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsPolicyIdentity {
    /// Nonzero when the policy was a published snapshot.
    pub present: u8,
    /// Configuration schema version.
    pub schema_version: u32,
    /// Publication revision.
    pub revision: u64,
    /// SHA-256 of the canonical effective settings.
    pub digest: [u8; 32],
    /// Profile name, borrowed from the handle it was read from.
    pub profile: XsBytes,
}

/// One policy decision, borrowed from its audit handle.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsDecision {
    /// `XS_DECISION_*`; zero for a kind this header does not name.
    pub kind: u32,
    /// `XS_ALGORITHM_ROLE_*` or `XS_URI_ROLE_*`, by kind.
    pub role: u32,
    /// `XS_URI_CLASS_*` of a URI decision.
    pub uri_class: u32,
    /// `XS_MANIFESTS_*` of a Manifest decision.
    pub manifests: u32,
    /// `XS_VIOLATION_*` of a refusal.
    pub violation: u32,
    /// Algorithm URI, exception authorization ID or refusal message.
    pub text: XsBytes,
}

const EMPTY: XsBytes = XsBytes {
    ptr: std::ptr::null(),
    len: 0,
};

fn borrowed(text: &str) -> XsBytes {
    XsBytes {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// Run `body`, contain any panic, and report the outcome through the status
/// and the optional error handle.
fn contain(
    error: Option<&mut MaybeUninit<XsError>>,
    body: impl FnOnce() -> Result<(), Failure>,
) -> XsStatus {
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(body))
        .unwrap_or_else(|_| Err(Failure::new(XS_INTERNAL, "internal error")));
    match outcome {
        Ok(()) => {
            if let Some(error) = error {
                error.write(XsError::default());
            }
            XS_OK
        }
        Err(failure) => {
            let status = failure.status;
            if let Some(error) = error {
                // A full table still reports the status, without details.
                let value = std::panic::catch_unwind(|| table::insert(Object::Error(failure)))
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or(0);
                error.write(XsError { value });
            }
            status
        }
    }
}

/// The caller's optional error slot; a misaligned one is treated as absent.
///
/// # Safety
/// `error` is null or valid for writes of one `XsError`.
unsafe fn error_slot<'a>(error: *mut XsError) -> Option<&'a mut MaybeUninit<XsError>> {
    if error.is_null() || !error.is_aligned() {
        return None;
    }
    // SAFETY: non-null, aligned, and valid for writes by the caller's contract.
    Some(unsafe { &mut *error.cast::<MaybeUninit<XsError>>() })
}

/// The caller's output slot, checked before any work is done.
///
/// # Safety
/// `out` is null or valid for writes of one `T`.
unsafe fn output<'a, T>(out: *mut T) -> Result<&'a mut MaybeUninit<T>, Failure> {
    if out.is_null() || !out.is_aligned() {
        return Err(Failure::new(XS_INVALID_ARGUMENT, "invalid output pointer"));
    }
    // SAFETY: non-null, aligned, and valid for writes by the caller's contract.
    Ok(unsafe { &mut *out.cast::<MaybeUninit<T>>() })
}

/// An optional input structure.
///
/// # Safety
/// `value` is null or valid for reads of one `T`.
unsafe fn optional<'a, T>(value: *const T) -> Result<Option<&'a T>, Failure> {
    if value.is_null() {
        return Ok(None);
    }
    if !value.is_aligned() {
        return Err(Failure::new(
            XS_INVALID_ARGUMENT,
            "misaligned input pointer",
        ));
    }
    // SAFETY: non-null, aligned, and valid for reads by the caller's contract.
    Ok(Some(unsafe { &*value }))
}

/// The bytes `bytes` names, borrowed for the call.
///
/// # Safety
/// A non-null `bytes.ptr` is valid for reads of `bytes.len` bytes.
unsafe fn input<'a>(bytes: XsBytes) -> Result<&'a [u8], Failure> {
    if bytes.ptr.is_null() {
        return if bytes.len == 0 {
            Ok(&[])
        } else {
            Err(Failure::new(
                XS_INVALID_ARGUMENT,
                "null pointer with a length",
            ))
        };
    }
    if isize::try_from(bytes.len).is_err() {
        return Err(Failure::new(
            XS_INVALID_ARGUMENT,
            "length overflows the address space",
        ));
    }
    // SAFETY: non-null, `len` fits `isize`, and the caller guarantees `len`
    // readable bytes; `u8` needs no alignment.
    Ok(unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) })
}

/// UTF-8 text `bytes` names, borrowed for the call.
///
/// # Safety
/// As for [`input`].
unsafe fn text<'a>(bytes: XsBytes) -> Result<&'a str, Failure> {
    // SAFETY: forwarded caller contract.
    let bytes = unsafe { input(bytes) }?;
    std::str::from_utf8(bytes).map_err(|_| Failure::new(XS_INVALID_ARGUMENT, "text is not UTF-8"))
}

/// UTF-8 text, or `None` for an empty string.
///
/// # Safety
/// As for [`input`].
unsafe fn optional_text<'a>(bytes: XsBytes) -> Result<Option<&'a str>, Failure> {
    // SAFETY: forwarded caller contract.
    let text = unsafe { text(bytes) }?;
    Ok((!text.is_empty()).then_some(text))
}

fn take(handle: u64, kind: Kind) -> Result<InUse, Failure> {
    table::use_handle(handle, kind).map_err(Failure::from)
}

fn insert(object: Object) -> Result<u64, Failure> {
    table::insert(object).map_err(Failure::from)
}

fn wrong() -> Failure {
    Failure::from(XS_WRONG_HANDLE)
}

/// A shared object one call reads, with the handle kept in use until the call
/// drops it, so destroying the handle meanwhile reports busy.
struct Held<T: ?Sized> {
    value: Arc<T>,
    _in_use: InUse,
}

impl<T: ?Sized> std::ops::Deref for Held<T> {
    type Target = Arc<T>;

    fn deref(&self) -> &Arc<T> {
        &self.value
    }
}

/// Hold the shared object `handle` names, as `project` reads it.
fn hold<T: ?Sized>(
    handle: u64,
    kind: Kind,
    project: impl FnOnce(&Object) -> Option<&Arc<T>>,
) -> Result<Held<T>, Failure> {
    let in_use = take(handle, kind)?;
    let value = Arc::clone(project(in_use.object()).ok_or_else(wrong)?);
    Ok(Held {
        value,
        _in_use: in_use,
    })
}

fn provider(handle: XsProvider) -> Result<Held<dyn CryptoProvider>, Failure> {
    hold(handle.value, Kind::Provider, |object| match object {
        Object::Provider(provider) => Some(provider),
        _ => None,
    })
}

fn policy(handle: XsPolicy) -> Result<Held<xml_sec::policy::CompiledPolicies>, Failure> {
    hold(handle.value, Kind::Policy, |object| match object {
        Object::Policy(policy) => Some(policy),
        _ => None,
    })
}

fn keys(handle: XsKeys) -> Result<Held<Keys>, Failure> {
    hold(handle.value, Kind::Keys, |object| match object {
        Object::Keys(keys) => Some(keys),
        _ => None,
    })
}

/// Lock `document` for one operation; another running operation makes it busy.
fn with_document<T>(
    handle: XsDocument,
    body: impl FnOnce(&mut xml_sec::XmlDocument) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let document = take(handle.value, Kind::Document)?;
    let Object::Document(document) = document.object() else {
        return Err(wrong());
    };
    let mut document = document.try_lock().ok_or_else(|| Failure::from(XS_BUSY))?;
    body(&mut document)
}

/// Publish an audit as a handle, unless the caller declined it with null.
fn audit_out(
    out: Option<&mut MaybeUninit<XsAudit>>,
    audit: &xml_sec::policy::PolicyAudit,
) -> Result<(), Failure> {
    if let Some(out) = out {
        let value = insert(Object::Audit(Audit::from(audit)))?;
        out.write(XsAudit { value });
    }
    Ok(())
}

/// The caller's optional audit slot.
///
/// # Safety
/// `out` is null or valid for writes of one `XsAudit`.
unsafe fn audit_slot<'a>(
    out: *mut XsAudit,
) -> Result<Option<&'a mut MaybeUninit<XsAudit>>, Failure> {
    if out.is_null() {
        return Ok(None);
    }
    // SAFETY: forwarded caller contract.
    unsafe { output(out) }.map(Some)
}

macro_rules! destroy_functions {
    ($($(#[$doc:meta])* $name:ident($handle:ident, $kind:ident);)*) => {$(
        $(#[$doc])*
        ///
        /// Returns `XS_DESTROYED_HANDLE` for a second destruction and `XS_BUSY`
        /// while a running call uses the object.
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(handle: $handle) -> XsStatus {
            contain(None, || table::destroy(handle.value, Kind::$kind).map_err(Failure::from))
        }
    )*};
}

destroy_functions! {
    /// Destroy a provider handle.
    xs_provider_destroy(XsProvider, Provider);
    /// Destroy a policy store handle.
    xs_policy_store_destroy(XsPolicyStore, PolicyStore);
    /// Destroy a policy handle.
    xs_policy_destroy(XsPolicy, Policy);
    /// Destroy a key manager handle.
    xs_keys_destroy(XsKeys, Keys);
    /// Destroy a document handle.
    xs_document_destroy(XsDocument, Document);
    /// Destroy a signer handle.
    xs_signer_destroy(XsSigner, Signer);
    /// Destroy a verifier handle.
    xs_verifier_destroy(XsVerifier, Verifier);
    /// Destroy an encryptor handle.
    xs_encryptor_destroy(XsEncryptor, Encryptor);
    /// Destroy a decryptor handle.
    xs_decryptor_destroy(XsDecryptor, Decryptor);
    /// Destroy an evidence handle.
    xs_evidence_destroy(XsEvidence, Evidence);
    /// Destroy an audit handle.
    xs_audit_destroy(XsAudit, Audit);
    /// Destroy an error handle.
    xs_error_destroy(XsError, Error);
}

/// The ABI revision of the loaded library.
#[unsafe(no_mangle)]
pub extern "C" fn xs_abi_version() -> u32 {
    XS_ABI_VERSION
}

/// Create a handle to the built-in `RustCrypto` engine.
///
/// # Safety
/// `out` is valid for writes of one `XsProvider`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_provider_new_rustcrypto(
    out: *mut XsProvider,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let value = insert(Object::Provider(Arc::new(RustCryptoProvider)))?;
        out.write(XsProvider { value });
        Ok(())
    })
}

/// Create a handle to the AWS-LC FIPS engine.
///
/// # Safety
/// As for [`xs_provider_new_rustcrypto`].
#[cfg(feature = "aws-lc-fips")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_provider_new_aws_lc_fips(
    out: *mut XsProvider,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let value = insert(Object::Provider(Arc::new(
            xml_sec::provider::AwsLcFipsProvider,
        )))?;
        out.write(XsProvider { value });
        Ok(())
    })
}

/// Read a policy source from the C arguments.
///
/// # Safety
/// The byte strings and the optional structures follow [`input`] and
/// [`optional`].
unsafe fn source(
    configuration: XsBytes,
    profile: XsBytes,
    provider: &dyn CryptoProvider,
    context: *const XsCompileContext,
    authorization: *const XsAuthorization,
) -> Result<PolicySource<'_>, Failure> {
    // SAFETY: forwarded caller contract.
    let context = unsafe { optional(context) }?
        .ok_or_else(|| Failure::new(XS_INVALID_ARGUMENT, "null compile context"))?;
    // SAFETY: forwarded caller contract.
    let grant = match unsafe { optional(authorization) }? {
        // SAFETY: forwarded caller contract for the grant's byte strings.
        Some(grant) => Some(unsafe {
            Grant {
                authorization_id: text(grant.authorization_id)?,
                authority: text(grant.authority)?,
                reason: text(grant.reason)?,
                not_before: (grant.not_before_seconds, grant.not_before_nanos),
                expires_at: (grant.expires_at_seconds, grant.expires_at_nanos),
            }
        }),
        None => None,
    };
    Ok(PolicySource {
        // SAFETY: forwarded caller contract.
        configuration: unsafe { text(configuration) }?,
        // SAFETY: forwarded caller contract.
        profile: unsafe { text(profile) }?,
        provider,
        context: PolicyCompileContext {
            external_resources: context.external_resources != 0,
            target_evidence: context.target_evidence != 0,
        },
        grant,
    })
}

/// Compile `profile` of the schema-v1 TOML `configuration` for `provider` and
/// publish it as revision 1 of a new policy store.
///
/// # Safety
/// `configuration` and `profile` follow the `XsBytes` contract; `context` is
/// valid for reads of one `XsCompileContext`; `authorization` is null or valid
/// for reads of one `XsAuthorization`; `out` is valid for writes of one
/// `XsPolicyStore`; `error` is null or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_policy_store_new(
    configuration: XsBytes,
    profile: XsBytes,
    provider_handle: XsProvider,
    context: *const XsCompileContext,
    authorization: *const XsAuthorization,
    out: *mut XsPolicyStore,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let provider = provider(provider_handle)?;
        // SAFETY: the caller's contract for the source arguments.
        let source =
            unsafe { source(configuration, profile, &**provider, context, authorization) }?;
        let value = insert(Object::PolicyStore(source.new_store()?))?;
        out.write(XsPolicyStore { value });
        Ok(())
    })
}

/// Validate and compile a replacement completely, then publish it atomically
/// as the store's next revision; a refused replacement publishes nothing.
///
/// # Safety
/// As for [`xs_policy_store_new`], without `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_policy_store_replace(
    store: XsPolicyStore,
    configuration: XsBytes,
    profile: XsBytes,
    provider_handle: XsProvider,
    context: *const XsCompileContext,
    authorization: *const XsAuthorization,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        let provider = provider(provider_handle)?;
        // SAFETY: the caller's contract for the source arguments.
        let source =
            unsafe { source(configuration, profile, &**provider, context, authorization) }?;
        let store = take(store.value, Kind::PolicyStore)?;
        let Object::PolicyStore(store) = store.object() else {
            return Err(wrong());
        };
        source.replace(store)
    })
}

/// The store's current snapshot, for any number of operations; later
/// publications do not change it.
///
/// # Safety
/// `out` is valid for writes of one `XsPolicy`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_policy_store_load(
    store: XsPolicyStore,
    out: *mut XsPolicy,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let store = take(store.value, Kind::PolicyStore)?;
        let Object::PolicyStore(store) = store.object() else {
            return Err(wrong());
        };
        let value = insert(Object::Policy(store.load()))?;
        out.write(XsPolicy { value });
        Ok(())
    })
}

/// Create a key manager whose imports are bounded by the resource policy of
/// `operation` (`XS_OPERATION_*`) in `policy`.
///
/// # Safety
/// `out` is valid for writes of one `XsKeys`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_keys_new(
    policy_handle: XsPolicy,
    operation: u32,
    out: *mut XsKeys,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let keys = Keys::new(&*policy(policy_handle)?, objects::operation(operation)?)?;
        let value = insert(Object::Keys(Arc::new(keys)))?;
        out.write(XsKeys { value });
        Ok(())
    })
}

fn with_keys(
    handle: XsKeys,
    body: impl FnOnce(&Keys) -> Result<(), Failure>,
) -> Result<(), Failure> {
    body(&*keys(handle)?)
}

/// Add a PEM private key under `name` with `XS_KEY_USAGE_*` bits; an empty
/// `password` means an unencrypted key.
///
/// # Safety
/// The byte strings follow the `XsBytes` contract; `error` is null or valid
/// for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_keys_add_private_pem(
    keys_handle: XsKeys,
    name: XsBytes,
    pem: XsBytes,
    password: XsBytes,
    usages: u32,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for the byte strings.
        let (name, pem, password) = unsafe { (text(name)?, input(pem)?, input(password)?) };
        let password = (!password.is_empty()).then_some(password);
        with_keys(keys_handle, |keys| {
            keys.add_private_pem(name, pem, password, usages)
        })
    })
}

/// Add a PEM public key or certificate under `name` with `XS_KEY_USAGE_*` bits.
///
/// # Safety
/// As for [`xs_keys_add_private_pem`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_keys_add_public_pem(
    keys_handle: XsKeys,
    name: XsBytes,
    pem: XsBytes,
    usages: u32,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for the byte strings.
        let (name, pem) = unsafe { (text(name)?, input(pem)?) };
        with_keys(keys_handle, |keys| keys.add_public_pem(name, pem, usages))
    })
}

/// Add raw symmetric key bytes of `XS_SYMMETRIC_*` kind under `name`.
///
/// # Safety
/// As for [`xs_keys_add_private_pem`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_keys_add_symmetric(
    keys_handle: XsKeys,
    name: XsBytes,
    kind: u32,
    key: XsBytes,
    usages: u32,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for the byte strings.
        let (name, key) = unsafe { (text(name)?, input(key)?) };
        with_keys(keys_handle, |keys| {
            keys.add_symmetric(name, kind, key, usages)
        })
    })
}

/// Parse UTF-8 `xml` under the compiled policy of `operation`
/// (`XS_OPERATION_*`) in `policy`.
///
/// # Safety
/// `xml` follows the `XsBytes` contract; `out` is valid for writes of one
/// `XsDocument`; `error` is null or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_document_parse(
    policy_handle: XsPolicy,
    operation: u32,
    xml: XsBytes,
    out: *mut XsDocument,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out` and `xml`.
        let (out, xml) = unsafe { (output(out)?, text(xml)?) };
        let document = objects::parse_document(
            &*policy(policy_handle)?,
            objects::operation(operation)?,
            xml,
        )?;
        let value = insert(Object::Document(parking_lot::Mutex::new(document)))?;
        out.write(XsDocument { value });
        Ok(())
    })
}

/// Copy the document's current XML into a buffer the library allocates.
///
/// # Safety
/// `out` is valid for writes of one `XsBuffer`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_document_serialize(
    document: XsDocument,
    out: *mut XsBuffer,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let bytes: Box<[u8]> =
            with_document(document, |document| Ok(document.as_xml().as_bytes().into()))?;
        let len = bytes.len();
        out.write(XsBuffer {
            ptr: Box::into_raw(bytes).cast::<u8>(),
            len,
        });
        Ok(())
    })
}

/// Release a buffer the library returned; an empty buffer is accepted.
///
/// # Safety
/// `buffer` is exactly a buffer this library returned and not yet released.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_buffer_free(buffer: XsBuffer) {
    if buffer.ptr.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: the pointer and length are those `Box::into_raw` returned
        // for a `Box<[u8]>`, released once by the caller's contract.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len)) });
    });
}

/// Create a signer with key `key_name` from `keys`, for `signature_method`
/// (an algorithm URI), under `policy` and `provider`.
///
/// # Safety
/// The byte strings follow the `XsBytes` contract; `out` is valid for writes
/// of one `XsSigner`; `error` is null or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_signer_new(
    policy_handle: XsPolicy,
    provider_handle: XsProvider,
    keys_handle: XsKeys,
    key_name: XsBytes,
    signature_method: XsBytes,
    out: *mut XsSigner,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out` and the byte strings.
        let (out, name, method) =
            unsafe { (output(out)?, text(key_name)?, text(signature_method)?) };
        let (policy, provider, keys) = (
            policy(policy_handle)?,
            provider(provider_handle)?,
            keys(keys_handle)?,
        );
        let signer = Signer::new(objects::security(&policy, &provider)?, &keys, name, method)?;
        let value = insert(Object::Signer(signer))?;
        out.write(XsSigner { value });
        Ok(())
    })
}

/// Fill the document's signature template and commit the signed document as
/// one new generation; a failure leaves it unchanged.
///
/// # Safety
/// `audit` is null or valid for writes of one `XsAudit`; `error` is null or
/// valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_sign(
    signer: XsSigner,
    document: XsDocument,
    audit: *mut XsAudit,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `audit`.
        let audit = unsafe { audit_slot(audit) }?;
        let signer = take(signer.value, Kind::Signer)?;
        let Object::Signer(signer) = signer.object() else {
            return Err(wrong());
        };
        let decided = with_document(document, |document| signer.sign(document))?;
        audit_out(audit, &decided)
    })
}

/// Create a verifier under `policy` and `provider`; keys come from `keys`, or
/// only from the document and the policy's trust when `keys` is zero.
///
/// # Safety
/// `out` is valid for writes of one `XsVerifier`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_verifier_new(
    policy_handle: XsPolicy,
    provider_handle: XsProvider,
    keys_handle: XsKeys,
    out: *mut XsVerifier,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out`.
        let out = unsafe { output(out) }?;
        let (policy, provider) = (policy(policy_handle)?, provider(provider_handle)?);
        let keys = match keys_handle.value {
            0 => None,
            _ => Some(keys(keys_handle)?),
        };
        let verifier = Verifier::new(
            objects::security(&policy, &provider)?,
            keys.as_deref().map(Arc::clone),
        );
        let value = insert(Object::Verifier(verifier))?;
        out.write(XsVerifier { value });
        Ok(())
    })
}

/// Verify every signature of the document. Success is a report, not
/// acceptance: ask [`xs_evidence_accepted`] with the same document.
///
/// # Safety
/// `request` is valid for reads of one `XsVerifyRequest`, whose ID array is
/// valid for reads of its count; `out` is valid for writes of one
/// `XsEvidence`; `error` is null or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_verify(
    verifier: XsVerifier,
    document: XsDocument,
    request: *const XsVerifyRequest,
    out: *mut XsEvidence,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out` and `request`.
        let (out, request) = unsafe { (output(out)?, optional(request)?) };
        let request = request.ok_or_else(|| Failure::new(XS_INVALID_ARGUMENT, "null request"))?;
        let entries = if request.expected_target_count == 0 {
            &[][..]
        } else {
            if request.expected_target_ids.is_null() || !request.expected_target_ids.is_aligned() {
                return Err(Failure::new(XS_INVALID_ARGUMENT, "invalid target ID array"));
            }
            if isize::try_from(request.expected_target_count)
                .ok()
                .and_then(|count| count.checked_mul(isize::try_from(size_of::<XsBytes>()).ok()?))
                .is_none()
            {
                return Err(Failure::new(
                    XS_INVALID_ARGUMENT,
                    "target ID count overflows",
                ));
            }
            // SAFETY: non-null, aligned, the total size fits `isize`, and the
            // caller guarantees the count of readable entries.
            unsafe {
                std::slice::from_raw_parts(
                    request.expected_target_ids,
                    request.expected_target_count,
                )
            }
        };
        let ids = entries
            .iter()
            // SAFETY: the caller's contract for each entry's bytes.
            .map(|id| unsafe { text(*id) })
            .collect::<Result<Vec<_>, _>>()?;
        let requirement = objects::requirement(request.requirement, request.count)?;
        let verifier = take(verifier.value, Kind::Verifier)?;
        let Object::Verifier(verifier) = verifier.object() else {
            return Err(wrong());
        };
        let evidence = with_document(document, |document| {
            verifier.verify(document, &ids, requirement)
        })?;
        let value = insert(Object::Evidence(evidence))?;
        out.write(XsEvidence { value });
        Ok(())
    })
}

/// Create an encryptor of `content_method` (an algorithm URI) for the RSA
/// public key `recipient` from `keys`, under `policy` and `provider`.
///
/// # Safety
/// As for [`xs_signer_new`], writing one `XsEncryptor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_encryptor_new(
    policy_handle: XsPolicy,
    provider_handle: XsProvider,
    keys_handle: XsKeys,
    recipient: XsBytes,
    content_method: XsBytes,
    out: *mut XsEncryptor,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out` and the byte strings.
        let (out, recipient, method) =
            unsafe { (output(out)?, text(recipient)?, text(content_method)?) };
        let (policy, provider, keys) = (
            policy(policy_handle)?,
            provider(provider_handle)?,
            keys(keys_handle)?,
        );
        let security = objects::security(&policy, &provider)?;
        let encryptor = Encryptor::new(security, &keys, recipient, method)?;
        let value = insert(Object::Encryptor(Box::new(encryptor)))?;
        out.write(XsEncryptor { value });
        Ok(())
    })
}

/// Replace the element with ID `element_id`, or the root when it is empty,
/// by its encryption, as one new document generation.
///
/// # Safety
/// `element_id` follows the `XsBytes` contract; `audit` is null or valid for
/// writes of one `XsAudit`; `error` is null or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_encrypt(
    encryptor: XsEncryptor,
    document: XsDocument,
    element_id: XsBytes,
    audit: *mut XsAudit,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `audit` and `element_id`.
        let (audit, id) = unsafe { (audit_slot(audit)?, optional_text(element_id)?) };
        let encryptor = take(encryptor.value, Kind::Encryptor)?;
        let Object::Encryptor(encryptor) = encryptor.object() else {
            return Err(wrong());
        };
        let decided = with_document(document, |document| encryptor.encrypt(document, id))?;
        audit_out(audit, &decided)
    })
}

/// Create a decryptor with recovery key `key_name` from `keys`, under `policy`
/// and `provider`.
///
/// # Safety
/// As for [`xs_signer_new`], writing one `XsDecryptor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_decryptor_new(
    policy_handle: XsPolicy,
    provider_handle: XsProvider,
    keys_handle: XsKeys,
    key_name: XsBytes,
    out: *mut XsDecryptor,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `out` and `key_name`.
        let (out, name) = unsafe { (output(out)?, text(key_name)?) };
        let (policy, provider, keys) = (
            policy(policy_handle)?,
            provider(provider_handle)?,
            keys(keys_handle)?,
        );
        let decryptor = Decryptor::new(objects::security(&policy, &provider)?, &keys, name)?;
        let value = insert(Object::Decryptor(decryptor))?;
        out.write(XsDecryptor { value });
        Ok(())
    })
}

/// Recover the `EncryptedData` whose schema `Id` is `encrypted_data_id`, or
/// the first one when it is empty, as one new document generation.
///
/// # Safety
/// As for [`xs_encrypt`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_decrypt(
    decryptor: XsDecryptor,
    document: XsDocument,
    encrypted_data_id: XsBytes,
    audit: *mut XsAudit,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `audit` and the ID.
        let (audit, id) = unsafe { (audit_slot(audit)?, optional_text(encrypted_data_id)?) };
        let decryptor = take(decryptor.value, Kind::Decryptor)?;
        let Object::Decryptor(decryptor) = decryptor.object() else {
            return Err(wrong());
        };
        let decided = with_document(document, |document| decryptor.decrypt(document, id))?;
        audit_out(audit, &decided)
    })
}

fn with_evidence<T>(
    handle: XsEvidence,
    body: impl FnOnce(&xml_sec::xmldsig::VerifyEvidence) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let evidence = take(handle.value, Kind::Evidence)?;
    let Object::Evidence(evidence) = evidence.object() else {
        return Err(wrong());
    };
    body(evidence)
}

/// Whether the request the evidence answers holds for `document` as it is
/// now: nonzero only for the verified generation of the same document.
///
/// # Safety
/// `accepted` is valid for writes of one `uint8_t`; `error` is null or valid
/// for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_evidence_accepted(
    evidence: XsEvidence,
    document: XsDocument,
    accepted: *mut u8,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `accepted`.
        let out = unsafe { output(accepted) }?;
        let verdict = with_evidence(evidence, |evidence| {
            with_document(document, |document| {
                evidence
                    .accepted(document)
                    .map_err(|error| Failure::from(xml_sec::XmlSecError::from(error)))
            })
        })?;
        out.write(u8::from(verdict));
        Ok(())
    })
}

/// The number of signatures the evidence reports.
///
/// # Safety
/// `count` is valid for writes of one `size_t`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_evidence_signature_count(
    evidence: XsEvidence,
    count: *mut usize,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `count`.
        let out = unsafe { output(count) }?;
        out.write(with_evidence(evidence, |evidence| {
            Ok(evidence.signatures().len())
        })?);
        Ok(())
    })
}

fn out_of_range() -> Failure {
    Failure::new(XS_INVALID_ARGUMENT, "index out of range")
}

/// The outcome of signature `index`, in document order.
///
/// # Safety
/// `outcome` is valid for writes of one `XsSignatureOutcome`; `error` is null
/// or valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_evidence_signature(
    evidence: XsEvidence,
    index: usize,
    outcome: *mut XsSignatureOutcome,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `outcome`.
        let out = unsafe { output(outcome) }?;
        let (outcome, key_trust) = with_evidence(evidence, |evidence| {
            objects::signature_outcome(evidence, index).ok_or_else(out_of_range)
        })?;
        out.write(XsSignatureOutcome { outcome, key_trust });
        Ok(())
    })
}

/// The audit of signature `index`, whatever its outcome.
///
/// # Safety
/// `audit` is valid for writes of one `XsAudit`; `error` is null or valid for
/// writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_evidence_signature_audit(
    evidence: XsEvidence,
    index: usize,
    audit: *mut XsAudit,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `audit`.
        let out = unsafe { output(audit) }?;
        let audit = with_evidence(evidence, |evidence| {
            let signature = evidence.signatures().get(index).ok_or_else(out_of_range)?;
            Ok(Audit::from(signature.policy()))
        })?;
        let value = insert(Object::Audit(audit))?;
        out.write(XsAudit { value });
        Ok(())
    })
}

fn identity_view(identity: Option<&xml_sec::policy::PolicyIdentity>) -> XsPolicyIdentity {
    match identity {
        Some(identity) => XsPolicyIdentity {
            present: 1,
            schema_version: identity.schema_version(),
            revision: identity.revision(),
            digest: *identity.digest(),
            profile: borrowed(identity.profile()),
        },
        None => XsPolicyIdentity {
            present: 0,
            schema_version: 0,
            revision: 0,
            digest: [0; 32],
            profile: EMPTY,
        },
    }
}

/// The snapshot the verification enforced, also without any signature. The
/// profile bytes stay valid until the evidence handle is destroyed.
///
/// # Safety
/// `identity` is valid for writes of one `XsPolicyIdentity`; `error` is null or
/// valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_evidence_policy_identity(
    evidence: XsEvidence,
    identity: *mut XsPolicyIdentity,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `identity`.
        let out = unsafe { output(identity) }?;
        out.write(with_evidence(evidence, |evidence| {
            Ok(identity_view(evidence.policy_identity()))
        })?);
        Ok(())
    })
}

/// The identity of a loaded snapshot. The profile bytes stay valid until the
/// policy handle is destroyed.
///
/// # Safety
/// `identity` is valid for writes of one `XsPolicyIdentity`; `error` is null or
/// valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_policy_identity(
    policy_handle: XsPolicy,
    identity: *mut XsPolicyIdentity,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `identity`.
        let out = unsafe { output(identity) }?;
        // The view borrows from the snapshot the table keeps alive until the
        // policy handle is destroyed.
        let snapshot = policy(policy_handle)?;
        out.write(identity_view(snapshot.identity()));
        Ok(())
    })
}

fn with_audit<T>(
    handle: XsAudit,
    body: impl FnOnce(&Audit) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let audit = take(handle.value, Kind::Audit)?;
    let Object::Audit(audit) = audit.object() else {
        return Err(wrong());
    };
    body(audit)
}

/// The snapshot the audited operation enforced. The profile bytes stay valid
/// until the audit handle is destroyed.
///
/// # Safety
/// As for [`xs_evidence_policy_identity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_audit_policy_identity(
    audit: XsAudit,
    identity: *mut XsPolicyIdentity,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `identity`.
        let out = unsafe { output(identity) }?;
        out.write(with_audit(audit, |audit| {
            Ok(identity_view(audit.identity.as_deref()))
        })?);
        Ok(())
    })
}

/// The number of decisions in the audit.
///
/// # Safety
/// As for [`xs_evidence_signature_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_audit_decision_count(
    audit: XsAudit,
    count: *mut usize,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `count`.
        let out = unsafe { output(count) }?;
        out.write(with_audit(audit, |audit| Ok(audit.decisions.len()))?);
        Ok(())
    })
}

/// Decision `index`, in the order the operation made them. Its text stays
/// valid until the audit handle is destroyed.
///
/// # Safety
/// `decision` is valid for writes of one `XsDecision`; `error` is null or
/// valid for writes of one `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_audit_decision(
    audit: XsAudit,
    index: usize,
    decision: *mut XsDecision,
    error: *mut XsError,
) -> XsStatus {
    // SAFETY: the caller's contract for `error`.
    let error = unsafe { error_slot(error) };
    contain(error, || {
        // SAFETY: the caller's contract for `decision`.
        let out = unsafe { output(decision) }?;
        out.write(with_audit(audit, |audit| {
            let view = audit.decisions.get(index).ok_or_else(out_of_range)?;
            Ok(XsDecision {
                kind: view.kind,
                role: view.role,
                uri_class: view.uri_class,
                manifests: view.manifests,
                violation: view.violation,
                text: borrowed(&view.text),
            })
        })?);
        Ok(())
    })
}

fn with_error<T>(handle: XsError, body: impl FnOnce(&Failure) -> T) -> Result<T, Failure> {
    let failure = take(handle.value, Kind::Error)?;
    let Object::Error(failure) = failure.object() else {
        return Err(wrong());
    };
    Ok(body(failure))
}

/// The status the failed call returned.
///
/// # Safety
/// `status` is valid for writes of one `int32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_error_status(error: XsError, status: *mut XsStatus) -> XsStatus {
    contain(None, || {
        // SAFETY: the caller's contract for `status`.
        let out = unsafe { output(status) }?;
        out.write(with_error(error, |failure| failure.status)?);
        Ok(())
    })
}

/// The `XS_VIOLATION_*` of a policy refusal; zero for any other failure.
///
/// # Safety
/// `violation` is valid for writes of one `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_error_policy_violation(
    error: XsError,
    violation: *mut u32,
) -> XsStatus {
    contain(None, || {
        // SAFETY: the caller's contract for `violation`.
        let out = unsafe { output(violation) }?;
        out.write(with_error(error, |failure| failure.violation)?);
        Ok(())
    })
}

/// The failure's UTF-8 diagnostic, valid until the error handle is destroyed.
///
/// # Safety
/// `message` is valid for writes of one `XsBytes`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_error_message(error: XsError, message: *mut XsBytes) -> XsStatus {
    contain(None, || {
        // SAFETY: the caller's contract for `message`.
        let out = unsafe { output(message) }?;
        out.write(with_error(error, |failure| borrowed(&failure.message))?);
        Ok(())
    })
}
