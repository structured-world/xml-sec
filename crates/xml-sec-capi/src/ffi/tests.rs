use super::{
    XsAudit, XsBytes, XsCompileContext, XsDecryptor, XsDocument, XsEncryptor, XsError, XsEvidence,
    XsKeyLookup, XsKeyQuery, XsKeys, XsPolicy, XsPolicyStore, XsProvider, XsSigner, XsVerifier,
    XsVerifyRequest, contain, keys as hold_keys, policy as hold_policy, provider as hold_provider,
    xs_audit_destroy, xs_buffer_free, xs_decrypt, xs_decryptor_destroy, xs_decryptor_new,
    xs_document_destroy, xs_document_parse, xs_document_serialize, xs_encrypt,
    xs_encryptor_destroy, xs_encryptor_new, xs_error_destroy, xs_error_message,
    xs_error_policy_violation, xs_error_status, xs_evidence_destroy, xs_keys_add_private_pem,
    xs_keys_add_public_pem, xs_keys_add_symmetric, xs_keys_destroy, xs_keys_new, xs_policy_destroy,
    xs_policy_store_destroy, xs_policy_store_load, xs_policy_store_new, xs_provider_destroy,
    xs_provider_new_rustcrypto, xs_sign, xs_signer_destroy, xs_signer_new, xs_verifier_destroy,
    xs_verifier_new, xs_verify,
};
use crate::objects::Failure;
use crate::status::{
    XS_BUSY, XS_CONFIGURATION, XS_DESTROYED_HANDLE, XS_DOCUMENT, XS_HANDLE_LIMIT, XS_INTERNAL,
    XS_INVALID_ARGUMENT, XS_KEY, XS_OK, XS_POLICY, XS_VERIFICATION, XsStatus,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use xml_sec::key_manager::{KeyInventory, KeyUsages};
use xml_sec::policy::{DecryptionPolicy, ResourcePolicy};
use xml_sec::provider::RUST_CRYPTO_PROVIDER;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, EncryptedDataBuilder, KeyCandidateBudget, KeyWrapAlgorithm,
    parse_encrypted_data,
};

/// The system allocator, recording the largest single request, so a test can
/// show an input was refused before the library copied it. Tests hold
/// [`crate::test_support::serial`], so no other test's allocations interleave.
struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every request is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded caller contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded caller contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        // SAFETY: forwarded caller contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Largest = Largest;

fn bytes(text: &str) -> XsBytes {
    XsBytes {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

const MODERN: &str = "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n";

/// A provider and a policy compiled from the Modern profile.
fn policy() -> (XsProvider, XsPolicyStore, XsPolicy) {
    policy_from(MODERN)
}

/// A provider and the `app` profile of `configuration`.
fn policy_from(configuration: &str) -> (XsProvider, XsPolicyStore, XsPolicy) {
    let mut provider = XsProvider::default();
    let mut store = XsPolicyStore::default();
    let mut policy = XsPolicy::default();
    let context = XsCompileContext {
        external_resources: 0,
        target_evidence: 1,
    };
    // SAFETY: every pointer names a live local of the declared type.
    unsafe {
        assert_eq!(
            xs_provider_new_rustcrypto(&raw mut provider, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_policy_store_new(
                bytes(configuration),
                bytes("app"),
                provider,
                &raw const context,
                std::ptr::null(),
                &raw mut store,
                std::ptr::null_mut(),
            ),
            XS_OK
        );
        assert_eq!(
            xs_policy_store_load(store, &raw mut policy, std::ptr::null_mut()),
            XS_OK
        );
    }
    (provider, store, policy)
}

fn release((provider, store, policy): (XsProvider, XsPolicyStore, XsPolicy)) {
    assert_eq!(xs_policy_destroy(policy), XS_OK);
    assert_eq!(xs_policy_store_destroy(store), XS_OK);
    assert_eq!(xs_provider_destroy(provider), XS_OK);
}

/// The status and message an error handle carries; the handle is destroyed.
fn take_error(error: XsError) -> (XsStatus, String) {
    let mut status = 0;
    let mut message = XsBytes {
        ptr: std::ptr::null(),
        len: 0,
    };
    // SAFETY: the outputs are live locals; the message is copied before the
    // handle that owns it is destroyed.
    let text = unsafe {
        assert_eq!(xs_error_status(error, &raw mut status), XS_OK);
        assert_eq!(xs_error_message(error, &raw mut message), XS_OK);
        String::from_utf8(std::slice::from_raw_parts(message.ptr, message.len).to_vec()).unwrap()
    };
    assert_eq!(xs_error_destroy(error), XS_OK);
    (status, text)
}

#[test]
fn a_panic_becomes_an_internal_status_and_error() {
    let _serial = crate::test_support::serial();
    // No unwinding may cross into C: the panic is contained and reported.
    let mut error = MaybeUninit::uninit();
    let status = contain(Some(&mut error), || panic!("contained"));
    assert_eq!(status, XS_INTERNAL);
    // SAFETY: `contain` writes the error slot on every path.
    let (status, message) = take_error(unsafe { error.assume_init() });
    assert_eq!(status, XS_INTERNAL);
    assert_eq!(message, "internal error");
}

#[test]
fn success_clears_the_error_slot() {
    let _serial = crate::test_support::serial();
    // A caller reusing one error variable never sees a previous failure.
    let mut error = MaybeUninit::new(XsError { value: 7 });
    assert_eq!(contain(Some(&mut error), || Ok(())), XS_OK);
    // SAFETY: initialized above and rewritten by `contain`.
    assert_eq!(unsafe { error.assume_init() }.value, 0);
    assert_eq!(
        contain(None, || Err(Failure::new(XS_DOCUMENT, "x"))),
        XS_DOCUMENT
    );
}

#[test]
fn invalid_pointers_and_lengths_are_refused_before_any_work() {
    let _serial = crate::test_support::serial();
    // A length without bytes, a length past the address space, invalid UTF-8
    // and a null output are argument errors, never dereferenced.
    let handles = policy();
    let mut document = XsDocument::default();
    let invalid_utf8 = [0xff_u8, 0xfe];
    for xml in [
        XsBytes {
            ptr: std::ptr::null(),
            len: 3,
        },
        XsBytes {
            ptr: invalid_utf8.as_ptr(),
            len: usize::MAX,
        },
        XsBytes {
            ptr: invalid_utf8.as_ptr(),
            len: invalid_utf8.len(),
        },
    ] {
        let mut error = XsError::default();
        // SAFETY: the byte strings are rejected before being read, or name a
        // live array; the outputs are live locals.
        let status =
            unsafe { xs_document_parse(handles.2, 1, xml, &raw mut document, &raw mut error) };
        assert_eq!(status, XS_INVALID_ARGUMENT);
        assert_eq!(take_error(error).0, XS_INVALID_ARGUMENT);
        assert_eq!(document.value, 0);
    }
    // SAFETY: a null output is reported, not written.
    let status = unsafe {
        xs_document_parse(
            handles.2,
            1,
            bytes("<a/>"),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_INVALID_ARGUMENT);
    release(handles);
}

#[test]
fn a_document_beyond_a_policy_limit_is_a_typed_policy_refusal() {
    let _serial = crate::test_support::serial();
    // Byte, depth, parse-work, node and namespace-binding ceilings of the
    // compiled policy refuse a document as policy, with the resource-limit
    // violation, not as malformed XML.
    let deep = "<a><b><c><d><e><f/></e></d></c></b></a>";
    let large = format!("<a>{}</a>", "x".repeat(256));
    let wide = format!("<a>{}</a>", "<b/>".repeat(64));
    // Bindings in scope at once, all declared on one element.
    let mut bound = String::from("<a");
    for n in 0..16 {
        write!(bound, " xmlns:p{n}='urn:{n}'").expect("a String accepts every write");
    }
    bound.push_str("/>");
    for (limit, xml) in [
        ("max_xml_document_bytes = 64", large.as_str()),
        ("max_xml_depth = 2", deep),
        ("max_xml_parse_work_bytes = 64", large.as_str()),
        ("max_xml_nodes = 8", wide.as_str()),
        ("max_xml_namespace_bindings = 4", bound.as_str()),
    ] {
        let handles = policy_from(&format!(
            "{MODERN}[profiles.app.verification.resources]\n{limit}\n"
        ));
        let mut document = XsDocument::default();
        let mut error = XsError::default();
        // SAFETY: the byte string names a live string; the outputs are live locals.
        let status = unsafe {
            xs_document_parse(handles.2, 1, bytes(xml), &raw mut document, &raw mut error)
        };
        let mut violation = 0;
        // SAFETY: the output is a live local.
        let read = unsafe { xs_error_policy_violation(error, &raw mut violation) };
        assert_eq!(read, XS_OK);
        let (error_status, message) = take_error(error);
        assert_eq!(
            (status, error_status, violation),
            (XS_POLICY, XS_POLICY, 8),
            "{limit}: {message}"
        );
        release(handles);
    }
}

/// A key manager under `[profiles.app.verification.resources]` `limits`.
fn keys_under(limits: &str) -> ((XsProvider, XsPolicyStore, XsPolicy), XsKeys) {
    let handles = policy_from(&format!(
        "{MODERN}[profiles.app.verification.resources]\n{limits}\n"
    ));
    let mut keys = XsKeys::default();
    // SAFETY: the output is a live local.
    let status = unsafe { xs_keys_new(handles.2, 1, &raw mut keys, std::ptr::null_mut()) };
    assert_eq!(status, XS_OK);
    (handles, keys)
}

#[test]
fn input_beyond_a_policy_limit_is_refused_before_it_is_copied() {
    let _serial = crate::test_support::serial();
    // A caller's bytes past the compiled ceiling are refused without the
    // library allocating their size, so an oversized input cannot exhaust
    // memory and abort the process before the refusal.
    let (handles, keys) = keys_under("max_external_resource_bytes = 64");
    let key = vec![7_u8; 1 << 20];
    let large = format!("<a>{}</a>", "x".repeat(1 << 20));
    let name = "n".repeat(1 << 20);
    let parse_handles = policy_from(&format!(
        "{MODERN}[profiles.app.verification.resources]\nmax_xml_document_bytes = 64\n"
    ));
    LARGEST.store(0, Ordering::Relaxed);
    let mut error = XsError::default();
    // SAFETY: the byte strings name live buffers; the output is a live local.
    let status = unsafe {
        xs_keys_add_symmetric(
            keys,
            bytes("hmac"),
            1,
            XsBytes {
                ptr: key.as_ptr(),
                len: key.len(),
            },
            1,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_POLICY);
    assert_eq!(take_error(error).0, XS_POLICY);
    let mut document = XsDocument::default();
    // SAFETY: as above.
    let status = unsafe {
        xs_document_parse(
            parse_handles.2,
            1,
            bytes(&large),
            &raw mut document,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_POLICY);
    assert_eq!(take_error(error).0, XS_POLICY);
    // A key name past the ceiling, through each of the three imports.
    // SAFETY: as above.
    let statuses = unsafe {
        [
            xs_keys_add_symmetric(
                keys,
                bytes(&name),
                1,
                bytes("0123456789abcdef"),
                1,
                &raw mut error,
            ),
            xs_keys_add_private_pem(
                keys,
                bytes(&name),
                bytes("pem"),
                bytes(""),
                1,
                &raw mut error,
            ),
            xs_keys_add_public_pem(keys, bytes(&name), bytes("pem"), 2, &raw mut error),
        ]
    };
    assert_eq!(statuses, [XS_POLICY; 3]);
    assert_eq!(take_error(error).0, XS_POLICY);
    assert!(LARGEST.load(Ordering::Relaxed) < 1 << 20);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
    release(parse_handles);
}

const TEMPLATE: &str = concat!(
    "<root><p Id=\"payload\">signed</p>",
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>",
    "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
    "<ds:Reference URI=\"#payload\"><ds:Transforms>",
    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    "<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>",
    "<ds:SignatureValue></ds:SignatureValue></ds:Signature></root>"
);

/// The document's current XML.
fn serialized(document: XsDocument) -> String {
    let mut buffer = MaybeUninit::uninit();
    // SAFETY: the output is a live local; the buffer is copied, then released
    // once with the library that allocated it.
    unsafe {
        assert_eq!(
            xs_document_serialize(document, buffer.as_mut_ptr(), std::ptr::null_mut()),
            XS_OK
        );
        let buffer = buffer.assume_init();
        let xml = String::from_utf8(std::slice::from_raw_parts(buffer.ptr, buffer.len).to_vec());
        xs_buffer_free(buffer);
        xml.unwrap()
    }
}

const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// A key store a test lookup reads, and what that lookup observed.
struct Store {
    pem: &'static str,
    private_key: bool,
    usages: u32,
    /// The method the stored key serves; other requests find nothing.
    method: &'static str,
    /// Import the key a second time, as "second", for an unnamed request.
    twice: bool,
    /// A key name the store fails to look up with `XS_KEY`.
    refuse: &'static str,
    result: XsStatus,
    queries: Vec<(Vec<String>, String)>,
    kept: XsKeys,
}

/// Import the stored key under each name the document gives, or "found".
unsafe extern "C" fn store_lookup(
    user_data: *mut std::ffi::c_void,
    query: *const XsKeyQuery,
    keys: XsKeys,
) -> XsStatus {
    // SAFETY: the tests pass a live `Store` as user data, and the library
    // passes a query valid for this invocation.
    let (store, query) = unsafe { (&mut *user_data.cast::<Store>(), &*query) };
    let view = |bytes: XsBytes| {
        // SAFETY: the query's byte strings are borrowed for this invocation.
        String::from_utf8(unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) }.to_vec())
            .unwrap()
    };
    let names: Vec<String> = if query.name_count == 0 {
        Vec::new()
    } else {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(query.names, query.name_count) }
            .iter()
            .map(|name| view(*name))
            .collect()
    };
    let method = view(query.method);
    store.queries.push((names.clone(), method.clone()));
    store.kept = keys;
    if store.result != XS_OK {
        return store.result;
    }
    if names.iter().any(|name| name == store.refuse) {
        return XS_KEY;
    }
    if method != store.method {
        return XS_OK;
    }
    let names = match (names.is_empty(), store.twice) {
        (false, _) => names,
        (true, false) => vec!["found".to_owned()],
        (true, true) => vec!["found".to_owned(), "second".to_owned()],
    };
    for name in names {
        // SAFETY: the byte strings name live strings.
        let status = unsafe {
            if store.private_key {
                xs_keys_add_private_pem(
                    keys,
                    bytes(&name),
                    bytes(store.pem),
                    bytes(""),
                    store.usages,
                    std::ptr::null_mut(),
                )
            } else {
                xs_keys_add_public_pem(
                    keys,
                    bytes(&name),
                    bytes(store.pem),
                    store.usages,
                    std::ptr::null_mut(),
                )
            }
        };
        if status != XS_OK {
            return status;
        }
    }
    XS_OK
}

/// `TEMPLATE` signed with the RSA test key, its `KeyInfo` naming "signer".
fn signed_with_key_name() -> String {
    let handles = policy();
    let key = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let template = TEMPLATE.replace(
        "</ds:Signature>",
        "<ds:KeyInfo><ds:KeyName>signer</ds:KeyName></ds:KeyInfo></ds:Signature>",
    );
    let (mut keys, mut signer, mut document) = (
        XsKeys::default(),
        XsSigner::default(),
        XsDocument::default(),
    );
    // SAFETY: every pointer names a live local or a live string.
    unsafe {
        assert_eq!(
            xs_keys_new(handles.2, 2, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_private_pem(
                keys,
                bytes("signer"),
                bytes(key),
                bytes(""),
                1,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_signer_new(
                handles.2,
                handles.0,
                keys,
                bytes("signer"),
                bytes(RSA_SHA256),
                &raw mut signer,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                2,
                bytes(&template),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_sign(signer, document, std::ptr::null_mut(), std::ptr::null_mut()),
            XS_OK
        );
    }
    let output = serialized(document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_signer_destroy(signer), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
    output
}

#[test]
fn a_lookup_supplies_the_verification_key_for_the_name_the_document_gives() {
    let _serial = crate::test_support::serial();
    // A verifier without keys resolves the signer through the lookup: it is
    // asked for the KeyName and the signature method, its key is trusted as
    // any application key, and its key manager ends with the invocation.
    let signed = signed_with_key_name();
    let handles = policy();
    let mut store = Store {
        pem: include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        private_key: false,
        usages: 2,
        method: RSA_SHA256,
        twice: false,
        refuse: "",
        result: XS_OK,
        queries: Vec::new(),
        kept: XsKeys::default(),
    };
    let lookup = XsKeyLookup {
        lookup: Some(store_lookup),
        user_data: (&raw mut store).cast(),
    };
    let (mut verifier, mut document, mut evidence) = (
        XsVerifier::default(),
        XsDocument::default(),
        XsEvidence::default(),
    );
    let ids = [bytes("payload")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: 1,
        requirement: 0,
        count: 0,
    };
    // SAFETY: every pointer names a live local, array or string.
    let status = unsafe {
        assert_eq!(
            xs_verifier_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                1,
                bytes(&signed),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_verify(
            verifier,
            document,
            &raw const request,
            &raw const lookup,
            &raw mut evidence,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_OK);
    assert_eq!(
        store.queries,
        [(vec!["signer".to_owned()], RSA_SHA256.to_owned())]
    );
    let held = crate::table::use_handle(evidence.value, crate::table::Kind::Evidence).unwrap();
    let crate::objects::Object::Evidence(report) = held.object() else {
        panic!("an evidence handle holds evidence");
    };
    let outcome = report.signatures()[0].result();
    assert!(
        matches!(outcome, Ok(result) if result.status == xml_sec::xmldsig::DsigStatus::Valid),
        "{outcome:?}"
    );
    drop(held);
    assert_eq!(
        // SAFETY: the byte strings name live strings.
        unsafe {
            xs_keys_add_symmetric(
                store.kept,
                bytes("late"),
                1,
                bytes("0123456789abcdef"),
                2,
                std::ptr::null_mut(),
            )
        },
        XS_DESTROYED_HANDLE
    );
    assert_eq!(xs_evidence_destroy(evidence), XS_OK);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    release(handles);
}

/// Verify `signed` through a lookup over `store`; the status and evidence.
fn verify_through(signed: &str, store: &mut Store) -> (XsStatus, XsStatus, XsEvidence) {
    let handles = policy();
    let lookup = XsKeyLookup {
        lookup: Some(store_lookup),
        user_data: std::ptr::from_mut(store).cast(),
    };
    let (mut verifier, mut document, mut evidence) = (
        XsVerifier::default(),
        XsDocument::default(),
        XsEvidence::default(),
    );
    let mut error = XsError::default();
    let ids = [bytes("payload")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: 1,
        requirement: 0,
        count: 0,
    };
    // SAFETY: every pointer names a live local, array or string.
    let status = unsafe {
        assert_eq!(
            xs_verifier_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                1,
                bytes(signed),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_verify(
            verifier,
            document,
            &raw const request,
            &raw const lookup,
            &raw mut evidence,
            &raw mut error,
        )
    };
    let reported = if error.value == 0 {
        XS_OK
    } else {
        take_error(error).0
    };
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    release(handles);
    (status, reported, evidence)
}

#[test]
fn a_failing_lookup_fails_the_call_with_its_status() {
    let _serial = crate::test_support::serial();
    // The callback's failure is the call's typed status, not a signature the
    // verification could not resolve; a code the header does not name is an
    // internal failure rather than a status the caller cannot interpret.
    let signed = signed_with_key_name();
    for (returned, expected) in [(XS_KEY, XS_KEY), (77, XS_INTERNAL), (-1, XS_INTERNAL)] {
        let mut store = Store {
            pem: "",
            private_key: false,
            usages: 2,
            method: RSA_SHA256,
            twice: false,
            refuse: "",
            result: returned,
            queries: Vec::new(),
            kept: XsKeys::default(),
        };
        let (status, reported, evidence) = verify_through(&signed, &mut store);
        assert_eq!((returned, status, reported), (returned, expected, expected));
        assert_eq!(evidence.value, 0);
    }
}

/// Destroys the key manager it is given, then finds nothing.
unsafe extern "C" fn destroying_lookup(
    _user_data: *mut std::ffi::c_void,
    _query: *const XsKeyQuery,
    keys: XsKeys,
) -> XsStatus {
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    XS_OK
}

#[test]
fn a_lookup_may_destroy_the_key_manager_it_is_given() {
    let _serial = crate::test_support::serial();
    // The key manager belongs to the call; a callback destroying its handle
    // only ends that handle, and the call completes without the key.
    let signed = signed_with_key_name();
    let handles = policy();
    let lookup = XsKeyLookup {
        lookup: Some(destroying_lookup),
        user_data: std::ptr::null_mut(),
    };
    let (mut verifier, mut document, mut evidence) = (
        XsVerifier::default(),
        XsDocument::default(),
        XsEvidence::default(),
    );
    let ids = [bytes("payload")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: 1,
        requirement: 0,
        count: 0,
    };
    // SAFETY: every pointer names a live local, array or string.
    let status = unsafe {
        assert_eq!(
            xs_verifier_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                1,
                bytes(&signed),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_verify(
            verifier,
            document,
            &raw const request,
            &raw const lookup,
            &raw mut evidence,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_OK);
    let held = crate::table::use_handle(evidence.value, crate::table::Kind::Evidence).unwrap();
    let crate::objects::Object::Evidence(report) = held.object() else {
        panic!("an evidence handle holds evidence");
    };
    assert!(!matches!(
        report.signatures()[0].result(),
        Ok(result) if result.status == xml_sec::xmldsig::DsigStatus::Valid
    ));
    drop(held);
    assert_eq!(xs_evidence_destroy(evidence), XS_OK);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    release(handles);
}

/// The policy a lookup creates objects under, and the key manager it made.
struct Replacing {
    policy: XsPolicy,
    created: XsKeys,
}

/// Destroys the key manager it is given and creates another one, which takes
/// over the freed table slot, then finds nothing.
unsafe extern "C" fn replacing_lookup(
    user_data: *mut std::ffi::c_void,
    _query: *const XsKeyQuery,
    keys: XsKeys,
) -> XsStatus {
    // SAFETY: the test passes a live `Replacing` as user data.
    let state = unsafe { &mut *user_data.cast::<Replacing>() };
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    // SAFETY: the output is a live field.
    let created = unsafe {
        xs_keys_new(
            state.policy,
            2,
            &raw mut state.created,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(created, XS_OK);
    XS_OK
}

#[test]
fn a_lookup_may_destroy_its_key_manager_and_create_objects() {
    let _serial = crate::test_support::serial();
    // Both are supported actions of a lookup: the new object reuses the freed
    // slot under a newer generation, and the call neither fails releasing the
    // handle it gave out nor touches the object that replaced it.
    let signed = signed_with_key_name();
    let handles = policy();
    let mut state = Replacing {
        policy: handles.2,
        created: XsKeys::default(),
    };
    let lookup = XsKeyLookup {
        lookup: Some(replacing_lookup),
        user_data: std::ptr::from_mut(&mut state).cast(),
    };
    let (mut verifier, mut document, mut evidence) = (
        XsVerifier::default(),
        XsDocument::default(),
        XsEvidence::default(),
    );
    let ids = [bytes("payload")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: 1,
        requirement: 0,
        count: 0,
    };
    // SAFETY: every pointer names a live local, array or string.
    let status = unsafe {
        assert_eq!(
            xs_verifier_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                1,
                bytes(&signed),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_verify(
            verifier,
            document,
            &raw const request,
            &raw const lookup,
            &raw mut evidence,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_OK);
    assert_ne!(state.created.value, 0);
    assert_eq!(xs_keys_destroy(state.created), XS_OK);
    assert_eq!(xs_evidence_destroy(evidence), XS_OK);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    release(handles);
}

const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

/// `<root><secret Id="s">42</secret></root>` with `secret` encrypted for the
/// RSA test key, its `EncryptedKey` naming "recipient".
fn encrypted_for_recipient() -> String {
    let handles = policy();
    let public = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let (mut keys, mut encryptor, mut document) = (
        XsKeys::default(),
        XsEncryptor::default(),
        XsDocument::default(),
    );
    // SAFETY: every pointer names a live local or a live string.
    unsafe {
        assert_eq!(
            xs_keys_new(handles.2, 3, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_public_pem(
                keys,
                bytes("recipient"),
                bytes(public),
                4,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_encryptor_new(
                handles.2,
                handles.0,
                keys,
                bytes("recipient"),
                bytes(AES256_GCM),
                &raw mut encryptor,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                3,
                bytes("<root><secret Id=\"s\">42</secret></root>"),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_encrypt(
                encryptor,
                document,
                bytes("s"),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            XS_OK
        );
    }
    let encrypted = serialized(document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_encryptor_destroy(encryptor), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
    encrypted
}

/// Decrypt `encrypted` with a keyless decryptor through a lookup over
/// `store`; the status and the resulting XML.
fn decrypt_through(encrypted: &str, store: &mut Store) -> (XsStatus, String) {
    let handles = policy();
    let lookup = XsKeyLookup {
        lookup: Some(store_lookup),
        user_data: std::ptr::from_mut(store).cast(),
    };
    let (mut decryptor, mut document) = (XsDecryptor::default(), XsDocument::default());
    // SAFETY: every pointer names a live local or a live string.
    let status = unsafe {
        assert_eq!(
            xs_decryptor_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                bytes(""),
                &raw mut decryptor,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                4,
                bytes(encrypted),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_decrypt(
            decryptor,
            document,
            bytes(""),
            &raw const lookup,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    let xml = serialized(document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_decryptor_destroy(decryptor), XS_OK);
    release(handles);
    (status, xml)
}

/// A key store that answers only for RSA-OAEP key transport.
fn recipient_store() -> Store {
    Store {
        pem: include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
        private_key: true,
        usages: 8,
        method: RSA_OAEP,
        twice: false,
        refuse: "",
        result: XS_OK,
        queries: Vec::new(),
        kept: XsKeys::default(),
    }
}

#[test]
fn a_lookup_supplies_the_recovery_key_by_name_or_as_the_only_key() {
    let _serial = crate::test_support::serial();
    // The EncryptedKey's KeyName selects the imported key; without a name,
    // the one key the lookup imported for that transport serves, and two
    // imported keys are no selection at all.
    let encrypted = encrypted_for_recipient();
    let mut store = recipient_store();
    let (status, xml) = decrypt_through(&encrypted, &mut store);
    assert_eq!(status, XS_OK, "{:?}", store.queries);
    assert!(xml.contains("<secret Id=\"s\">42</secret>"));
    assert!(
        store
            .queries
            .contains(&(vec!["recipient".to_owned()], RSA_OAEP.to_owned()))
    );

    let unnamed = encrypted.replace(
        "<ds:KeyInfo><ds:KeyName>recipient</ds:KeyName></ds:KeyInfo>",
        "",
    );
    assert_ne!(unnamed, encrypted, "{encrypted}");
    let mut store = recipient_store();
    let (status, xml) = decrypt_through(&unnamed, &mut store);
    assert_eq!(status, XS_OK, "{:?}", store.queries);
    assert!(xml.contains("<secret Id=\"s\">42</secret>"));
    assert!(store.queries.contains(&(Vec::new(), RSA_OAEP.to_owned())));

    let mut store = Store {
        twice: true,
        ..recipient_store()
    };
    let (status, xml) = decrypt_through(&unnamed, &mut store);
    assert_ne!(status, XS_OK);
    assert!(!xml.contains("<secret"));
}

/// `<root><secret Id="s">42</secret></root>` with `secret` encrypted under a
/// content key AES-256-wrapped by a key that a nested RSA-OAEP
/// `EncryptedKey` naming "recipient" transports.
fn encrypted_through_a_nested_recipient() -> String {
    // The RSA-OAEP EncryptedKey of a document encrypted for "recipient", and
    // the 256-bit key it transports, recovered here to wrap the outer key.
    let transport = encrypted_for_recipient();
    let start = transport.find("<xenc:EncryptedKey>").unwrap();
    let end = transport.find("</xenc:EncryptedKey>").unwrap() + "</xenc:EncryptedKey>".len();
    let nested = &transport[start..end];
    let data = &transport["<root>".len()..transport.len() - "</root>".len()];
    let mut inventory = KeyInventory::default();
    inventory
        .add_private_pem(
            "recipient",
            recipient_store().pem.as_bytes(),
            None,
            KeyUsages::DECRYPT,
            &ResourcePolicy::default(),
        )
        .unwrap();
    let policy_snapshot = DecryptionPolicy::default();
    let kek = inventory
        .decryption_resolver_with_provider("recipient", &policy_snapshot, &RUST_CRYPTO_PROVIDER)
        .unwrap()
        .resolve_content_keys_with_policy(
            &RUST_CRYPTO_PROVIDER,
            DataEncryptionAlgorithm::Aes256Gcm,
            Some(&parse_encrypted_data(data).unwrap().encrypted_keys[0]),
            &policy_snapshot,
            &mut KeyCandidateBudget::for_operation(),
        )
        .unwrap()
        .remove(0)
        .into_key()
        .unwrap();
    let outer = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .recipient_aes_kw(kek, KeyWrapAlgorithm::AesKw256)
        .encrypt_xml("<secret Id=\"s\">42</secret>")
        .unwrap()
        .encrypted_data_xml;
    let method =
        "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes256\"/>";
    assert!(outer.contains(method), "{outer}");
    format!(
        "<root>{}</root>",
        outer.replacen(
            method,
            &format!("{method}<ds:KeyInfo>{nested}</ds:KeyInfo>"),
            1
        )
    )
}

#[test]
fn a_lookup_is_asked_for_a_nested_key_with_its_own_method() {
    let _serial = crate::test_support::serial();
    // The lookup is asked for "recipient" with RSA-OAEP, the method the key
    // it holds serves, not with the outer AES wrap method.
    let document = encrypted_through_a_nested_recipient();
    let handles = policy();
    let mut store = recipient_store();
    let lookup = XsKeyLookup {
        lookup: Some(store_lookup),
        user_data: std::ptr::from_mut(&mut store).cast(),
    };
    let (mut decryptor, mut parsed) = (XsDecryptor::default(), XsDocument::default());
    let mut error = XsError::default();
    // SAFETY: every pointer names a live local or a live string.
    let status = unsafe {
        assert_eq!(
            xs_decryptor_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                bytes(""),
                &raw mut decryptor,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                4,
                bytes(&document),
                &raw mut parsed,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_decrypt(
            decryptor,
            parsed,
            bytes(""),
            &raw const lookup,
            std::ptr::null_mut(),
            &raw mut error,
        )
    };
    let message = if error.value == 0 {
        String::new()
    } else {
        take_error(error).1
    };
    let xml = serialized(parsed);
    assert_eq!(xs_document_destroy(parsed), XS_OK);
    assert_eq!(xs_decryptor_destroy(decryptor), XS_OK);
    release(handles);
    assert_eq!(status, XS_OK, "{message}: {:?}", store.queries);
    assert!(xml.contains("<secret Id=\"s\">42</secret>"), "{xml}");
    assert!(
        store
            .queries
            .contains(&(vec!["recipient".to_owned()], RSA_OAEP.to_owned())),
        "{:?}",
        store.queries
    );
}

#[test]
fn a_failed_lookup_leaves_the_document_encrypted() {
    let _serial = crate::test_support::serial();
    // The first recipient's key recovers the content, the lookup for the
    // second fails: the call fails with the lookup's status before the
    // plaintext replaces the EncryptedData, not after.
    let encrypted = encrypted_for_recipient();
    let start = encrypted.find("<xenc:EncryptedKey>").unwrap();
    let end = encrypted.find("</xenc:EncryptedKey>").unwrap() + "</xenc:EncryptedKey>".len();
    let other = encrypted[start..end].replace(
        "<ds:KeyName>recipient</ds:KeyName>",
        "<ds:KeyName>other</ds:KeyName>",
    );
    let two = format!("{}{other}{}", &encrypted[..end], &encrypted[end..]);
    let mut store = Store {
        refuse: "other",
        ..recipient_store()
    };
    let (status, xml) = decrypt_through(&two, &mut store);
    assert_eq!(status, XS_KEY, "{:?}", store.queries);
    assert_eq!(xml, two);
}

#[test]
fn diagnostics_never_carry_passwords_or_key_bytes() {
    let _serial = crate::test_support::serial();
    // Error messages are the Rust API's redacted diagnostics: a wrong
    // password, malformed private key material and a rejected secret key
    // each fail with a message that contains none of the caller's secrets.
    let encrypted =
        include_str!("../../../../tests/fixtures/xmldsig/keys/eddsa/eddsa-ed25519-key.p8-pem");
    let malformed =
        "-----BEGIN PRIVATE KEY-----\nU0VDUkVUS0VZQllURVM=\n-----END PRIVATE KEY-----\n";
    let handles = policy();
    let mut keys = XsKeys::default();
    // SAFETY: the output is a live local.
    let created = unsafe { xs_keys_new(handles.2, 2, &raw mut keys, std::ptr::null_mut()) };
    assert_eq!(created, XS_OK);
    let mut messages = Vec::new();
    for attempt in 0..3 {
        let mut error = XsError::default();
        // SAFETY: the byte strings name live strings; the output is a live local.
        let status = unsafe {
            match attempt {
                0 => xs_keys_add_private_pem(
                    keys,
                    bytes("a"),
                    bytes(encrypted),
                    bytes("hunter2-correct-horse"),
                    1,
                    &raw mut error,
                ),
                1 => xs_keys_add_private_pem(
                    keys,
                    bytes("b"),
                    bytes(malformed),
                    bytes(""),
                    1,
                    &raw mut error,
                ),
                _ => xs_keys_add_symmetric(
                    keys,
                    bytes("c"),
                    2,
                    bytes("TOPSECRETAES"),
                    8,
                    &raw mut error,
                ),
            }
        };
        assert_ne!(status, XS_OK, "attempt {attempt}");
        messages.push(take_error(error).1);
    }
    for message in &messages {
        assert_ne!(message, "");
        for secret in [
            "hunter2",
            "U0VDUkVUS0VZQllURVM",
            "SECRETKEYBYTES",
            "TOPSECRET",
            "MC4CAQAw",
        ] {
            assert!(!message.contains(secret), "{message}");
        }
    }
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
}

#[test]
fn concurrent_destroys_release_an_object_exactly_once() {
    let _serial = crate::test_support::serial();
    // Threads racing to destroy one handle: exactly one succeeds and every
    // other one is told the handle is destroyed, round after round, so no
    // object is released twice or reached after release.
    for _ in 0..200 {
        let handle =
            crate::table::insert(crate::objects::Object::Error(Failure::new(XS_KEY, "x"))).unwrap();
        let outcomes: Vec<XsStatus> = std::thread::scope(|scope| {
            let racers: Vec<_> = (0..8)
                .map(|_| scope.spawn(move || xs_error_destroy(XsError { value: handle })))
                .collect();
            racers
                .into_iter()
                .map(|racer| racer.join().unwrap())
                .collect()
        });
        assert_eq!(
            outcomes.iter().filter(|status| **status == XS_OK).count(),
            1,
            "{outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .all(|status| [XS_OK, XS_DESTROYED_HANDLE].contains(status)),
            "{outcomes:?}"
        );
    }
}

#[test]
fn a_destroy_racing_running_calls_waits_for_them_and_ends_every_later_use() {
    let _serial = crate::test_support::serial();
    // Readers use one error handle while another thread destroys it: a read
    // either completes on the live object or reports the handle destroyed,
    // the destroyer sees busy until no read is running, and once destroyed
    // the handle stays destroyed.
    for _ in 0..50 {
        let handle =
            crate::table::insert(crate::objects::Object::Error(Failure::new(XS_KEY, "x"))).unwrap();
        let error = XsError { value: handle };
        std::thread::scope(|scope| {
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(move || {
                        for _ in 0..200 {
                            let mut status = 0;
                            // SAFETY: the output is a live local.
                            match unsafe { xs_error_status(error, &raw mut status) } {
                                XS_OK => assert_eq!(status, XS_KEY),
                                outcome => assert_eq!(outcome, XS_DESTROYED_HANDLE),
                            }
                        }
                    })
                })
                .collect();
            loop {
                match xs_error_destroy(error) {
                    XS_OK => break,
                    XS_BUSY => std::hint::spin_loop(),
                    other => panic!("destroy returned {other}"),
                }
            }
            for reader in readers {
                reader.join().unwrap();
            }
        });
        assert_eq!(xs_error_destroy(error), XS_DESTROYED_HANDLE);
        let mut status = 0;
        // SAFETY: the output is a live local.
        let read = unsafe { xs_error_status(error, &raw mut status) };
        assert_eq!(read, XS_DESTROYED_HANDLE);
    }
}

#[test]
fn an_audit_that_cannot_be_published_leaves_the_document_unchanged() {
    let _serial = crate::test_support::serial();
    // The audit handle's slot is held before the document changes: a full
    // table refuses the call and keeps the document's generation, so a retry
    // cannot sign an already signed document.
    let handles = policy();
    let key = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let (mut keys, mut signer, mut document) = (
        XsKeys::default(),
        XsSigner::default(),
        XsDocument::default(),
    );
    // SAFETY: every pointer names a live local or a live string.
    unsafe {
        assert_eq!(
            xs_keys_new(handles.2, 2, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_private_pem(
                keys,
                bytes("signer"),
                bytes(key),
                bytes(""),
                1,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_signer_new(
                handles.2,
                handles.0,
                keys,
                bytes("signer"),
                bytes("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
                &raw mut signer,
                std::ptr::null_mut(),
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                2,
                bytes(TEMPLATE),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
    }
    crate::table::EXHAUSTED.store(true, Ordering::Relaxed);
    let mut audit = XsAudit::default();
    // SAFETY: the outputs are live locals.
    let status = unsafe { xs_sign(signer, document, &raw mut audit, std::ptr::null_mut()) };
    crate::table::EXHAUSTED.store(false, Ordering::Relaxed);
    assert_eq!(status, XS_HANDLE_LIMIT);
    assert_eq!(audit.value, 0);
    assert_eq!(serialized(document), TEMPLATE);
    // With a slot available the same call signs and reports its audit.
    // SAFETY: as above.
    let status = unsafe { xs_sign(signer, document, &raw mut audit, std::ptr::null_mut()) };
    assert_eq!(status, XS_OK);
    assert_ne!(serialized(document), TEMPLATE);
    assert_eq!(xs_audit_destroy(audit), XS_OK);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_signer_destroy(signer), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
}

#[test]
fn a_request_for_more_targets_than_the_policy_admits_is_refused_before_lookup() {
    let _serial = crate::test_support::serial();
    // Each expected ID is a scan of the document: a request over the
    // compiled reference ceiling is refused before any of them is resolved,
    // so its IDs, here none of them present, are never looked up.
    let handles = policy_from(&format!(
        "{MODERN}[profiles.app.verification.resources]\nmax_references = 2\n"
    ));
    let (mut verifier, mut document) = (XsVerifier::default(), XsDocument::default());
    let ids = [bytes("a"), bytes("b"), bytes("c")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: ids.len(),
        requirement: 0,
        count: 0,
    };
    let mut evidence = XsEvidence::default();
    let mut error = XsError::default();
    // SAFETY: every pointer names a live local, array or string.
    let status = unsafe {
        assert_eq!(
            xs_verifier_new(
                handles.2,
                handles.0,
                XsKeys::default(),
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_document_parse(
                handles.2,
                1,
                bytes("<root/>"),
                &raw mut document,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_verify(
            verifier,
            document,
            &raw const request,
            std::ptr::null(),
            &raw mut evidence,
            &raw mut error,
        )
    };
    let (_, message) = take_error(error);
    assert_eq!(
        (status, message.as_str()),
        (
            XS_VERIFICATION,
            "invalid verification request: too many expected coverage targets"
        )
    );
    assert_eq!(evidence.value, 0);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    release(handles);
}

#[test]
fn a_held_object_is_busy_until_the_call_that_holds_it_ends() {
    let _serial = crate::test_support::serial();
    // A call keeps the provider, policy and key handles it reads in use for
    // its whole length, so destroying them meanwhile reports busy.
    let (handles, keys_handle) = keys_under("");
    let (Ok(held_provider), Ok(held_policy), Ok(held_keys)) = (
        hold_provider(handles.0),
        hold_policy(handles.2),
        hold_keys(keys_handle),
    ) else {
        panic!("live handles must be held");
    };
    assert_eq!(xs_provider_destroy(handles.0), XS_BUSY);
    assert_eq!(xs_policy_destroy(handles.2), XS_BUSY);
    assert_eq!(xs_keys_destroy(keys_handle), XS_BUSY);
    drop((held_provider, held_policy, held_keys));
    assert_eq!(xs_keys_destroy(keys_handle), XS_OK);
    release(handles);
}

#[test]
fn configuration_and_document_failures_carry_their_class() {
    let _serial = crate::test_support::serial();
    // The status names the failing layer, and the message comes with it.
    let handles = policy();
    let context = XsCompileContext {
        external_resources: 0,
        target_evidence: 0,
    };
    let mut store = XsPolicyStore::default();
    let mut error = XsError::default();
    // SAFETY: every pointer names a live local of the declared type.
    let status = unsafe {
        xs_policy_store_new(
            bytes("schema_version = 1\n[profiles.app\n"),
            bytes("app"),
            handles.0,
            &raw const context,
            std::ptr::null(),
            &raw mut store,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_CONFIGURATION);
    assert_eq!(store.value, 0);
    let (status, message) = take_error(error);
    assert_eq!(status, XS_CONFIGURATION);
    assert_ne!(message, "");

    let mut document = XsDocument::default();
    // SAFETY: as above.
    let status = unsafe {
        xs_document_parse(
            handles.2,
            1,
            bytes("<broken"),
            &raw mut document,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_DOCUMENT);
    assert_eq!(take_error(error).0, XS_DOCUMENT);
    release(handles);
}
