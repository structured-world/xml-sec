use super::*;

use xml_sec::xmlenc::DataEncryptionAlgorithm;
use xml_sec_libxml2::ffi::tree::{xsDocSetRootElement, xsFreeDoc, xsNewDoc};

use crate::ffi::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::crypto::{
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use crate::ffi::keyinfo::XmlSecKeyInfoCtx;
use crate::ffi::keys::xmlSecKeyCreate;
use crate::ffi::keysdata::xmlSecKeyDataBinRead;
use crate::ffi::keysmngr::{xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use crate::ffi::library::{xmlSecInit, xmlSecShutdown};
use crate::ffi::symkeys;
use crate::ffi::templates::{xmlSecTmplEncDataCreate, xmlSecTmplEncDataEnsureCipherValue};
use crate::ffi::tests::own_process;
use crate::ffi::transforms::ciphers::aes128_cbc;

/// An AES key of sixteen `0x5a` octets.
fn aes_key() -> *mut XmlSecKey {
    aes_key_of([0x5a; 16])
}

/// An AES key of `bytes`.
fn aes_key_of(bytes: [u8; 16]) -> *mut XmlSecKey {
    // SAFETY: a key and a read context created here; the AES klass reads
    // the key.
    unsafe {
        let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::aes(),
                key.cast(),
                bytes.as_ptr(),
                bytes.len(),
                read.cast(),
            ),
            0
        );
        crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        key
    }
}

/// A key manager's lookup that republishes a policy refusing AES-128-CBC
/// while it answers, then hands back the key.
unsafe extern "C" fn republishing_lookup(
    _node: *mut XmlNode,
    _ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    xml_sec_libxml2::policy::republish_encryption(
        |_| {},
        |decryption| {
            if let Some(allowed) = decryption.data_algorithms.as_mut() {
                allowed.remove(&DataEncryptionAlgorithm::Aes128Cbc);
            }
        },
    )
    .expect("the library policy compiles");
    aes_key()
}

#[test]
fn one_decryption_runs_under_the_revision_its_key_was_read_under() {
    // A republish while the key is looked up takes effect for later
    // operations; this one keeps the revision that admitted its key.
    own_process();
    let plaintext = b"one revision";
    // SAFETY: the library, a document, contexts, keys and a manager set up
    // and released here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(republishing_lookup);
        let ctx = xmlSecEncCtxCreate(mngr);
        let result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
        assert!(!result.is_null(), "decryption kept its revision");
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result)),
            plaintext
        );
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The ciphertext the test's input callbacks serve.
static SERVED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
/// Octets of [`SERVED`] already read.
static SERVED_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn served_matches(_uri: *const std::ffi::c_char) -> std::ffi::c_int {
    1
}

unsafe extern "C" fn served_open(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    SERVED_SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn served_read(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let served = SERVED.lock().expect("one test thread");
    let sent = SERVED_SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &served[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    SERVED_SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn served_close(_context: *mut std::ffi::c_void) -> std::ffi::c_int {
    0
}

/// The reasons reported during [`reported`], in order.
static REASONS: std::sync::Mutex<Vec<std::ffi::c_int>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn record(
    _file: *const std::ffi::c_char,
    _line: std::ffi::c_int,
    func: *const std::ffi::c_char,
    _object: *const std::ffi::c_char,
    _subject: *const std::ffi::c_char,
    reason: std::ffi::c_int,
    message: *const std::ffi::c_char,
) {
    let text = |text: *const std::ffi::c_char| {
        // SAFETY: the library passes null or NUL-terminated strings.
        unsafe { text.as_ref() }.map_or_else(String::new, |_| {
            // SAFETY: as above.
            unsafe { std::ffi::CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned()
        })
    };
    // Shown with a failing assertion's output.
    eprintln!("{}: {reason}: {}", text(func), text(message));
    REASONS.lock().expect("one test thread").push(reason);
}

/// `run`'s result and the reasons reported while it ran.
fn reported<T>(run: impl FnOnce() -> T) -> (T, Vec<std::ffi::c_int>) {
    REASONS.lock().expect("one test thread").clear();
    // SAFETY: the callback has the callback's signature.
    unsafe {
        crate::ffi::errors::xmlSecErrorsSetCallback(Some(
            record as crate::ffi::errors::ErrorsCallback,
        ));
    }
    let result = run();
    // SAFETY: restores the default callback.
    unsafe { crate::ffi::errors::xmlSecErrorsSetCallback(None) };
    (result, REASONS.lock().expect("one test thread").clone())
}

/// The resources [`by_uri_open`] serves, each under the URI it is asked for.
static RESOURCES: std::sync::Mutex<Vec<(&str, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());
/// Resources [`by_uri_open`] opened.
static OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Octets [`by_uri_read`] handed out.
static READ_OCTETS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// An open resource of [`RESOURCES`] and the octets already read.
struct Cursor {
    bytes: Vec<u8>,
    sent: usize,
}

unsafe extern "C" fn by_uri_open(uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    OPENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the transform passes a NUL-terminated URI.
    let uri = unsafe { std::ffi::CStr::from_ptr(uri) }.to_string_lossy();
    RESOURCES
        .lock()
        .expect("one test thread")
        .iter()
        .find(|(name, _)| *name == uri)
        .map_or(std::ptr::null_mut(), |(_, bytes)| {
            Box::into_raw(Box::new(Cursor {
                bytes: bytes.clone(),
                sent: 0,
            }))
            .cast()
        })
}

unsafe extern "C" fn by_uri_read(
    context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    // SAFETY: the cursor `by_uri_open` boxed.
    let cursor = unsafe { &mut *context.cast::<Cursor>() };
    let rest = &cursor.bytes[cursor.sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    cursor.sent += count;
    READ_OCTETS.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn by_uri_close(context: *mut std::ffi::c_void) -> std::ffi::c_int {
    // SAFETY: the cursor `by_uri_open` boxed, closed once.
    drop(unsafe { Box::from_raw(context.cast::<Cursor>()) });
    0
}

/// Registers the callbacks that serve [`RESOURCES`].
///
/// # Safety
/// The library is initialized.
unsafe fn serve_by_uri(resources: Vec<(&'static str, Vec<u8>)>) {
    *RESOURCES.lock().expect("one test thread") = resources;
    OPENS.store(0, std::sync::atomic::Ordering::Relaxed);
    READ_OCTETS.store(0, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: by the caller's contract.
    let registered = unsafe {
        crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
            Some(served_matches),
            Some(by_uri_open),
            Some(by_uri_read),
            Some(by_uri_close),
        )
    };
    assert_eq!(registered, 0);
}

/// Initializes the library and its crypto for one test.
///
/// # Safety
/// Called once, on the test's thread, before [`shut_down`].
unsafe fn start_up() {
    // SAFETY: by the caller's contract.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
    }
}

/// Shuts down what [`start_up`] initialized.
///
/// # Safety
/// After [`start_up`], with every object of the test released.
unsafe fn shut_down() {
    // SAFETY: by the caller's contract.
    unsafe {
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// `plaintext` encrypted with [`aes_key`] by the method `klass`, as the
/// Base64 text of its `CipherValue` and as raw octets.
///
/// # Safety
/// The library is initialized; `klass` is a cipher, wrap or transport klass.
unsafe fn encrypted(
    klass: *const crate::ffi::transforms::XmlSecTransformKlass,
    plaintext: &[u8],
) -> (String, Vec<u8>) {
    // SAFETY: a document, a template and a context created and released
    // here.
    unsafe {
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            klass,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        let cipher_value = xmlSecTmplEncDataEnsureCipherValue(tmpl);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let text = xml_sec_libxml2::ffi::tree::xsNodeGetContent(cipher_value.cast());
        let encoded = std::ffi::CStr::from_ptr(text.cast())
            .to_string_lossy()
            .into_owned();
        let mut size = 0;
        assert_eq!(
            crate::ffi::base64::xmlSecBase64DecodeInPlace(text, &raw mut size),
            0
        );
        let raw = std::slice::from_raw_parts(text, size).to_vec();
        crate::ffi::free(text.cast());
        xsFreeDoc(doc);
        (encoded, raw)
    }
}

/// `xml` parsed.
fn parsed(xml: &str) -> *mut crate::ffi::tree::XmlDoc {
    // SAFETY: the bytes and their length.
    let doc = unsafe {
        xml_sec_libxml2::ffi::tree::xsReadMemory(
            xml.as_ptr().cast(),
            std::ffi::c_int::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!doc.is_null(), "the document parses");
    doc.cast()
}

#[test]
fn an_encrypted_key_reads_its_cipher_reference_under_the_decryption_policy() {
    // An EncryptedKey is decrypted: its CipherReference is opened under the
    // decryption policy's URI classes, not verification's, so a decryption
    // policy refusing external references reads nothing.
    own_process();
    // SAFETY: the library, a document and a context set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        serve_by_uri(vec![("test:wrapped", wrapped)]);
        crate::ffi::policy::republish(
            |verification| verification.uris.references = xml_sec::xmldsig::UriTypeSet::ALL,
            |_| {},
        )
        .expect("the library policy compiles");
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.uris.references = xml_sec::xmldsig::UriTypeSet::SAME_DOCUMENT,
        )
        .expect("the library policy compiles");
        let doc = parsed(concat!(
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
            "</EncryptedKey>"
        ));
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).mode = MODE_ENCRYPTED_KEY;
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.enabled_uris = 0xFFFF;
        let result = xmlSecEncCtxDecryptToBuffer(
            ctx,
            xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
        );
        assert!(result.is_null(), "the decryption policy refuses the URI");
        assert_eq!(
            OPENS.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing was opened"
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn uri_encryption_reads_its_resource_under_the_encryption_policy() {
    // The resource a caller names for encryption is read under the
    // encryption policy's limits: a verification policy refusing external
    // references and allowing one octet does not refuse it, and an
    // encryption limit below its size does.
    own_process();
    let plaintext = b"named by the caller";
    // SAFETY: the library, documents and contexts set up and released here,
    // on this thread alone.
    unsafe {
        start_up();
        serve_by_uri(vec![("test:plain", plaintext.to_vec())]);
        crate::ffi::policy::republish(
            |verification| {
                verification.uris.references = xml_sec::xmldsig::UriTypeSet::SAME_DOCUMENT;
                // The AES key itself is read within these limits.
                verification.resources.max_external_resource_bytes = 16;
                verification.resources.max_external_resource_total_bytes = 16;
            },
            |_| {},
        )
        .expect("the library policy compiles");
        let encrypt = || {
            let doc = xsNewDoc(c"1.0".as_ptr().cast());
            let tmpl = xmlSecTmplEncDataCreate(
                doc,
                aes128_cbc(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            xsDocSetRootElement(doc, tmpl);
            assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).enc_key = aes_key();
            let encrypted = xmlSecEncCtxUriEncrypt(ctx, tmpl, c"test:plain".as_ptr().cast());
            xmlSecEncCtxDestroy(ctx);
            xsFreeDoc(doc);
            encrypted
        };
        assert_eq!(encrypt(), 0, "the encryption policy admits the resource");
        xml_sec_libxml2::policy::republish_encryption(
            |encryption| encryption.resources.max_external_resource_bytes = plaintext.len() - 1,
            |_| {},
        )
        .expect("the library policy compiles");
        let (encrypted, reasons) = reported(encrypt);
        assert_eq!(encrypted, -1, "the encryption limit refuses the resource");
        assert_eq!(
            reasons.first(),
            Some(&crate::ffi::errors::R_INVALID_SIZE),
            "{reasons:?}"
        );
        shut_down();
    }
}

/// A key manager's lookup that hands back [`aes_key`] for an element without
/// a `KeyInfo` and reads the `KeyInfo` of any other.
unsafe extern "C" fn kek_or_read(node: *mut XmlNode, ctx: *mut XmlSecKeyInfoCtx) -> *mut XmlSecKey {
    if node.is_null() {
        return aes_key();
    }
    // SAFETY: the operation's node and read context.
    unsafe { crate::ffi::keysmngr::xmlSecKeysMngrGetKey(node, ctx) }
}

#[test]
fn an_encrypted_key_with_a_cipher_reference_carries_the_content_key() {
    // An EncryptedData whose KeyInfo carries EncryptedKeys with
    // CipherReferences decrypts as with libxmlsec1: the key's read reads the
    // first recipient's resource once and skips the others, the core
    // decrypts with the key it found without needing a skipped recipient's
    // resource, and the reads share the operation's aggregate limit.
    own_process();
    let plaintext = b"under one allowance";
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        let (_, cipher) = encrypted(aes128_cbc(), plaintext);
        let total = wrapped.len() + cipher.len();
        serve_by_uri(vec![("test:wrapped", wrapped), ("test:cipher", cipher)]);
        let doc = parsed(concat!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
            "</EncryptedKey>",
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<CipherData><CipherReference URI=\"test:another-recipient\"/></CipherData>",
            "</EncryptedKey>",
            "</KeyInfo>",
            "<CipherData><CipherReference URI=\"test:cipher\"/></CipherData>",
            "</EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        for (limit, admitted) in [(total - 1, false), (total, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_external_resource_total_bytes = limit,
            )
            .expect("the library policy compiles");
            OPENS.store(0, std::sync::atomic::Ordering::Relaxed);
            let ctx = xmlSecEncCtxCreate(mngr);
            (*ctx).transform_ctx.enabled_uris = 0xFFFF;
            // The EncryptedKey's context takes the caller's URI settings.
            let read = &raw mut (*ctx).key_info_read_ctx;
            assert_eq!(encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(read), 0);
            (*(*read).enc_ctx.cast::<XmlSecEncCtx>())
                .transform_ctx
                .enabled_uris = 0xFFFF;
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            if admitted {
                assert!(!result.is_null(), "both reads fit in {limit}: {reasons:?}");
                assert_eq!(
                    std::slice::from_raw_parts(
                        xmlSecBufferGetData(result),
                        xmlSecBufferGetSize(result)
                    ),
                    plaintext
                );
                assert_eq!(
                    OPENS.load(std::sync::atomic::Ordering::Relaxed),
                    2,
                    "each resource was read once"
                );
            } else {
                assert!(result.is_null(), "the reads passed the limit {limit}");
                assert_eq!(
                    reasons.first(),
                    Some(&crate::ffi::errors::R_INVALID_SIZE),
                    "{reasons:?}"
                );
            }
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn an_encrypted_key_veto_comes_before_its_resource_is_read() {
    // A pre-execute callback refusing an EncryptedKey's chain runs before
    // its CipherReference is read, as libxmlsec1 runs it before pumping the
    // resource: no octet reaches the operation.
    own_process();
    // SAFETY: the library, a document and a context set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        serve_by_uri(vec![("test:wrapped", wrapped)]);
        let doc = parsed(concat!(
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
            "</EncryptedKey>"
        ));
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).mode = MODE_ENCRYPTED_KEY;
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.enabled_uris = 0xFFFF;
        (*ctx).transform_ctx.pre_exec_callback = Some(veto);
        let result = xmlSecEncCtxDecryptToBuffer(
            ctx,
            xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
        );
        assert!(result.is_null(), "the veto refuses the chain");
        assert_eq!(
            VETOES.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the refusal is the veto's"
        );
        assert_eq!(
            READ_OCTETS.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing was read"
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_recipient_past_the_resource_limit_ends_the_key_read() {
    // A recipient whose CipherReference passes a resource limit spends the
    // operation's budget: the key read ends there instead of trying the next
    // recipient under the same allowance, as the core ends an operation whose
    // budget is spent.
    own_process();
    let plaintext = b"one budget";
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let limit = wrapped.len();
        serve_by_uri(vec![
            ("test:oversized", vec![0; limit + 1]),
            ("test:wrapped", wrapped),
        ]);
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.resources.max_external_resource_bytes = limit,
        )
        .expect("the library policy compiles");
        let doc = parsed(&format!(
            "{}{}{}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherReference URI=\"test:oversized\"/></CipherData>",
                "</EncryptedKey>",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
                "</EncryptedKey>",
                "</KeyInfo>",
            ),
            "<CipherData><CipherValue>",
            cipher,
            "</CipherValue></CipherData></EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        let ctx = xmlSecEncCtxCreate(mngr);
        let read = &raw mut (*ctx).key_info_read_ctx;
        assert_eq!(encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(read), 0);
        (*(*read).enc_ctx.cast::<XmlSecEncCtx>())
            .transform_ctx
            .enabled_uris = 0xFFFF;
        let (result, reasons) = reported(|| {
            xmlSecEncCtxDecryptToBuffer(
                ctx,
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
            )
        });
        assert!(result.is_null(), "the spent budget ends the operation");
        // The oversized resource is no valid wrap either: the limit, not the
        // unwrap, refused it.
        assert_eq!(
            reasons.first(),
            Some(&crate::ffi::errors::R_INVALID_SIZE),
            "{reasons:?}"
        );
        assert_eq!(
            OPENS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the next recipient was not tried"
        );
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn a_rejected_key_recovery_fails_the_decryption_after_its_content_work() {
    // A key recovered by RSAES-PKCS1-v1_5 may be the random substitute of a
    // rejected recovery; even when content decryption succeeds with it, the
    // operation fails once its content work is done.
    own_process();
    let plaintext = b"decrypted with a substitute";
    // SAFETY: the library, a document, contexts and keys set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let doc = parsed(&format!(
            "{}{cipher}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedData>"
        ));
        let (_, rejected) = xml_sec::provider::RecoveredContentKey::recovery(
            zeroize::Zeroizing::new(vec![0; 16]),
            subtle::Choice::from(0),
        )
        .into_key_with_validity()
        .expect("an exportable recovery");
        for (validity, decrypts) in [
            (xml_sec::provider::RecoveryValidity::accepted(), true),
            (rejected, false),
        ] {
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).enc_key = aes_key();
            crate::ffi::transforms::ctx::run_budget(&raw mut (*ctx).transform_ctx).recovery =
                validity;
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            assert_eq!(!result.is_null(), decrypts, "{reasons:?}");
            xmlSecEncCtxDestroy(ctx);
        }
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_wrapped_key_is_recovered_on_the_signing_side() {
    // An EncryptedKey that already carries its ciphertext is a transported
    // key to recover, whatever operation reads it: a signer reusing the
    // session key a request carried gets that key, not the wrap of its
    // ciphertext text.
    own_process();
    let secret = [0x7e_u8; 32];
    // SAFETY: the library, a document, keys, a manager and a context set up
    // and released here, on this thread alone.
    unsafe {
        start_up();
        let (wrapped, _) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &secret);
        let doc = parsed(&format!(
            "{}{wrapped}{}",
            concat!(
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedKey></KeyInfo>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(mngr);
        (*read).operation = crate::ffi::transforms::OPERATION_SIGN;
        (*read).key_req.key_id = symkeys::hmac();
        let key = xmlSecKeyCreate();
        let (status, reasons) = reported(|| {
            crate::ffi::keyinfo::xmlSecKeyInfoNodeRead(
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                key,
                read,
            )
        });
        assert_eq!(status, 0, "{reasons:?}");
        let value = crate::ffi::keys::xmlSecKeyGetValue(key);
        assert!(!value.is_null(), "a key was recovered: {reasons:?}");
        let buffer = crate::ffi::keysdata::xmlSecKeyDataBinaryValueGetBuffer(value);
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer)),
            secret,
            "the transported key, not the wrap of its ciphertext"
        );
        crate::ffi::keys::xmlSecKeyDestroy(key);
        crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn a_failed_recipient_leaves_no_rejected_recovery_behind() {
    // Work counts are shared by every recipient a key read tries, but a
    // recovery's validity belongs to the key it yields: a recipient that
    // fails (a wrap unlocked by a rejected PKCS #1 v1.5 recovery), or that
    // returns without installing a key as libxmlsec1 does by default, does
    // not fail the decryption a later recipient's key serves; one that
    // installs its substitute keeps the rejection.
    own_process();
    let (_, rejected) = xml_sec::provider::RecoveredContentKey::recovery(
        zeroize::Zeroizing::new(vec![0; 16]),
        subtle::Choice::from(0),
    )
    .into_key_with_validity()
    .expect("an exportable recovery");
    // SAFETY: the library and contexts set up and released here, on this
    // thread alone.
    unsafe {
        start_up();
        for (done, installs, valid) in [(-1, false, true), (0, false, true), (0, true, false)] {
            let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
            (*read).operation = crate::ffi::transforms::OPERATION_DECRYPT;
            let pin = crate::ffi::policy::SlotPin::hold(
                &raw mut (*read).reserved0,
                crate::ffi::errors::here!("test"),
            )
            .expect("a revision is published");
            assert_eq!(super::encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(read), 0);
            let enc = (*read).enc_ctx.cast::<XmlSecEncCtx>();
            super::encrypted_key::within_key_info(
                read,
                enc,
                || {
                    crate::ffi::transforms::ctx::run_budget(&raw mut (*enc).transform_ctx)
                        .recovery = rejected;
                    done
                },
                || installs,
            );
            let spent = crate::ffi::policy::spent((*read).reserved0)
                .expect("the read is pinned")
                .get();
            assert_eq!(
                spent.recovery.is_valid(),
                valid,
                "a recipient returning {done}, installing a key: {installs}"
            );
            drop(pin);
            crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        }
        shut_down();
    }
}

#[test]
fn no_resource_is_read_once_a_limit_refused_a_read_of_the_operation() {
    // A refusal by a resource limit spends the operation's budget wherever
    // it happened, a key lookup's nested read included: a later read of the
    // same operation is refused before it opens anything.
    own_process();
    // SAFETY: the library, a document and a context set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        serve_by_uri(vec![("test:content", vec![0; 32])]);
        let pinned = crate::ffi::policy::Pinned::current(crate::ffi::errors::here!("test"))
            .expect("a revision is published");
        let doc = parsed("<root/>");
        let refused = crate::ffi::policy::Spent {
            limit_reached: true,
            ..crate::ffi::policy::Spent::default()
        };
        let prefs = crate::ffi::transforms::ctx::xmlSecTransformCtxCreate();
        (*prefs).enabled_uris = 0xFFFF;
        let mut scope = crate::ffi::transforms::ctx::ResourceScope::new(
            &pinned,
            crate::ffi::policy::Side::Decrypt,
            refused,
        );
        let (read, _) = reported(|| {
            crate::ffi::transforms::ctx::read_resource(
                prefs,
                b"test:content",
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                doc.cast(),
                &mut scope,
            )
        });
        assert!(read.is_none());
        assert!(scope.limit_reached, "the refusal stays the operation's");
        assert_eq!(
            OPENS.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing was opened"
        );
        crate::ffi::transforms::ctx::xmlSecTransformCtxDestroy(prefs);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_recovered_key_is_bounded_by_the_decryption_depth() {
    // A carried EncryptedKey is recovered under the decryption policy even
    // on the signing side, so that policy's key reference depth bounds it,
    // not the depth of the operation that reads it.
    own_process();
    let secret = [0x7e_u8; 32];
    // SAFETY: the library, a document, keys, a manager and contexts set up
    // and released here, on this thread alone.
    unsafe {
        start_up();
        let (wrapped, _) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &secret);
        let doc = parsed(&format!(
            "{}{wrapped}{}",
            concat!(
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedKey></KeyInfo>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        // Depth 0 refuses the key with the depth diagnostic; depth 1, the
        // control, recovers it from the same document.
        for (depth, recovered) in [(0, false), (1, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_key_info_reference_depth = depth,
            )
            .expect("the library policy compiles");
            let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(mngr);
            (*read).operation = crate::ffi::transforms::OPERATION_SIGN;
            (*read).key_req.key_id = symkeys::hmac();
            let key = xmlSecKeyCreate();
            let (_, reasons) = reported(|| {
                crate::ffi::keyinfo::xmlSecKeyInfoNodeRead(
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                    key,
                    read,
                )
            });
            let value = crate::ffi::keys::xmlSecKeyGetValue(key);
            assert_eq!(!value.is_null(), recovered, "depth {depth}: {reasons:?}");
            if recovered {
                let buffer = crate::ffi::keysdata::xmlSecKeyDataBinaryValueGetBuffer(value);
                assert_eq!(
                    std::slice::from_raw_parts(
                        xmlSecBufferGetData(buffer),
                        xmlSecBufferGetSize(buffer)
                    ),
                    secret
                );
            } else {
                assert!(
                    reasons.contains(&crate::ffi::errors::R_INVALID_SIZE),
                    "the depth limit refused the read: {reasons:?}"
                );
            }
            crate::ffi::keys::xmlSecKeyDestroy(key);
            crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_nested_recipient_past_the_resource_limit_ends_the_key_read() {
    // The EncryptedKey in a recipient's KeyInfo is a part of the same key
    // read: its CipherReference passing a resource limit spends the
    // operation's budget, so the read ends there rather than taking the
    // enclosing recipient for a miss and trying the next one.
    own_process();
    let plaintext = b"one budget, nested";
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let limit = wrapped.len();
        serve_by_uri(vec![
            ("test:oversized", vec![0; limit + 1]),
            ("test:wrapped", wrapped),
        ]);
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.resources.max_external_resource_bytes = limit,
        )
        .expect("the library policy compiles");
        let doc = parsed(&format!(
            "{}{}{}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherReference URI=\"test:oversized\"/></CipherData>",
                "</EncryptedKey>",
                "</KeyInfo>",
                "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
                "</EncryptedKey>",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherReference URI=\"test:wrapped\"/></CipherData>",
                "</EncryptedKey>",
                "</KeyInfo>",
            ),
            "<CipherData><CipherValue>",
            cipher,
            "</CipherValue></CipherData></EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        let ctx = xmlSecEncCtxCreate(mngr);
        let read = &raw mut (*ctx).key_info_read_ctx;
        // The recipient and the EncryptedKey in its KeyInfo are two levels.
        (*read).max_encrypted_key_level = 2;
        assert_eq!(encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(read), 0);
        let recipient = (*read).enc_ctx.cast::<XmlSecEncCtx>();
        (*recipient).transform_ctx.enabled_uris = 0xFFFF;
        // The EncryptedKey in the recipient's KeyInfo takes the same URIs.
        let nested_read = &raw mut (*recipient).key_info_read_ctx;
        assert_eq!(encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(nested_read), 0);
        (*(*nested_read).enc_ctx.cast::<XmlSecEncCtx>())
            .transform_ctx
            .enabled_uris = 0xFFFF;
        let (result, reasons) = reported(|| {
            xmlSecEncCtxDecryptToBuffer(
                ctx,
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
            )
        });
        assert!(
            result.is_null(),
            "the spent budget ends the operation: {reasons:?}"
        );
        assert_eq!(
            reasons.first(),
            Some(&crate::ffi::errors::R_INVALID_SIZE),
            "{reasons:?}"
        );
        assert_eq!(
            OPENS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "neither the enclosing recipient's nor the next recipient's resource was opened"
        );
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn nested_encrypted_keys_share_the_base64_allowance() {
    // The Base64 output limit is cumulative per operation: the CipherValues
    // of an EncryptedKey and of the EncryptedKey in its KeyInfo decode
    // within one allowance, not one each.
    own_process();
    let content_key = [0x5a_u8; 16];
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (value, wrapped) =
            encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &content_key);
        let total = 2 * wrapped.len();
        let doc = parsed(&format!(
            "{}{value}{}{value}{}",
            concat!(
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedKey></KeyInfo><CipherData><CipherValue>",
            "</CipherValue></CipherData></EncryptedKey>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        for (limit, admitted) in [(total - 1, false), (total, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_base64_transform_output_bytes = limit,
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(mngr);
            (*ctx).mode = MODE_ENCRYPTED_KEY;
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            assert_eq!(
                !result.is_null(),
                admitted,
                "{total} octets decoded under {limit}: {reasons:?}"
            );
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_key_read_past_the_operations_limit_fails_the_decryption() {
    // What the key read spent is checked against the decryption's own
    // aggregate limit even when the decryption reads nothing more: an
    // EncryptedData with a CipherValue cannot hide a key read past it.
    own_process();
    let plaintext = b"read inline";
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let doc = parsed(&format!(
            "{}{cipher}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(charging_lookup);
        for (limit, admitted) in [(KEY_READ_OCTETS - 1, false), (KEY_READ_OCTETS, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_external_resource_total_bytes = limit,
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(mngr);
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            assert_eq!(
                !result.is_null(),
                admitted,
                "a key read of {KEY_READ_OCTETS} under {limit}: {reasons:?}"
            );
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

/// A key manager's lookup that republishes an encryption policy admitting
/// no key wrap while it answers, then hands back [`aes_key`].
unsafe extern "C" fn wrap_refusing_lookup(
    _node: *mut XmlNode,
    _ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    xml_sec_libxml2::policy::republish_encryption(
        |encryption| encryption.key_wrap_algorithms = Some(std::collections::BTreeSet::new()),
        |_| {},
    )
    .expect("the library policy compiles");
    aes_key()
}

#[test]
fn an_encrypted_key_is_written_under_the_operations_revision() {
    // The EncryptedKey an encryption writes into its KeyInfo is a part of
    // that encryption: a republish while its key is looked up takes effect
    // for later operations, not for the wrap this one writes. The first
    // encryption writes the wrapped key; the next one, under the revision
    // admitting no key wrap, refuses the same wrap.
    own_process();
    // SAFETY: the library, documents, contexts, keys and a manager set up
    // and released here, on this thread alone.
    unsafe {
        start_up();
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(wrap_refusing_lookup);
        for (revision, wrapped) in [("the first", true), ("the next", false)] {
            let doc = xsNewDoc(c"1.0".as_ptr().cast());
            let tmpl = xmlSecTmplEncDataCreate(
                doc,
                aes128_cbc(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            xsDocSetRootElement(doc, tmpl);
            assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
            let key_info =
                crate::ffi::templates::xmlSecTmplEncDataEnsureKeyInfo(tmpl, std::ptr::null());
            let encrypted_key = crate::ffi::templates::xmlSecTmplKeyInfoAddEncryptedKey(
                key_info,
                crate::ffi::transforms::ciphers::kw_aes128(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            let wrapped_value = xmlSecTmplEncDataEnsureCipherValue(encrypted_key);
            assert!(!wrapped_value.is_null());
            let ctx = xmlSecEncCtxCreate(mngr);
            let content = b"wrapped under its own revision";
            let (encrypted, reasons) =
                reported(|| xmlSecEncCtxBinaryEncrypt(ctx, tmpl, content.as_ptr(), content.len()));
            assert_eq!(
                encrypted == 0,
                wrapped,
                "{revision} encryption: {reasons:?}"
            );
            if wrapped {
                assert!(
                    crate::ffi::xmltree::trimmed_content(wrapped_value)
                        .is_some_and(|value| !value.is_empty()),
                    "the wrapped key was written"
                );
            }
            xmlSecEncCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        xmlSecKeysMngrDestroy(mngr);
        shut_down();
    }
}

#[test]
fn an_encrypted_key_method_is_admitted_as_a_key_wrap() {
    // An EncryptedKey's method carries a key, so the policy admits it as a
    // key transport or key wrap, as the core does: the libxmlsec1-compatible
    // library profile lists the CBC key wraps libxmlsec1 accepts, and a
    // policy listing none refuses the key whatever content it may decrypt.
    own_process();
    // SAFETY: the library, a document and contexts set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        let (value, _) = encrypted(aes128_cbc(), &[0x5a; 16]);
        let doc = parsed(&format!(
            "{}{value}{}",
            concat!(
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedKey>"
        ));
        let recovered = || {
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).mode = MODE_ENCRYPTED_KEY;
            (*ctx).enc_key = aes_key();
            let result = xmlSecEncCtxDecryptToBuffer(
                ctx,
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
            );
            let recovered = !result.is_null()
                && std::slice::from_raw_parts(
                    xmlSecBufferGetData(result),
                    xmlSecBufferGetSize(result),
                ) == [0x5a; 16];
            xmlSecEncCtxDestroy(ctx);
            recovered
        };
        assert!(recovered(), "the compatible profile admits a CBC key wrap");
        // The CBC key wrap alone decides: content limited to AES-GCM does not
        // refuse the cipher that wraps the key.
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| {
                decryption.key_wrap_algorithms = Some(std::collections::BTreeSet::from([
                    xml_sec::xmlenc::KeyWrapAlgorithm::Cbc(DataEncryptionAlgorithm::Aes128Cbc),
                ]));
                decryption.data_algorithms = Some(std::collections::BTreeSet::from([
                    DataEncryptionAlgorithm::Aes128Gcm,
                ]));
            },
        )
        .expect("the library policy compiles");
        assert!(
            recovered(),
            "a CBC key wrap is admitted as a key wrap, not as content"
        );
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| {
                decryption.key_wrap_algorithms = Some(std::collections::BTreeSet::new());
                decryption.key_transport_algorithms = Some(std::collections::BTreeSet::new());
            },
        )
        .expect("the library policy compiles");
        assert!(
            !recovered(),
            "no key is recovered without a key-wrap permission"
        );
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn decrypted_xml_is_parsed_under_the_decryption_policy() {
    // The plaintext an Element EncryptedData is replaced with is parsed
    // under the decryption's own XML limits, not the verification policy's:
    // a decryption allowing less depth refuses a deeper plaintext and leaves
    // the document as it was.
    own_process();
    let plaintext = b"<a><b><c><d><e><f><g><h><i><j/></i></h></g></f></e></d></c></b></a>";
    // SAFETY: the library, a document and contexts set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            c"http://www.w3.org/2001/04/xmlenc#Element".as_ptr().cast(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.resources.max_xml_depth = 4,
        )
        .expect("the library policy compiles");
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxDecrypt(ctx, tmpl),
            -1,
            "the plaintext is too deep"
        );
        assert_eq!(
            xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc),
            tmpl,
            "the EncryptedData stays"
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        shut_down();
    }
}

#[test]
fn an_element_using_a_declared_entity_survives_encryption() {
    // libxmlsec1 encrypts an element as xmlNodeDumpOutput writes it, so an
    // entity the document declares stays a reference in the plaintext; the
    // replacement is then parsed in the document's context, its internal
    // subset included, as xmlParseInNodeContext parses it.
    own_process();
    // SAFETY: the library, a document and contexts set up and released
    // here, on this thread alone.
    unsafe {
        start_up();
        // A deployment that admits internal DTDs for the documents it reads
        // and the plaintexts it decrypts.
        crate::ffi::policy::republish(
            |verification| verification.xml.allow_internal_dtd = true,
            |_| {},
        )
        .expect("the library policy compiles");
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.xml.allow_internal_dtd = true,
        )
        .expect("the library policy compiles");
        let doc = parsed(concat!(
            "<!DOCTYPE root [<!ENTITY label \"declared text\">]>",
            "<root><item>&label; and more</item></root>"
        ));
        let root = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast());
        let item = xml_sec_libxml2::ffi::tree::xsNodeGetChildren(root);
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            c"http://www.w3.org/2001/04/xmlenc#Element".as_ptr().cast(),
            std::ptr::null(),
            std::ptr::null(),
        );
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(xmlSecEncCtxXmlEncrypt(ctx, tmpl, item.cast()), 0);
        xmlSecEncCtxDestroy(ctx);
        let encrypted = xml_sec_libxml2::ffi::tree::xsNodeGetChildren(root);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(xmlSecEncCtxDecrypt(ctx, encrypted.cast()), 0);
        xmlSecEncCtxDestroy(ctx);
        let restored = xml_sec_libxml2::ffi::tree::xsNodeGetChildren(root);
        let content = xml_sec_libxml2::ffi::tree::xsNodeGetContent(restored);
        assert_eq!(
            std::ffi::CStr::from_ptr(content.cast()).to_str(),
            Ok("declared text and more")
        );
        crate::ffi::free(content.cast());
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn decrypted_xml_is_parsed_within_the_decryptions_parse_work() {
    // Parsing the plaintext is XML parse work of the decryption: a
    // decryption whose max_xml_parse_work_bytes is less than the plaintext
    // refuses it and leaves the document as it was.
    own_process();
    let plaintext = b"<plaintext><of>the decryption</of></plaintext>";
    // SAFETY: the library, documents and contexts set up and released here,
    // on this thread alone.
    unsafe {
        start_up();
        for (limit, replaced) in [(plaintext.len() - 1, false), (16 * plaintext.len(), true)] {
            let doc = xsNewDoc(c"1.0".as_ptr().cast());
            let tmpl = xmlSecTmplEncDataCreate(
                doc,
                aes128_cbc(),
                std::ptr::null(),
                c"http://www.w3.org/2001/04/xmlenc#Element".as_ptr().cast(),
                std::ptr::null(),
                std::ptr::null(),
            );
            xsDocSetRootElement(doc, tmpl);
            assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).enc_key = aes_key();
            assert_eq!(
                xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
                0
            );
            xmlSecEncCtxDestroy(ctx);
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_xml_parse_work_bytes = limit,
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).enc_key = aes_key();
            let (result, reasons) = reported(|| xmlSecEncCtxDecrypt(ctx, tmpl));
            assert_eq!(
                result == 0,
                replaced,
                "a plaintext of {} octets under {limit}: {reasons:?}",
                plaintext.len()
            );
            assert_eq!(
                xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc) == tmpl,
                !replaced,
                "the EncryptedData stays only when the plaintext is refused"
            );
            xmlSecEncCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        shut_down();
    }
}

#[test]
fn the_plaintext_parse_counts_on_from_the_cores_parse_work() {
    // A CipherReference whose transforms parse an external document spends
    // parse work inside the core's decryption; replacing the element with
    // its plaintext parses more within the same max_xml_parse_work_bytes.
    // The smallest allowance a decryption to a buffer fits in leaves nothing
    // for the replacement.
    own_process();
    let plaintext = b"<plaintext><of>the decryption</of></plaintext>";
    // SAFETY: the library, documents and contexts set up and released here,
    // on this thread alone.
    unsafe {
        start_up();
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let resource = format!("<d><!--{}-->{cipher}</d>", "padding ".repeat(64));
        serve_by_uri(vec![("test:doc", resource.into_bytes())]);
        let document = concat!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"",
            " Type=\"http://www.w3.org/2001/04/xmlenc#Element\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
            "<CipherData><CipherReference URI=\"test:doc\"><Transforms>",
            "<ds:Transform xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            " Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">",
            "<ds:XPath>self::text()</ds:XPath></ds:Transform>",
            "<ds:Transform xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            " Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"/>",
            "</Transforms></CipherReference></CipherData></EncryptedData>"
        );
        // Whether the decryption under `limit` succeeds, replacing the
        // element when `replace`.
        let decrypts = |limit: usize, replace: bool| {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_xml_parse_work_bytes = limit,
            )
            .expect("the library policy compiles");
            let doc = parsed(document);
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            (*ctx).enc_key = aes_key();
            (*ctx).transform_ctx.enabled_uris = 0xFFFF;
            let root = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast());
            let done = if replace {
                xmlSecEncCtxDecrypt(ctx, root) == 0
            } else {
                !xmlSecEncCtxDecryptToBuffer(ctx, root).is_null()
            };
            xmlSecEncCtxDestroy(ctx);
            xsFreeDoc(doc.cast());
            done
        };
        let (mut low, mut high) = (0, 1 << 20);
        assert!(
            decrypts(high, false),
            "the decryption fits a generous limit"
        );
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if decrypts(middle, false) {
                high = middle;
            } else {
                low = middle;
            }
        }
        assert!(
            !decrypts(high, true),
            "the plaintext parse is past the {high} octets the core's work fits in"
        );
        assert!(
            decrypts(high + 4 * plaintext.len() + 64, true),
            "with room for the plaintext the replacement succeeds"
        );
        shut_down();
    }
}

/// Wrapping keys [`inspecting_lookup`] handed out so far.
static INSPECTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A key manager's lookup that, for an `EncryptedKey` without a `KeyInfo`,
/// inspects one stored wrapping key as a key-store search does, charging the
/// read's candidate allowance: a wrong key first, [`aes_key`] after; any
/// other `KeyInfo` it reads.
unsafe extern "C" fn inspecting_lookup(
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    if !node.is_null() {
        // SAFETY: the operation's node and read context.
        return unsafe { crate::ffi::keysmngr::xmlSecKeysMngrGetKey(node, ctx) };
    }
    // SAFETY: the read context the operation passes.
    let charged = unsafe {
        crate::ffi::keyinfo::charge_candidate(
            ctx,
            crate::ffi::errors::here!("inspecting_lookup"),
            std::ptr::null(),
        )
    };
    if !charged {
        return std::ptr::null_mut();
    }
    if INSPECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
        aes_key_of([0x11; 16])
    } else {
        aes_key()
    }
}

/// An `EncryptedData` whose `KeyInfo` holds two `EncryptedKey` recipients,
/// each its content key wrapped under [`aes_key`].
///
/// # Safety
/// The library is started.
unsafe fn two_recipients(plaintext: &[u8]) -> *mut crate::ffi::tree::XmlDoc {
    // SAFETY: by the caller's contract.
    unsafe {
        let (wrapped, _) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &[0x5a; 16]);
        let (cipher, _) = encrypted(aes128_cbc(), plaintext);
        let recipient = format!(
            "{}{wrapped}{}",
            concat!(
                "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
                "<CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedKey>"
        );
        parsed(&format!(
            "{}{recipient}{recipient}{}{cipher}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            ),
            "</KeyInfo><CipherData><CipherValue>",
            "</CipherValue></CipherData></EncryptedData>"
        ))
    }
}

#[test]
fn a_decryption_inspects_no_more_candidates_than_its_own_policy_allows() {
    // The KeyInfo read of a decryption is a part of it: with the read's own
    // limit at 64 and the decryption's at one, a wrong stored key followed by
    // the right one is past the decryption's allowance.
    own_process();
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        use crate::ffi::keys::xmlSecKeySetName;
        use crate::ffi::keysmngr::{
            xmlSecKeyStoreCreate, xmlSecKeysMngrAdoptKeysStore, xmlSecKeysMngrGetKey,
            xmlSecSimpleKeysStoreAdoptKey, xmlSecSimpleKeysStoreGetKlass,
        };
        start_up();
        // One recipient, named: the core sees one key, while the store search
        // that finds it inspects the wrong key stored first and then this one.
        let (cipher, _) = encrypted(aes128_cbc(), b"the decryption's own allowance");
        let doc = parsed(&format!(
            "{}{cipher}{}",
            concat!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
                "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
                "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>k</KeyName>",
                "</KeyInfo><CipherData><CipherValue>",
            ),
            "</CipherValue></CipherData></EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        let store = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreGetKlass());
        assert_eq!(xmlSecKeysMngrAdoptKeysStore(mngr, store), 0);
        for (name, key) in [(c"other", aes_key_of([0x11; 16])), (c"k", aes_key())] {
            assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
            assert_eq!(xmlSecSimpleKeysStoreAdoptKey(store, key), 0);
        }
        (*mngr).get_key = Some(xmlSecKeysMngrGetKey);
        crate::ffi::policy::republish(
            |verification| verification.resources.max_key_candidates = 64,
            |_| {},
        )
        .expect("the library policy compiles");
        for (limit, admitted) in [(1, false), (2, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_key_candidates = limit,
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(mngr);
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            assert_eq!(
                !result.is_null(),
                admitted,
                "two inspected keys under a decryption limit of {limit}: {reasons:?}"
            );
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn encrypted_key_recipients_share_the_candidate_allowance() {
    // The key candidates every recipient's lookup inspects belong to one
    // KeyInfo read: a recipient whose key fails does not hand the next one a
    // fresh allowance.
    own_process();
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let doc = two_recipients(b"one candidate allowance");
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(inspecting_lookup);
        for (limit, admitted) in [(1, false), (2, true)] {
            crate::ffi::policy::republish(
                |verification| verification.resources.max_key_candidates = limit,
                |_| {},
            )
            .expect("the library policy compiles");
            INSPECTED.store(0, std::sync::atomic::Ordering::Relaxed);
            let ctx = xmlSecEncCtxCreate(mngr);
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            assert_eq!(
                !result.is_null(),
                admitted,
                "two inspected keys under {limit}: {reasons:?}"
            );
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_nested_encrypted_key_shares_the_operations_allowance() {
    // The EncryptedKey in the KeyInfo of another is a part of the decryption
    // that reads it: the octets its CipherReference reads count against the
    // aggregate limit the outer EncryptedKey's CipherReference is read within.
    own_process();
    let content_key = [0x5a_u8; 16];
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        // Both keys are the content key wrapped under itself.
        let (_, wrapped) = encrypted(crate::ffi::transforms::ciphers::kw_aes128(), &content_key);
        let total = 2 * wrapped.len();
        serve_by_uri(vec![
            ("test:inner", wrapped.clone()),
            ("test:outer", wrapped),
        ]);
        let doc = parsed(concat!(
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>",
            "<CipherData><CipherReference URI=\"test:inner\"/></CipherData>",
            "</EncryptedKey>",
            "</KeyInfo>",
            "<CipherData><CipherReference URI=\"test:outer\"/></CipherData>",
            "</EncryptedKey>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(kek_or_read);
        for (limit, admitted) in [(total - 1, false), (total, true)] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| decryption.resources.max_external_resource_total_bytes = limit,
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(mngr);
            (*ctx).mode = MODE_ENCRYPTED_KEY;
            (*ctx).transform_ctx.enabled_uris = 0xFFFF;
            // The inner EncryptedKey's context takes the caller's URI settings.
            let read = &raw mut (*ctx).key_info_read_ctx;
            assert_eq!(encrypted_key::xmlSecKeyInfoCtxCreateEncCtx(read), 0);
            (*(*read).enc_ctx.cast::<XmlSecEncCtx>())
                .transform_ctx
                .enabled_uris = 0xFFFF;
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            if admitted {
                assert!(!result.is_null(), "both reads fit in {limit}: {reasons:?}");
                assert_eq!(
                    std::slice::from_raw_parts(
                        xmlSecBufferGetData(result),
                        xmlSecBufferGetSize(result)
                    ),
                    content_key
                );
            } else {
                assert!(result.is_null(), "the reads passed the limit {limit}");
                assert_eq!(
                    reasons.first(),
                    Some(&crate::ffi::errors::R_INVALID_SIZE),
                    "{reasons:?}"
                );
            }
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

#[test]
fn a_cipher_reference_is_found_under_the_uri_the_core_resolves() {
    // `test:dir/../cipher` resolves to `test:cipher` (RFC 3986 section
    // 5.2.2): the callback is asked for the URI as written, as libxmlsec1
    // asks, and the core finds the octets under the resolved one.
    own_process();
    let plaintext = b"referenced ciphertext";
    // SAFETY: the library, documents, contexts and keys set up and released
    // here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        assert_eq!(
            crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
                Some(served_matches),
                Some(served_open),
                Some(served_read),
                Some(served_close),
            ),
            0
        );
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        let cipher_value = xmlSecTmplEncDataEnsureCipherValue(tmpl);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let text = xml_sec_libxml2::ffi::tree::xsNodeGetContent(cipher_value.cast());
        let mut size = 0;
        assert_eq!(
            crate::ffi::base64::xmlSecBase64DecodeInPlace(text, &raw mut size),
            0,
            "the cipher value decodes"
        );
        *SERVED.lock().expect("one test thread") = std::slice::from_raw_parts(text, size).to_vec();
        crate::ffi::free(text.cast());
        xsFreeDoc(doc);

        let referenced = concat!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
            "<CipherData><CipherReference URI=\"test:dir/../cipher\"/></CipherData>",
            "</EncryptedData>"
        );
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            referenced.as_ptr().cast(),
            std::ffi::c_int::try_from(referenced.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.enabled_uris = 0xFFFF;
        let result =
            xmlSecEncCtxDecryptToBuffer(ctx, xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc));
        assert!(!result.is_null(), "the referenced ciphertext was found");
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result)),
            plaintext
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// Octets a key lookup charges as read from an external key reference.
const KEY_READ_OCTETS: usize = 16;

/// A key manager's lookup that charges [`KEY_READ_OCTETS`] to the
/// operation's external-resource allowance, as a `KeyInfo` read dereferencing
/// an external key reference does, and hands back the AES key.
unsafe extern "C" fn charging_lookup(
    _node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    // SAFETY: the read context the operation passes.
    if let Some(spent) = unsafe { crate::ffi::policy::spent((*ctx).reserved0) } {
        spent.set(crate::ffi::policy::Spent {
            external_resources: KEY_READ_OCTETS,
            ..crate::ffi::policy::Spent::default()
        });
    }
    aes_key()
}

#[test]
fn a_key_read_and_the_cipher_reference_share_one_allowance() {
    // The KeyInfo read and the CipherReference belong to one decryption:
    // what the key read spent counts against the CipherReference read, so
    // the two together cannot pass the aggregate limit.
    own_process();
    let plaintext = b"referenced ciphertext";
    // SAFETY: the library, documents, contexts, keys and a manager set up and
    // released here, on this thread alone.
    unsafe {
        start_up();
        let (_, cipher) = encrypted(aes128_cbc(), plaintext);
        let size = cipher.len();
        serve_by_uri(vec![("test:cipher", cipher)]);
        let doc = parsed(concat!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
            "<CipherData><CipherReference URI=\"test:cipher\"/></CipherData>",
            "</EncryptedData>"
        ));
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(charging_lookup);
        // Below the key read alone, one octet short of both reads, and both.
        for (total, admitted) in [
            (KEY_READ_OCTETS - 1, false),
            (KEY_READ_OCTETS + size - 1, false),
            (KEY_READ_OCTETS + size, true),
        ] {
            xml_sec_libxml2::policy::republish_encryption(
                |_| {},
                |decryption| {
                    decryption.resources.max_external_resource_bytes = size;
                    decryption.resources.max_external_resource_total_bytes = total;
                },
            )
            .expect("the library policy compiles");
            let ctx = xmlSecEncCtxCreate(mngr);
            (*ctx).transform_ctx.enabled_uris = 0xFFFF;
            let (result, reasons) = reported(|| {
                xmlSecEncCtxDecryptToBuffer(
                    ctx,
                    xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc.cast()),
                )
            });
            if admitted {
                assert!(!result.is_null(), "both reads fit in {total}: {reasons:?}");
                assert_eq!(
                    std::slice::from_raw_parts(
                        xmlSecBufferGetData(result),
                        xmlSecBufferGetSize(result)
                    ),
                    plaintext
                );
            } else {
                assert!(result.is_null(), "the reads passed the limit {total}");
                assert_eq!(
                    reasons.first(),
                    Some(&crate::ffi::errors::R_INVALID_SIZE),
                    "the aggregate limit refused the read: {reasons:?}"
                );
            }
            xmlSecEncCtxDestroy(ctx);
        }
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        shut_down();
    }
}

/// Chains [`veto`] refused so far.
static VETOES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A pre-execute callback that refuses every chain, counting each.
unsafe extern "C" fn veto(
    _ctx: *mut crate::ffi::transforms::XmlSecTransformCtx,
) -> std::ffi::c_int {
    VETOES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    -1
}

#[test]
fn a_pre_execute_veto_stops_decryption_before_the_document_changes() {
    // libxmlsec1 runs the context's pre-execute callback when it prepares the
    // decryption chain: a negative return refuses the operation, so the
    // EncryptedData stays in the document.
    own_process();
    let plaintext = b"<Data>kept encrypted</Data>";
    // SAFETY: the library, a document, contexts and keys set up and released
    // here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.pre_exec_callback = Some(veto);
        assert_eq!(xmlSecEncCtxDecrypt(ctx, tmpl), -1);
        assert_eq!((*ctx).result_replaced, 0);
        assert_eq!(xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc), tmpl);
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn encryption_reads_its_oaep_label_under_the_encryption_policy() {
    // The context knows its operation before it reads the EncryptionMethod:
    // an encryption reads the label under the encryption policy, so a
    // stricter decryption limit does not refuse it.
    own_process();
    xml_sec_libxml2::policy::republish_encryption(
        |_| {},
        |decryption| decryption.resources.max_encryption_metadata_bytes = 64,
    )
    .expect("the library policy compiles");
    let label = [0x4c_u8; 72];
    let content_key = [0x42_u8; 16];
    let pem = include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    // SAFETY: the library, a document, a context and a key set up and
    // released here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            crate::ffi::transforms::transport::rsa_oaep(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let method = crate::ffi::templates::xmlSecTmplEncDataGetEncMethodNode(tmpl);
        assert_eq!(
            crate::ffi::templates::xmlSecTmplTransformAddRsaOaepParam(
                method,
                label.as_ptr(),
                label.len(),
            ),
            0
        );
        let key = crate::ffi::app::key_load_memory(
            pem.as_ptr(),
            pem.len(),
            2,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert!(!key.is_null(), "the fixture loads");
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = key.cast();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, content_key.as_ptr(), content_key.len()),
            0,
            "the encryption policy admits the label"
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn failure_strings_are_libxmlsec1s() {
    assert_eq!(failure_string(FAILURE_KEY_NOT_FOUND), c"KEY-NOT-FOUND");
    assert_eq!(failure_string(FAILURE_UNKNOWN), c"UNKNOWN");
    assert_eq!(failure_string(7), c"UNKNOWN");
}

#[test]
fn a_context_initializes_with_libxmlsec1s_defaults_and_finalizes_to_zero() {
    // SAFETY: contexts created, initialized and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        assert!(!ctx.is_null());
        assert_eq!((*ctx).mode, MODE_ENCRYPTED_DATA);
        assert_eq!((*ctx).key_info_read_ctx.mode, MODE_READ);
        assert_eq!((*ctx).key_info_write_ctx.mode, MODE_WRITE);
        assert_eq!((*ctx).key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        // A reset keeps the user settings and the defaults.
        (*ctx).flags = FLAGS_RETURN_REPLACED_NODE;
        (*ctx).mode = MODE_ENCRYPTED_KEY;
        xmlSecEncCtxReset(ctx);
        assert_eq!((*ctx).flags, FLAGS_RETURN_REPLACED_NODE);
        assert_eq!((*ctx).mode, MODE_ENCRYPTED_KEY);
        assert_eq!((*ctx).key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        let copy = xmlSecEncCtxCreate(std::ptr::null_mut());
        assert_eq!(xmlSecEncCtxCopyUserPref(copy, ctx), 0);
        assert_eq!((*copy).flags, FLAGS_RETURN_REPLACED_NODE);
        assert_eq!((*copy).mode, MODE_ENCRYPTED_KEY);
        xmlSecEncCtxDestroy(copy);
        xmlSecEncCtxDestroy(ctx);

        let mut stack = std::mem::MaybeUninit::<XmlSecEncCtx>::uninit();
        assert_eq!(
            xmlSecEncCtxInitialize(stack.as_mut_ptr(), std::ptr::null_mut()),
            0
        );
        xmlSecEncCtxFinalize(stack.as_mut_ptr());
        let bytes =
            std::slice::from_raw_parts(stack.as_ptr().cast::<u8>(), size_of::<XmlSecEncCtx>());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
