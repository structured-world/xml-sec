//! The ML-KEM key transport klasses through the encryption context: the
//! donor's vectors decrypt to their data, every parameter set round trips,
//! and the run's policy decides which parameter sets and content ciphers an
//! ML-KEM key may serve.

use std::ffi::CStr;

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::super::super::app::key_load_memory;
use super::super::super::crypto::{
    xmlSecCryptoAppDefaultKeysMngrAdoptKey, xmlSecCryptoAppDefaultKeysMngrInit,
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use super::super::super::keys::xmlSecKeySetName;
use super::super::super::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use super::super::super::library::{xmlSecInit, xmlSecShutdown};
use super::super::super::tests::own_process;
use super::super::super::tree::XmlDoc;
use super::super::super::xmlenc::{
    xmlSecEncCtxBinaryEncrypt, xmlSecEncCtxCreate, xmlSecEncCtxDecryptToBuffer, xmlSecEncCtxDestroy,
};
use super::*;

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;

macro_rules! fixture {
    ($path:literal) => {
        include_bytes!(concat!("../../../../../../tests/fixtures/", $path))
    };
}

const KEY_512: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-512-key.pem");
const PUBLIC_512: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-512-pubkey.pem");
const KEY_768: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-768-key.pem");
const PUBLIC_768: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-768-pubkey.pem");
const KEY_1024: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-1024-key.pem");
const PUBLIC_1024: &[u8] = fixture!("xmldsig/keys/ml-kem/ml-kem-1024-pubkey.pem");

/// Initializes the library and its crypto, runs `test` and shuts both down.
fn with_library(test: impl FnOnce()) {
    own_process();
    // SAFETY: the library initialized and shut down on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
    }
    test();
    // SAFETY: every object of the test is released.
    unsafe {
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A keys manager holding each PEM key under its name.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn manager(keys: &[(&[u8], &CStr)]) -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract; each key is adopted by the manager.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(xmlSecCryptoAppDefaultKeysMngrInit(mngr.cast()), 0);
        for (pem, name) in keys {
            let key = key_load_memory(
                pem.as_ptr(),
                pem.len(),
                FORMAT_PEM,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
            .cast::<XmlSecKey>();
            assert!(!key.is_null(), "the fixture loads");
            assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
            assert_eq!(
                xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr.cast(), key.cast()),
                0
            );
        }
        mngr
    }
}

/// `xml` read as a document.
fn document(xml: &[u8]) -> *mut XmlDoc {
    // SAFETY: the document's bytes.
    let doc = unsafe {
        xsReadMemory(
            xml.as_ptr().cast(),
            c_int::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!doc.is_null(), "the document parses");
    doc.cast()
}

/// What decrypting `doc` with a context over `mngr` yields, `None` when it
/// fails.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn decrypted(doc: *mut XmlDoc, mngr: *mut XmlSecKeysMngr) -> Option<Vec<u8>> {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        // A donor vector encrypts content inside a larger document.
        let node = super::super::super::xmltree::xmlSecFindNode(
            xsDocGetRootElement(doc.cast()).cast(),
            c"EncryptedData".as_ptr().cast(),
            c"http://www.w3.org/2001/04/xmlenc#".as_ptr().cast(),
        );
        assert!(!node.is_null(), "the document holds EncryptedData");
        let result = xmlSecEncCtxDecryptToBuffer(ctx, node.cast());
        let plaintext = (!result.is_null()).then(|| {
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec()
        });
        xmlSecEncCtxDestroy(ctx);
        plaintext
    }
}

/// Decrypts the donor document `xml` with the private key `key` under
/// `name`: the plaintext, `None` when the decryption fails.
fn decrypt_vector(xml: &[u8], key: &[u8], name: &CStr) -> Option<Vec<u8>> {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(xml);
        let mngr = manager(&[(key, name)]);
        let result = decrypted(doc, mngr);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        result
    }
}

/// Encrypts `plaintext` into the template `xml` for the recipient whose
/// public key `public` is under `name`, the content key being the secret
/// the template's ML-KEM `EncryptedKey` encapsulates, as libxmlsec1's
/// encryption takes it from its `KeyInfo`; then decrypts with the private key
/// `key`: the plaintext, `None` when the decryption fails. The encryption
/// must succeed.
fn round_trip(
    xml: &[u8],
    public: &[u8],
    key: &[u8],
    name: &CStr,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(xml);
        let sender = manager(&[(public, name)]);
        let ctx = xmlSecEncCtxCreate(sender);
        let encrypted = xmlSecEncCtxBinaryEncrypt(
            ctx,
            xsDocGetRootElement(doc.cast()),
            plaintext.as_ptr(),
            plaintext.len(),
        );
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(sender);
        assert_eq!(encrypted, 0, "the sender encrypts");
        let recipient = manager(&[(key, name)]);
        let result = decrypted(doc, recipient);
        xmlSecKeysMngrDestroy(recipient);
        xsFreeDoc(doc.cast());
        result
    }
}

/// A donor vector: its document, its data, the recipient's private key file
/// and the name the vector gives that key.
type Vector = (&'static [u8], &'static [u8], &'static [u8], &'static CStr);

#[test]
fn donor_ml_kem_vectors_decrypt_to_their_data() {
    // The donor's ML-KEM EncryptedKey vectors, GCM and CBC content alike,
    // decrypt to the data they were made from under the library policy,
    // which admits ML-KEM keying CBC content as libxmlsec1 does.
    with_library(|| {
        let mut vectors: Vec<Vector> = vec![
            (
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.data"),
                KEY_512,
                c"TestKeyName-ml-kem-512",
            ),
            (
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256gcm-kt-ml-kem-1024.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256gcm-kt-ml-kem-1024.data"),
                KEY_1024,
                c"TestKeyName-ml-kem-1024",
            ),
            (
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-512.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-512.data"),
                KEY_512,
                c"TestKeyName-ml-kem-512",
            ),
            (
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-768.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-768.data"),
                KEY_768,
                c"TestKeyName-ml-kem-768",
            ),
            (
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-1024.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-1024.data"),
                KEY_1024,
                c"TestKeyName-ml-kem-1024",
            ),
        ];
        // AES-192 is built only with the historical algorithms.
        if cfg!(feature = "legacy-algorithms") {
            vectors.push((
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes192gcm-kt-ml-kem-768.xml"),
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes192gcm-kt-ml-kem-768.data"),
                KEY_768,
                c"TestKeyName-ml-kem-768",
            ));
        }
        for (xml, data, key, name) in vectors {
            // The vector encrypted the content of the data's CreditCard
            // element, which the decryption recovers.
            let content = decrypt_vector(xml, key, name).expect("the vector decrypts");
            assert!(content.starts_with(b"\n    <Number>"), "{name:?}");
            assert!(
                data.windows(content.len()).any(|window| window == content),
                "{name:?}"
            );
        }
    });
}

#[test]
fn every_parameter_set_round_trips() {
    // A sender holding the recipient's public key encapsulates a fresh
    // secret, keys the content with its first octets and writes the
    // ciphertext; the recipient's private key decapsulates it.
    with_library(|| {
        for (xml, public, key, name) in [
            (
                &fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.tmpl")[..],
                PUBLIC_512,
                KEY_512,
                c"TestKeyName-ml-kem-512",
            ),
            (
                &fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-768.tmpl")[..],
                PUBLIC_768,
                KEY_768,
                c"TestKeyName-ml-kem-768",
            ),
            (
                &fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256gcm-kt-ml-kem-1024.tmpl")[..],
                PUBLIC_1024,
                KEY_1024,
                c"TestKeyName-ml-kem-1024",
            ),
        ] {
            assert_eq!(
                round_trip(xml, public, key, name, b"encapsulated content").as_deref(),
                Some(&b"encapsulated content"[..]),
                "{name:?}"
            );
        }
    });
}

/// The PEM key `pem` loaded as a key.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn load_key(pem: &[u8]) -> *mut XmlSecKey {
    // SAFETY: by the caller's contract.
    let key = unsafe {
        key_load_memory(
            pem.as_ptr(),
            pem.len(),
            FORMAT_PEM,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }
    .cast::<XmlSecKey>();
    assert!(!key.is_null(), "the fixture loads");
    key
}

#[test]
fn a_decapsulation_takes_no_public_only_key() {
    // A public key cannot decapsulate, so a decrypting transport refuses it
    // without taking it, and the private key that follows is taken; an
    // encrypting transport takes the public key.
    use super::super::super::keys::xmlSecKeyDestroy;
    use super::super::super::transforms::ctx::{
        xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
    };
    use super::super::super::transforms::xmlSecTransformSetKey;
    with_library(|| {
        // SAFETY: contexts and keys created and released here.
        unsafe {
            let public = load_key(PUBLIC_512);
            let private = load_key(KEY_512);
            for (operation, first, expected) in [
                (OPERATION_DECRYPT, public, -1),
                (OPERATION_ENCRYPT, public, 0),
            ] {
                let ctx = xmlSecTransformCtxCreate();
                let transform = xmlSecTransformCtxCreateAndAppend(ctx, mlkem512());
                (*transform).operation = operation;
                assert_eq!(xmlSecTransformSetKey(transform, first.cast()), expected);
                if expected < 0 {
                    assert_eq!(xmlSecTransformSetKey(transform, private.cast()), 0);
                }
                xmlSecTransformCtxDestroy(ctx);
            }
            xmlSecKeyDestroy(public);
            xmlSecKeyDestroy(private);
        }
    });
}

#[test]
fn a_decapsulation_buffers_no_more_than_one_ciphertext() {
    // A ciphertext has the parameter set's exact width, so input beyond it is
    // refused as it arrives rather than held until the final call; input up
    // to the width is kept for it.
    use super::super::super::keys::xmlSecKeyDestroy;
    use super::super::super::transforms::ctx::{
        xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
    };
    use super::super::super::transforms::{xmlSecTransformPushBin, xmlSecTransformSetKey};
    with_library(|| {
        let width = KeyEncapsulationAlgorithm::MlKem512.ciphertext_len();
        // SAFETY: contexts and a key created and released here.
        unsafe {
            let private = load_key(KEY_512);
            for (size, expected) in [(width, 0), (width + 1, -1)] {
                let ctx = xmlSecTransformCtxCreate();
                let transform = xmlSecTransformCtxCreateAndAppend(ctx, mlkem512());
                (*transform).operation = OPERATION_DECRYPT;
                assert_eq!(xmlSecTransformSetKey(transform, private.cast()), 0);
                let input = vec![0x5a; size];
                assert_eq!(
                    xmlSecTransformPushBin(transform, input.as_ptr(), input.len(), 0, ctx),
                    expected,
                    "{size} octets"
                );
                xmlSecTransformCtxDestroy(ctx);
            }
            xmlSecKeyDestroy(private);
        }
    });
}

#[test]
fn a_kept_ciphertext_is_written_whole_whatever_the_expected_width() {
    // The expected width is the width of the key the secret becomes; a
    // ciphertext the context keeps for the EncryptedKey write is written
    // whole, since a cut ciphertext decapsulates to nothing.
    use super::super::super::buffer::xmlSecBufferSetData;
    use super::super::super::keys::xmlSecKeyDestroy;
    use super::super::super::transforms::ctx::{
        xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate,
        xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
    };
    use super::super::super::transforms::xmlSecTransformSetKey;
    with_library(|| {
        let width = KeyEncapsulationAlgorithm::MlKem512.ciphertext_len();
        // SAFETY: a context and a key created and released here.
        unsafe {
            let public = load_key(PUBLIC_512);
            let ctx = xmlSecTransformCtxCreate();
            let kept = kem_data(xmlSecTransformCtxExtraKeyDataEnsure(
                ctx,
                &raw const KEM_DATA,
            ))
            .expect("the context keeps KEM data");
            let ciphertext = vec![0x3c; width];
            assert_eq!(
                xmlSecBufferSetData(&raw mut kept.ciphertext, ciphertext.as_ptr(), width),
                0
            );
            let spki = &mlkemkeys::key_of(xmlSecKeyGetValue(public))
                .expect("an ML-KEM key")
                .spki;
            assert_eq!(
                xmlSecBufferSetData(&raw mut kept.recipient, spki.as_ptr(), spki.len()),
                0
            );
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, mlkem512());
            (*transform).operation = OPERATION_ENCRYPT;
            (*transform).expected_output_size = 16;
            assert_eq!(xmlSecTransformSetKey(transform, public.cast()), 0);
            assert_eq!(xmlSecTransformCtxBinaryExecute(ctx, [].as_ptr(), 0), 0);
            assert_eq!(
                xmlSecBufferGetSize((*ctx).result),
                width,
                "the whole ciphertext"
            );
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(public);
        }
    });
}

#[test]
fn a_kept_ciphertext_is_written_for_its_own_recipient_only() {
    // An ML-KEM secret keys the content for the one recipient it was
    // encapsulated to; writing its ciphertext into another recipient's
    // EncryptedKey would hand that recipient a key it cannot recover, so the
    // write is refused (libxmlsec1 writes it and reports success).
    use super::super::super::buffer::xmlSecBufferSetData;
    use super::super::super::keys::xmlSecKeyDestroy;
    use super::super::super::transforms::ctx::{
        xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate,
        xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
    };
    use super::super::super::transforms::xmlSecTransformSetKey;
    with_library(|| {
        let width = KeyEncapsulationAlgorithm::MlKem512.ciphertext_len();
        // SAFETY: a context and a key created and released here.
        unsafe {
            let public = load_key(PUBLIC_512);
            let ctx = xmlSecTransformCtxCreate();
            let kept = kem_data(xmlSecTransformCtxExtraKeyDataEnsure(
                ctx,
                &raw const KEM_DATA,
            ))
            .expect("the context keeps KEM data");
            let ciphertext = vec![0x3c; width];
            let another = [0x11; 64];
            assert_eq!(
                xmlSecBufferSetData(&raw mut kept.ciphertext, ciphertext.as_ptr(), width),
                0
            );
            assert_eq!(
                xmlSecBufferSetData(&raw mut kept.recipient, another.as_ptr(), another.len()),
                0
            );
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, mlkem512());
            (*transform).operation = OPERATION_ENCRYPT;
            assert_eq!(xmlSecTransformSetKey(transform, public.cast()), 0);
            assert_eq!(xmlSecTransformCtxBinaryExecute(ctx, [].as_ptr(), 0), -1);
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(public);
        }
    });
}

/// The octets the `test:content` resource still holds.
static CONTENT_LEFT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn content_matches(uri: *const std::ffi::c_char) -> c_int {
    // SAFETY: the transform passes a NUL-terminated URI.
    c_int::from(unsafe { CStr::from_ptr(uri) } == c"test:content")
}

unsafe extern "C" fn content_open(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    CONTENT_LEFT.store(7, std::sync::atomic::Ordering::Relaxed);
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn content_read(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: c_int,
) -> c_int {
    let left = CONTENT_LEFT.load(std::sync::atomic::Ordering::Relaxed);
    let count = left.min(usize::try_from(len).expect("a non-negative length"));
    CONTENT_LEFT.store(left - count, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { buffer.cast::<u8>().write_bytes(b'c', count) };
    c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn content_close(_context: *mut std::ffi::c_void) -> c_int {
    0
}

/// Whether the ML-KEM template `xml` encrypts for the public key `public`
/// under `name`: its content from a buffer, or with `by_uri` the resource
/// `test:content` read through the caller's input callbacks.
fn kem_encrypts(xml: &[u8], public: &[u8], name: &CStr, by_uri: bool) -> bool {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(xml);
        let sender = manager(&[(public, name)]);
        let ctx = xmlSecEncCtxCreate(sender);
        let tmpl = xsDocGetRootElement(doc.cast());
        let plaintext = b"content";
        let encrypted = if by_uri {
            super::super::super::xmlenc::xmlSecEncCtxUriEncrypt(
                ctx,
                tmpl,
                c"test:content".as_ptr().cast(),
            )
        } else {
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len())
        };
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(sender);
        xsFreeDoc(doc.cast());
        encrypted == 0
    }
}

#[test]
fn an_encryption_keys_cbc_content_by_kem_only_when_the_policy_lets_it() {
    // The encryption policy decides whether an ML-KEM secret may key CBC
    // content on the way out, as the decryption policy decides it on the
    // way in: requiring an authenticated cipher refuses the CBC template
    // before anything is written, whether the content comes from a buffer or
    // from a resource the caller names, and leaves the GCM one encrypting.
    with_library(|| {
        // SAFETY: the callback list belongs to this test's process.
        let registered = unsafe {
            crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
                Some(content_matches),
                Some(content_open),
                Some(content_read),
                Some(content_close),
            )
        };
        assert_eq!(registered, 0);
        let encrypts =
            |xml: &[u8], public: &[u8], name: &CStr| kem_encrypts(xml, public, name, false);
        let cbc: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-768.tmpl");
        let gcm: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.tmpl");
        let name_768 = c"TestKeyName-ml-kem-768";
        assert!(encrypts(cbc, PUBLIC_768, name_768));
        assert!(kem_encrypts(cbc, PUBLIC_768, name_768, true));
        xml_sec_libxml2::policy::republish_encryption(
            |encryption| {
                encryption.key_establishment.kem_content_authentication =
                    xml_sec::policy::KemContentAuthentication::RequireAuthenticatedCipher;
            },
            |_| {},
        )
        .expect("the library policy compiles");
        assert!(!encrypts(cbc, PUBLIC_768, name_768));
        assert!(!kem_encrypts(cbc, PUBLIC_768, name_768, true));
        assert!(encrypts(gcm, PUBLIC_512, c"TestKeyName-ml-kem-512"));
    });
}

#[test]
fn a_key_of_another_parameter_set_decapsulates_nothing() {
    // An ML-KEM-768 private key named as the ML-KEM-512 recipient is refused
    // by the 512 transform, as libxmlsec1 refuses a parameter-set mismatch,
    // so the content does not decrypt.
    with_library(|| {
        assert_eq!(
            decrypt_vector(
                fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.xml"),
                KEY_768,
                c"TestKeyName-ml-kem-512",
            ),
            None
        );
    });
}

/// Whether the donor ML-KEM HMAC signature `xml` verifies with a signature
/// context whose keys manager holds the recipient key `key` under `name`.
fn verifies_kem_signature(xml: &[u8], key: &[u8], name: &CStr) -> bool {
    use super::super::super::xmldsig::{
        STATUS_SUCCEEDED, xmlSecDSigCtxCreate, xmlSecDSigCtxDestroy, xmlSecDSigCtxVerify,
    };
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(xml);
        let mngr = manager(&[(key, name)]);
        let ctx = xmlSecDSigCtxCreate(mngr);
        let node = super::super::super::xmltree::xmlSecFindNode(
            xsDocGetRootElement(doc.cast()).cast(),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        assert!(!node.is_null(), "the document holds a Signature");
        let verified =
            xmlSecDSigCtxVerify(ctx, node.cast()) == 0 && (*ctx).status == STATUS_SUCCEEDED;
        xmlSecDSigCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc.cast());
        verified
    }
}

const KEM_SIGNATURE: &[u8] =
    fixture!("xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-kt-ml-kem-512.xml");

#[test]
fn a_signature_spends_its_own_kem_allowance() {
    // The EncryptedKey of a KEM/HMAC signature decapsulates for the
    // verification, so the verification's encapsulation allowance bounds it,
    // whatever the decryption policy admits.
    with_library(|| {
        let name = c"TestKeyName-ml-kem-512";
        assert!(verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
        crate::ffi::policy::republish(
            |verification| verification.key_establishment.max_encapsulation_operations = 0,
            |_| {},
        )
        .expect("the library policy compiles");
        assert!(!verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
    });
}

#[test]
fn a_signature_admits_its_kem_parameter_set_by_its_own_policy() {
    // The EncryptedKey of a KEM/HMAC signature runs in the decryption
    // direction, but its method is admitted by the verification it serves:
    // dropping ML-KEM-512 from decryption alone leaves the signature
    // verifying, dropping it from verification refuses it.
    with_library(|| {
        let name = c"TestKeyName-ml-kem-512";
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| {
                decryption
                    .key_establishment
                    .encapsulation_algorithms
                    .remove(&KeyEncapsulationAlgorithm::MlKem512);
            },
        )
        .expect("the library policy compiles");
        assert!(verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
        crate::ffi::policy::republish(
            |verification| {
                verification
                    .key_establishment
                    .encapsulation_algorithms
                    .remove(&KeyEncapsulationAlgorithm::MlKem512);
            },
            |_| {},
        )
        .expect("the library policy compiles");
        assert!(!verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
    });
}

#[test]
fn the_recovered_secret_is_reserved_before_it_is_copied() {
    // The secret a transport copies out is owned key establishment storage:
    // with no owned bytes allowed, neither a decryption nor a verification
    // recovers it, as the core refuses its own decapsulation.
    with_library(|| {
        let name = c"TestKeyName-ml-kem-512";
        let gcm: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.xml");
        assert!(decrypt_vector(gcm, KEY_512, name).is_some());
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| decryption.key_establishment.max_owned_bytes = 0,
        )
        .expect("the library policy compiles");
        assert_eq!(decrypt_vector(gcm, KEY_512, name), None);
        assert!(verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
        crate::ffi::policy::republish(
            |verification| verification.key_establishment.max_owned_bytes = 0,
            |_| {},
        )
        .expect("the library policy compiles");
        assert!(!verifies_kem_signature(KEM_SIGNATURE, KEY_512, name));
    });
}

#[test]
fn the_policy_decides_parameter_sets_and_kem_content_ciphers() {
    // A deployment that requires an authenticated content cipher keeps
    // ML-KEM for GCM content and refuses it for CBC content; one that drops
    // a parameter set refuses that parameter set's vector.
    with_library(|| {
        let gcm: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.xml");
        let cbc: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-512.xml");
        let name = c"TestKeyName-ml-kem-512";
        assert!(decrypt_vector(cbc, KEY_512, name).is_some());
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| {
                decryption.key_establishment.kem_content_authentication =
                    xml_sec::policy::KemContentAuthentication::RequireAuthenticatedCipher;
            },
        )
        .expect("the library policy compiles");
        assert_eq!(decrypt_vector(cbc, KEY_512, name), None);
        assert!(decrypt_vector(gcm, KEY_512, name).is_some());
        xml_sec_libxml2::policy::republish_encryption(
            |_| {},
            |decryption| {
                decryption
                    .key_establishment
                    .encapsulation_algorithms
                    .remove(&KeyEncapsulationAlgorithm::MlKem512);
            },
        )
        .expect("the library policy compiles");
        assert_eq!(decrypt_vector(gcm, KEY_512, name), None);
    });
}

#[test]
fn a_restricting_layer_takes_kem_content_ciphers_and_parameter_sets_back() {
    // A C deployment applying its xml-sec-config layer with
    // xsPolicyRestrict gets what the layer states for every later
    // operation: CBC content keyed by ML-KEM refused, GCM still decrypting,
    // and a dropped parameter set refused.
    with_library(|| {
        let gcm: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes128gcm-kt-ml-kem-512.xml");
        let cbc: &[u8] = fixture!("xmlenc/aleksey-xmlenc-01/enc-aes256-kt-ml-kem-512.xml");
        let name = c"TestKeyName-ml-kem-512";
        assert!(decrypt_vector(cbc, KEY_512, name).is_some());
        let restrict = |toml: &str| {
            // SAFETY: the document's bytes and a NUL-terminated name.
            unsafe {
                super::super::super::policy::xsPolicyRestrict(
                    toml.as_ptr(),
                    toml.len(),
                    c"deployment".as_ptr(),
                )
            }
        };
        let authenticated = r#"
schema_version = 1
[profiles.deployment]
base = "XmlSecCompatible"
[profiles.deployment.decryption.key_establishment]
kem_content_authentication = "RequireAuthenticatedCipher"
"#;
        assert_eq!(restrict(authenticated), 0);
        assert_eq!(decrypt_vector(cbc, KEY_512, name), None);
        assert!(decrypt_vector(gcm, KEY_512, name).is_some());
        let without_512 = format!(
            r#"
schema_version = 1
[profiles.deployment]
base = "XmlSecCompatible"
[profiles.deployment.decryption.key_establishment]
encapsulation_algorithms = ["{}", "{}"]
"#,
            KeyEncapsulationAlgorithm::MlKem768.uri(),
            KeyEncapsulationAlgorithm::MlKem1024.uri()
        );
        assert_eq!(restrict(&without_512), 0);
        assert_eq!(decrypt_vector(gcm, KEY_512, name), None);
    });
}
