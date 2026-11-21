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
