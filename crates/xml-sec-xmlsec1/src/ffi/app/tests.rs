//! Key loading keeps the failure of a protected private key: the public-key
//! reading it falls back to is tried only for a container that holds no
//! private key.

use xml_sec::key_manager::KeyStoreError;
use xml_sec::policy::ResourcePolicy;

use super::{FORMAT_PEM, Password, material};

const RSA_ENCRYPTED: &[u8] =
    include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem");
const RSA_PUBLIC: &[u8] =
    include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

/// A password source holding `explicit`, or none.
fn password(explicit: Option<&std::ffi::CStr>) -> Password {
    Password {
        explicit: explicit.map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
        callback: std::ptr::null_mut(),
        context: std::ptr::null_mut(),
    }
}

#[test]
fn a_protected_key_without_its_password_stays_a_protected_failure() {
    // A missing or wrong password is the failure the caller can recover
    // from; it is not replaced by the public-key reader's.
    let resources = ResourcePolicy::default();
    for given in [None, Some(c"wrong")] {
        let loaded = material(RSA_ENCRYPTED, FORMAT_PEM, &password(given), &resources);
        assert!(
            matches!(loaded, Err(KeyStoreError::ProtectedContainer)),
            "{given:?}: {:?}",
            loaded.as_ref().err()
        );
    }
    let public = material(RSA_PUBLIC, FORMAT_PEM, &password(None), &resources)
        .expect("a public key reads")
        .expect("a format it reads");
    assert!(public.private.is_none());
}

#[test]
fn a_private_key_value_is_refused_rather_than_written_public() {
    // A context asking for the private key gets a failure, not a KeyValue
    // holding only the public part; asking for the public key writes it.
    use crate::ffi::asymkeys;
    use crate::ffi::keyinfo::{MODE_WRITE, xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy};
    use crate::ffi::keys::{
        TYPE_PRIVATE, TYPE_PUBLIC, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeySetValue,
    };
    use crate::ffi::keysdata::xmlSecKeyDataXmlWrite;
    use crate::ffi::tree::nodes;
    use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};
    const RSA_PRIVATE: &[u8] =
        include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let private = material(
        RSA_PRIVATE,
        FORMAT_PEM,
        &password(None),
        &ResourcePolicy::default(),
    )
    .expect("a private key reads")
    .expect("a format it reads");
    assert!(private.private.is_some());
    let xml = "<RSAKeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>";
    // SAFETY: objects created and destroyed here.
    unsafe {
        let key = xmlSecKeyCreate();
        assert_eq!(xmlSecKeySetValue(key, asymkeys::adopt(private)), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        (*ctx).mode = MODE_WRITE;
        for (key_type, expected) in [(TYPE_PRIVATE, -1), (TYPE_PUBLIC, 0)] {
            let doc = xsReadMemory(
                xml.as_ptr().cast(),
                i32::try_from(xml.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            let node = xsDocGetRootElement(doc);
            (*ctx).key_req.key_type = key_type;
            assert_eq!(
                xmlSecKeyDataXmlWrite(asymkeys::rsa(), key.cast(), node.cast(), ctx.cast()),
                expected,
                "key type {key_type}"
            );
            assert_eq!(nodes::first_child(node).is_null(), expected < 0);
            xsFreeDoc(doc);
        }
        xmlSecKeyInfoCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
    }
}
