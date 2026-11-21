//! Key loading keeps the failure of a protected private key: the public-key
//! reading it falls back to is tried only for a container that holds no
//! private key.

use xml_sec::key_manager::KeyStoreError;
use xml_sec::policy::ResourcePolicy;

use super::{FORMAT_PEM, FORMAT_PKCS8_PEM, Loaded, Password, material};
use crate::ffi::asymkeys::Material;

/// The RSA, DSA or EC key `loaded` holds.
fn asymmetric(loaded: Loaded) -> Material {
    match loaded {
        Loaded::Asymmetric(material) => material,
        Loaded::Xdh(_) => panic!("an XDH key, not an asymmetric one"),
    }
}

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
    assert!(asymmetric(public).private.is_none());
}

#[test]
fn xdh_keys_load_as_xdh_key_data() {
    // X25519 and X448 key files, the private key also in password-protected
    // PKCS#8, load as XDH keys: the private key with its PKCS#8 and the
    // public key the matching public file holds, the public file alone with
    // no private key.
    let resources = ResourcePolicy::default();
    let xdh = |bytes: &[u8], format, pwd: Option<&std::ffi::CStr>| match material(
        bytes,
        format,
        &password(pwd),
        &resources,
    )
    .expect("the key reads")
    .expect("a format it reads")
    {
        Loaded::Xdh(key) => key,
        Loaded::Asymmetric(_) => panic!("an asymmetric key, not an XDH one"),
    };
    for (private, encrypted, public, width) in [
        (
            &include_bytes!(
                "../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-key.pem"
            )[..],
            &include_bytes!(
                "../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-key.p8-pem"
            )[..],
            &include_bytes!(
                "../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-pubkey.pem"
            )[..],
            32,
        ),
        (
            &include_bytes!("../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-first-key.pem")
                [..],
            &include_bytes!(
                "../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-first-key.p8-pem"
            )[..],
            &include_bytes!(
                "../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-first-pubkey.pem"
            )[..],
            56,
        ),
    ] {
        let from_private = xdh(private, FORMAT_PEM, None);
        let from_encrypted = xdh(encrypted, FORMAT_PKCS8_PEM, Some(c"secret123"));
        let from_public = xdh(public, FORMAT_PEM, None);
        assert!(from_private.private.is_some() && from_encrypted.private.is_some());
        assert!(from_public.private.is_none());
        assert_eq!(from_private.spki, from_public.spki);
        assert_eq!(from_encrypted.spki, from_public.spki);
        assert_eq!(from_public.public().map(|(_, key)| key.len()), Some(width));
    }
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
    let private = asymmetric(
        material(
            RSA_PRIVATE,
            FORMAT_PEM,
            &password(None),
            &ResourcePolicy::default(),
        )
        .expect("a private key reads")
        .expect("a format it reads"),
    );
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
