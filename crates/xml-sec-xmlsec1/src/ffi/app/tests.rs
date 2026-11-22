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
        Loaded::MlKem(_) => panic!("an ML-KEM key, not an asymmetric one"),
    }
}

#[test]
fn a_public_ml_kem_key_is_no_private_key() {
    // Departure: libxmlsec1 reports every OpenSSL 3 key as private and
    // public (its issue 588), so a public key file passes a private key
    // requirement and fails only when used. Here the type says what the key
    // holds: public for the public file, both for the private one.
    use crate::ffi::keys::{TYPE_PRIVATE, TYPE_PUBLIC, xmlSecKeyDestroy, xmlSecKeyGetValue};
    use crate::ffi::keysdata::xmlSecKeyDataGetType;
    for (bytes, expected) in [
        (
            &include_bytes!(
                "../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-512-pubkey.pem"
            )[..],
            TYPE_PUBLIC,
        ),
        (
            &include_bytes!("../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-512-key.pem")
                [..],
            TYPE_PUBLIC | TYPE_PRIVATE,
        ),
    ] {
        // SAFETY: the fixture's bytes; the key is released here.
        unsafe {
            let key = super::key_load_memory(
                bytes.as_ptr(),
                bytes.len(),
                FORMAT_PEM,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
            .cast::<crate::ffi::keys::XmlSecKey>();
            assert!(!key.is_null(), "the key loads");
            assert_eq!(xmlSecKeyDataGetType(xmlSecKeyGetValue(key)), expected);
            xmlSecKeyDestroy(key);
        }
    }
}

#[test]
fn ml_kem_keys_load_as_ml_kem_key_data() {
    // ML-KEM key files of every parameter set load as ML-KEM keys: the
    // private key in PEM, DER and password-protected PKCS#8 with its PKCS#8
    // and the public key of the matching public file, the public file alone
    // with no private key; the parameter set is the key's own.
    use xml_sec::provider::KeyEncapsulationAlgorithm as A;
    let resources = ResourcePolicy::default();
    let load = |bytes: &[u8], format| match material(
        bytes,
        format,
        &password(Some(c"secret123")),
        &resources,
    )
    .expect("the key reads")
    .expect("a format it reads")
    {
        Loaded::MlKem(key) => key,
        Loaded::Asymmetric(_) | Loaded::Xdh(_) => panic!("not an ML-KEM key"),
    };
    macro_rules! key_files {
        ($size:literal) => {
            (
                &include_bytes!(concat!(
                    "../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-",
                    $size,
                    "-key.pem"
                ))[..],
                &include_bytes!(concat!(
                    "../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-",
                    $size,
                    "-key.der"
                ))[..],
                &include_bytes!(concat!(
                    "../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-",
                    $size,
                    "-key.p8-der"
                ))[..],
                &include_bytes!(concat!(
                    "../../../../../tests/fixtures/xmldsig/keys/ml-kem/ml-kem-",
                    $size,
                    "-pubkey.pem"
                ))[..],
            )
        };
    }
    for (algorithm, (pem, der, pkcs8, public)) in [
        (A::MlKem512, key_files!("512")),
        (A::MlKem768, key_files!("768")),
        (A::MlKem1024, key_files!("1024")),
    ] {
        let public = load(public, FORMAT_PEM);
        assert_eq!(public.algorithm, algorithm);
        assert!(public.private.is_none());
        for (bytes, format) in [
            (pem, FORMAT_PEM),
            (der, super::FORMAT_DER),
            (pkcs8, super::FORMAT_PKCS8_DER),
        ] {
            let private = load(bytes, format);
            assert_eq!(private.algorithm, algorithm, "{algorithm:?} {format}");
            assert!(private.private.is_some());
            assert_eq!(private.spki, public.spki, "{algorithm:?} {format}");
        }
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
fn an_xdh_pkcs12_bundle_loads_as_xdh_key_data() {
    // A PKCS#12 bundle of an X25519 key loads as XDH key data holding the
    // private key, as libxmlsec1 loads it; a wrong password loads nothing.
    use crate::ffi::keys::{xmlSecKeyDestroy, xmlSecKeyGetValue};
    use crate::ffi::xdhkeys::key_of;
    const BUNDLE: &[u8] =
        include_bytes!("../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-key.p12");
    let load = |pwd: &std::ffi::CStr| {
        // SAFETY: the fixture's bytes and a NUL-terminated password.
        unsafe {
            super::pkcs12_load_memory(
                BUNDLE.as_ptr(),
                BUNDLE.len(),
                pwd.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
        .cast::<crate::ffi::keys::XmlSecKey>()
    };
    let key = load(c"secret123");
    assert!(!key.is_null(), "the bundle loads");
    // SAFETY: the key loaded above, released here.
    unsafe {
        let xdh = key_of(xmlSecKeyGetValue(key)).expect("XDH key data");
        assert!(xdh.private.is_some());
        assert_eq!(xdh.public().map(|(_, public)| public.len()), Some(32));
        xmlSecKeyDestroy(key);
    }
    assert!(load(c"wrong").is_null());
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
        Loaded::Asymmetric(_) | Loaded::MlKem(_) => panic!("not an XDH key"),
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
