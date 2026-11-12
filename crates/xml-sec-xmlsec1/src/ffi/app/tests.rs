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
