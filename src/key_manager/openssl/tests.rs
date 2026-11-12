use std::fmt::Write as _;

use aes::cipher::BlockModeEncrypt as _;
use base64::Engine as _;
use p256::pkcs8::DecodePrivateKey as _;

/// The error of bytes outside the selected container, as a pattern.
macro_rules! unsupported {
    () => {
        Err(KeyStoreError::Selection(
            "unsupported private key container",
        ))
    };
}

use super::*;

const RSA_ENCRYPTED: &[u8] =
    include_bytes!("../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem");
const EC_ENCRYPTED: &[u8] =
    include_bytes!("../../../tests/fixtures/keys/ec/p256-key-traditional-encrypted.pem");
const DSA_ENCRYPTED: &[u8] =
    include_bytes!("../../../tests/fixtures/keys/dsa/dsa-2048-key-traditional-encrypted.pem");
const RSA_PKCS8: &[u8] = include_bytes!("../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
const RSA_PUBLIC: &str = include_str!("../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

fn import(
    bytes: &[u8],
    container: PrivateKeyContainer,
    password: Option<&[u8]>,
    resources: &ResourcePolicy,
) -> Result<KeyInventory, KeyStoreError> {
    let mut inventory = KeyInventory::default();
    inventory.add_openssl_private_key(
        "key".to_owned(),
        bytes,
        container,
        password,
        KeyUsages::SIGN,
        resources,
    )?;
    Ok(inventory)
}

/// `der` under `tag` in the traditional envelope with AES-256-CBC.
fn encrypted_pem(tag: &str, der: &[u8], password: &[u8]) -> String {
    let iv = [0x39; 16];
    let key = envelope_key(password, &iv[..8], 32);
    let mut ciphertext = vec![0_u8; der.len() + 16];
    ciphertext[..der.len()].copy_from_slice(der);
    let length = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
        .expect("a 32-byte key and a 16-byte IV")
        .encrypt_padded::<Pkcs7>(&mut ciphertext, der.len())
        .expect("room for one padding block")
        .len();
    ciphertext.truncate(length);
    let body = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    let mut iv_hex = String::new();
    for byte in iv {
        write!(iv_hex, "{byte:02X}").expect("writing to a String cannot fail");
    }
    format!(
        "-----BEGIN {tag}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{iv_hex}\n\n{body}\n-----END {tag}-----\n"
    )
}

fn plain_pem(tag: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN {tag}-----\n{body}\n-----END {tag}-----\n")
}

#[test]
fn encrypted_traditional_keys_import_with_their_password() {
    // OpenSSL's traditional envelope of each family decrypts to the key whose
    // public half matches the fixture's public key.
    let resources = ResourcePolicy::default();
    let rsa = import(
        RSA_ENCRYPTED,
        PrivateKeyContainer::Pem,
        Some(b"legacy-rsa-password"),
        &resources,
    )
    .expect("the fixture password decrypts the RSA key");
    let expected = pem::parse(RSA_PUBLIC)
        .expect("the public key fixture")
        .into_contents();
    let spki = rsa.private_keys()[0]
        .public_key_spki_der()
        .expect("an RSA private key derives its public key");
    assert_eq!(spki, expected);
    for (bytes, password) in [
        (EC_ENCRYPTED, b"legacy-ec-password".as_slice()),
        (DSA_ENCRYPTED, b"legacy-dsa-password".as_slice()),
    ] {
        let inventory = import(bytes, PrivateKeyContainer::Pem, Some(password), &resources)
            .expect("the fixture password decrypts the key");
        assert_eq!(inventory.private_keys().len(), 1);
    }
}

#[test]
fn missing_or_wrong_password_is_a_protected_container_failure() {
    // A protected envelope never falls back to plaintext decoding.
    for password in [None, Some(b"wrong".as_slice())] {
        assert!(matches!(
            import(
                RSA_ENCRYPTED,
                PrivateKeyContainer::Pem,
                password,
                &ResourcePolicy::default()
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
    }
}

#[test]
fn malformed_protection_is_refused_before_the_payload_is_decoded() {
    // An unknown cipher or a malformed IV is refused even when no budget is
    // left for the decoded DER, so it is checked before that allocation.
    let text = core::str::from_utf8(RSA_ENCRYPTED).expect("PEM is ASCII");
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: RSA_ENCRYPTED.len(),
        ..ResourcePolicy::default()
    };
    for malformed in [
        text.replace("AES-256-CBC", "RC2-CBC"),
        text.replace(
            "C98DDAE6A971742BF435D3FF6CD60028",
            "C98DDAE6A971742BF435D3FF6CD6002Z",
        ),
        text.replace("4,ENCRYPTED", "4,MIC-ONLY"),
    ] {
        assert!(matches!(
            import(
                malformed.as_bytes(),
                PrivateKeyContainer::Pem,
                Some(b"legacy-rsa-password"),
                &resources
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
    }
}

#[test]
fn a_decrypted_key_of_the_wrong_usage_is_not_a_password_failure() {
    // With the right password, an EC key imported to decrypt is refused for
    // its usage, a candidate a lax search may pass over, not reported as a
    // protected container the password failed to open.
    let mut inventory = KeyInventory::default();
    let refused = inventory.add_openssl_private_key(
        "key".to_owned(),
        EC_ENCRYPTED,
        PrivateKeyContainer::Pem,
        Some(b"legacy-ec-password"),
        KeyUsages::DECRYPT,
        &ResourcePolicy::default(),
    );
    assert!(
        matches!(
            refused,
            Err(KeyStoreError::Selection(crate::key_manager::CANNOT_DECRYPT))
        ),
        "{refused:?}"
    );
}

#[test]
fn decoded_payload_is_reserved_against_the_aggregate_budget() {
    // The new entry's name, the source and its decoded DER fit exactly; one
    // byte less fails with a policy violation before the DER is allocated.
    let pem = plain_pem("RSA PRIVATE KEY", &[1, 2, 3]);
    let name = crate::key_manager::named_material_length("key", 0, 1).expect("a short name");
    let mut resources = ResourcePolicy {
        max_external_resource_total_bytes: name + pem.len() + 3,
        ..ResourcePolicy::default()
    };
    assert!(!matches!(
        import(pem.as_bytes(), PrivateKeyContainer::Pem, None, &resources),
        Err(KeyStoreError::Policy(_))
    ));
    resources.max_external_resource_total_bytes -= 1;
    assert!(matches!(
        import(pem.as_bytes(), PrivateKeyContainer::Pem, None, &resources),
        Err(KeyStoreError::Policy(_))
    ));
}

#[test]
fn the_decoded_der_is_charged_once() {
    // The PEM source, its decoded PKCS#1 and the PKCS#8 output are live
    // together, each counted once: a budget with room for them, but not for
    // the DER a second time, admits the import.
    let pkcs8 = pem::parse(RSA_PKCS8)
        .expect("the private key fixture")
        .into_contents();
    let info = PrivateKeyInfoRef::try_from(pkcs8.as_slice()).expect("fixture PKCS#8");
    let pkcs1 = info.private_key.as_bytes();
    let text = plain_pem("RSA PRIVATE KEY", pkcs1);
    // PKCS#8 wraps PKCS#1 in a few dozen bytes; the name is three.
    let peak = text.len() + pkcs1.len() + (pkcs1.len() + 64) + 16;
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: peak + pkcs1.len() / 2,
        ..ResourcePolicy::default()
    };
    import(text.as_bytes(), PrivateKeyContainer::Pem, None, &resources)
        .expect("the live buffers fit the budget");
}

#[test]
fn the_single_resource_limit_holds_one_normalized_dsa_document() {
    // DSA normalization holds the PKCS#8 document and its copy at once: the
    // aggregate budget counts both, the single-resource limit each one, so a
    // limit with room for one document admits the key.
    let block = BorrowedPem::parse(DSA_ENCRYPTED, usize::MAX).expect("the fixture PEM");
    let traditional = decode_pem(
        &block,
        Some(b"legacy-dsa-password"),
        DSA_ENCRYPTED.len(),
        &ResourcePolicy::default(),
    )
    .expect("the fixture password decrypts the DSA key");
    let der = traditional.der.as_slice();
    let resources = ResourcePolicy {
        max_external_resource_bytes: der.len() + PKCS8_DSA_FRAMING,
        ..ResourcePolicy::default()
    };
    import(der, PrivateKeyContainer::Der, None, &resources)
        .expect("one normalized document fits the single-resource limit");
}

#[test]
fn damaged_or_unauthenticated_envelopes_stay_protected_failures() {
    // A damaged body and a body whose CBC padding is valid but whose DER is
    // not a key are both terminal for a candidate search.
    // A checkout may give the fixture CRLF line ends; the boundary between
    // the headers and the body is found on LF ones.
    let text = core::str::from_utf8(RSA_ENCRYPTED)
        .expect("PEM is ASCII")
        .replace("\r\n", "\n");
    let (headers, _) = text
        .split_once("\n\n")
        .expect("the envelope headers end with a blank line");
    let damaged = format!("{headers}\n\n!!!!\n-----END RSA PRIVATE KEY-----\n");
    let mut cases = vec![damaged];
    for tag in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"] {
        cases.push(encrypted_pem(tag, b"not ASN.1", b"secret"));
    }
    for case in cases {
        assert!(
            matches!(
                import(
                    case.as_bytes(),
                    PrivateKeyContainer::Pem,
                    Some(b"secret"),
                    &ResourcePolicy::default()
                ),
                Err(KeyStoreError::ProtectedContainer)
            ),
            "{case}"
        );
    }
}

#[test]
fn oversized_rsa_in_the_envelope_reports_the_safety_limit() {
    // A key that decrypts but exceeds the RSA ceiling is reported as such,
    // not as a password failure.
    let pkcs8 = pem::parse(RSA_PKCS8)
        .expect("the private key fixture")
        .into_contents();
    let info = PrivateKeyInfoRef::try_from(pkcs8.as_slice()).expect("fixture PKCS#8");
    let mut key =
        pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).expect("fixture PKCS#1");
    let oversized = vec![1_u8; 1025];
    key.modulus = UintRef::new(&oversized).expect("a positive integer");
    let pkcs1 = key.to_der().expect("PKCS#1 encoding");
    let protected = encrypted_pem("RSA PRIVATE KEY", &pkcs1, b"secret");
    assert!(matches!(
        import(
            protected.as_bytes(),
            PrivateKeyContainer::Pem,
            Some(b"secret"),
            &ResourcePolicy::default()
        ),
        Err(KeyStoreError::Selection("RSA modulus exceeds safety limit"))
    ));
}

#[test]
fn sec1_keys_import_from_pem_der_and_the_envelope() {
    // SEC1 keys, with or without curve parameters, become PKCS#8 with the
    // named curve the key validates on.
    let key = p256::SecretKey::from_slice(&[0x11; 32]).expect("a scalar below the order");
    let der = key.to_sec1_der().expect("SEC1 encoding");
    let resources = ResourcePolicy::default();
    for (bytes, container, password) in [
        (der.to_vec(), PrivateKeyContainer::Der, None),
        (
            plain_pem("EC PRIVATE KEY", &der).into_bytes(),
            PrivateKeyContainer::Pem,
            None,
        ),
        (
            encrypted_pem("EC PRIVATE KEY", &der, b"secret").into_bytes(),
            PrivateKeyContainer::Pem,
            Some(b"secret".as_slice()),
        ),
    ] {
        let inventory =
            import(&bytes, container, password, &resources).expect("the SEC1 key imports");
        let pkcs8 = inventory.private_keys()[0].pkcs8_der();
        assert_eq!(
            p256::SecretKey::from_pkcs8_der(pkcs8)
                .expect("PKCS#8 of the P-256 key")
                .to_bytes(),
            key.to_bytes()
        );
    }
}

#[test]
fn pkcs8_containers_accept_nothing_else() {
    // The PKCS#8 forms refuse traditional keys; the generic forms read both,
    // and an RSA label never carries PKCS#8.
    let resources = ResourcePolicy::default();
    let traditional = import(
        RSA_ENCRYPTED,
        PrivateKeyContainer::Pkcs8Pem,
        Some(b"legacy-rsa-password"),
        &resources,
    );
    assert!(matches!(traditional, unsupported!()));
    import(RSA_PKCS8, PrivateKeyContainer::Pkcs8Pem, None, &resources)
        .expect("PKCS#8 PEM is a PKCS#8 container");
    import(RSA_PKCS8, PrivateKeyContainer::Pem, None, &resources)
        .expect("generic PEM reads PKCS#8");
    let pkcs8 = pem::parse(RSA_PKCS8)
        .expect("the private key fixture")
        .into_contents();
    import(&pkcs8, PrivateKeyContainer::Pkcs8Der, None, &resources)
        .expect("PKCS#8 DER is a PKCS#8 container");
    let mislabeled = plain_pem("RSA PRIVATE KEY", &pkcs8);
    assert!(matches!(
        import(
            mislabeled.as_bytes(),
            PrivateKeyContainer::Pem,
            None,
            &resources
        ),
        unsupported!()
    ));
}

/// The traditional DER of the DSA fixture.
fn dsa_der() -> Zeroizing<Vec<u8>> {
    let block = pem::parse(DSA_ENCRYPTED).expect("the DSA fixture");
    let (cipher, iv) = block
        .headers()
        .get("DEK-Info")
        .and_then(|value| value.split_once(','))
        .expect("the envelope header");
    Cipher::named(cipher)
        .expect("a known cipher")
        .decrypt(
            &decode_hex(iv).expect("a hex IV"),
            Zeroizing::new(block.into_contents()),
            b"legacy-dsa-password",
        )
        .expect("the fixture password decrypts the key")
}

#[test]
fn a_dsa_generator_shorter_than_the_modulus_is_refused() {
    // A generator encoded in fewer octets than p reaches the g^x check at
    // p's precision; it does not match the stored public key and is refused
    // as an error, not a panic.
    let resources = ResourcePolicy::default();
    let der = dsa_der();
    normalize_dsa(&der, &resources, 0)
        .expect("the fixture normalizes")
        .expect("the fixture is a DSA key");
    let key = TraditionalDsaPrivateKey::from_der(&der).expect("a DSA key");
    let short = TraditionalDsaPrivateKey {
        g: UintRef::new(&[2]).expect("a positive integer"),
        ..key
    }
    .to_der()
    .expect("the key encodes");
    assert!(matches!(
        normalize_dsa(&short, &resources, 0),
        unsupported!()
    ));
}
