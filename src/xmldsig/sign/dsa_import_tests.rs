use super::*;
use der::{Decode, Encode};

fn plaintext() -> pkcs8::SecretDocument {
    pkcs8::EncryptedPrivateKeyInfoRef::from_der(include_bytes!(
        "../../../tests/fixtures/xmldsig/keys/dsa/dsa-2048-key.p8-der"
    ))
    .expect("valid encrypted DSA fixture")
    .decrypt(b"secret123")
    .expect("known fixture password")
}

#[test]
fn dsa_plain_pem_reports_the_failing_format_layer() -> Result<(), Box<dyn std::error::Error>> {
    // PEM syntax, block labels and decoded DER are distinct public errors;
    // checked DSA decoding must not collapse the PEM-layer diagnostics.
    assert!(matches!(
        DsaSigningKey::from_pkcs8_pem("invalid PEM"),
        Err(SigningKeyError::InvalidKeyPem)
    ));
    let wrong_label = pem::encode(&pem::Pem::new("PUBLIC KEY", vec![1, 2, 3]));
    assert!(matches!(
        DsaSigningKey::from_pkcs8_pem(&wrong_label),
        Err(SigningKeyError::InvalidKeyFormat { label }) if label == "PUBLIC KEY"
    ));
    let bad_der = pem::encode(&pem::Pem::new("PRIVATE KEY", vec![1, 2, 3]));
    assert!(matches!(
        DsaSigningKey::from_pkcs8_pem(&bad_der),
        Err(SigningKeyError::InvalidKeyDer)
    ));
    let valid = plaintext().to_pem("PRIVATE KEY", der::pem::LineEnding::LF)?;
    assert!(DsaSigningKey::from_pkcs8_pem(&valid).is_ok());
    assert!(matches!(
        DsaSigningKey::from_pkcs8_pem(&format!("{}unexpected trailing data", valid.as_str())),
        Err(SigningKeyError::InvalidKeyPem)
    ));
    Ok(())
}

#[test]
fn dsa_pkcs8_import_formats_and_password_failures() -> Result<(), Box<dyn std::error::Error>> {
    // All public constructors converge on the same checked native decoder;
    // a wrong password or label cannot select a more permissive path.
    let plain = plaintext();
    let pem = plain.to_pem("PRIVATE KEY", der::pem::LineEnding::LF)?;
    let encrypted = include_bytes!("../../../tests/fixtures/xmldsig/keys/dsa/dsa-2048-key.p8-der");
    let encrypted_doc = pkcs8::SecretDocument::try_from(encrypted.as_slice())?;
    let encrypted_pem = encrypted_doc.to_pem("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF)?;
    let key = DsaSigningKey::from_pkcs8_der(plain.as_bytes())?;
    let expected = key.public_key_info()?;
    for imported in [
        DsaSigningKey::from_pkcs8_pem(&pem)?,
        DsaSigningKey::from_pkcs8_encrypted_der(encrypted, b"secret123")?,
        DsaSigningKey::from_pkcs8_encrypted_pem(&encrypted_pem, b"secret123")?,
    ] {
        assert_eq!(imported.public_key_info()?, expected);
    }
    assert!(DsaSigningKey::from_pkcs8_encrypted_der(encrypted, b"wrong").is_err());
    assert!(DsaSigningKey::from_pkcs8_encrypted_pem(&encrypted_pem, b"wrong").is_err());
    assert!(DsaSigningKey::from_pkcs8_encrypted_pem(&pem, b"secret123").is_err());
    assert!(DsaSigningKey::from_pkcs8_pem(&encrypted_pem).is_err());
    assert!(DsaSigningKey::from_pkcs8_pem("invalid PEM").is_err());
    assert!(DsaSigningKey::from_pkcs8_der(b"invalid DER").is_err());
    Ok(())
}

#[test]
fn dsa_preflight_bounds_every_private_key_component() -> Result<(), Box<dyn std::error::Error>> {
    // Oversized p/q/g/x/publicKey must be rejected by borrowed preflight,
    // independently of whether the downstream crypto decoder would reject it.
    let plain = plaintext();
    let original = pkcs8::PrivateKeyInfoRef::from_der(plain.as_bytes())?;
    let oversized = vec![0x7f; crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING + 1];
    let large = der::asn1::UintRef::new(&oversized)?;
    for field in 0..5 {
        let mut parameters = original
            .algorithm
            .parameters
            .as_ref()
            .expect("DSA fixture parameters")
            .decode_as::<super::super::signature::BorrowedDsaPublicParameters<'_>>()?;
        match field {
            0 => parameters.p = large,
            1 => parameters.q = large,
            2 => parameters.g = large,
            _ => {}
        }
        let encoded_parameters = parameters.to_der()?;
        let encoded_large = large.to_der()?;
        let mut info = original.clone();
        info.algorithm.parameters = Some(der::asn1::AnyRef::from_der(&encoded_parameters)?);
        if field == 3 {
            info.private_key = der::asn1::OctetStringRef::new(&encoded_large)?;
        }
        if field == 4 {
            info.public_key = Some(der::asn1::BitStringRef::new(0, &encoded_large)?);
        }
        assert!(preflight_dsa_private_key(&info).is_err(), "field {field}");
        assert!(
            DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err(),
            "field {field}"
        );
    }
    Ok(())
}

#[test]
fn accepts_dsa_pkcs8_with_consistent_public_component() -> Result<(), Box<dyn std::error::Error>> {
    // The optional RFC 5958 publicKey is legal: consistency validation
    // must not reject a correctly bound OneAsymmetricKey.
    let plain = plaintext();
    let key = DsaSigningKey::from_pkcs8_der(plain.as_bytes())?;
    let SigningPublicKeyInfo::Dsa { spki_der, .. } = key.public_key_info()? else {
        panic!("DSA key")
    };
    let spki = pkcs8::SubjectPublicKeyInfoRef::from_der(&spki_der)?;
    let mut info = pkcs8::PrivateKeyInfoRef::from_der(plain.as_bytes())?;
    info.public_key = Some(spki.subject_public_key);
    let encoded = info.to_der()?;
    assert_eq!(
        DsaSigningKey::from_pkcs8_der(&encoded)?.public_key_info()?,
        key.public_key_info()?
    );
    // Inventory identity matching must accept the same bound public component.
    crate::key_manager::KeyInventory::default().add_private_der(
        "consistent-dsa".into(),
        &encoded,
        None,
        crate::key_manager::KeyUsages::SIGN,
        &crate::policy::ResourcePolicy::default(),
    )?;
    Ok(())
}

#[test]
fn rejects_invalid_dsa_private_exponents_and_parameters() -> Result<(), Box<dyn std::error::Error>>
{
    // Zero and x >= q are not DSA private keys. Malformed parameters,
    // missing parameters and unrelated algorithm OIDs must fail import.
    let plain = plaintext();
    let original = pkcs8::PrivateKeyInfoRef::from_der(plain.as_bytes())?;
    let parameters = original
        .algorithm
        .parameters
        .as_ref()
        .expect("DSA fixture parameters")
        .decode_as::<super::super::signature::BorrowedDsaPublicParameters<'_>>()?;
    for exponent in [der::asn1::UintRef::new(&[0])?, parameters.q] {
        let encoded = exponent.to_der()?;
        let mut info = original.clone();
        info.private_key = der::asn1::OctetStringRef::new(&encoded)?;
        assert!(DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err());
    }
    let mut info = original.clone();
    info.algorithm.parameters = None;
    assert!(DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err());
    // An INTEGER cannot substitute for the Dss-Parms SEQUENCE.
    let mut info = original.clone();
    info.algorithm.parameters = Some(der::asn1::AnyRef::from_der(&[0x02, 0x01, 0x01])?);
    assert!(DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err());
    // DSA publicKey encodes a complete DER INTEGER, not partial bits.
    let mut info = original.clone();
    info.public_key = Some(der::asn1::BitStringRef::new(1, &[0x02])?);
    assert!(DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err());
    let mut info = original;
    info.algorithm.oid = pkcs1::ALGORITHM_OID;
    assert!(DsaSigningKey::from_pkcs8_der(&info.to_der()?).is_err());
    Ok(())
}

#[test]
fn rejects_dsa_pkcs8_with_inconsistent_public_component() -> Result<(), Box<dyn std::error::Error>>
{
    // RFC 5958 section 2 binds publicKey to the privateKey. A valid
    // subgroup element belonging to a different key must not be accepted.
    let plain = plaintext();
    let mut info = pkcs8::PrivateKeyInfoRef::from_der(plain.as_bytes())?;
    let parameters = info
        .algorithm
        .parameters
        .as_ref()
        .expect("DSA fixture parameters")
        .decode_as::<super::super::signature::BorrowedDsaPublicParameters<'_>>()?;
    let wrong_public = parameters.g.to_der()?;
    info.public_key = Some(der::asn1::BitStringRef::new(0, &wrong_public)?);
    let encoded = info.to_der()?;
    assert!(matches!(
        DsaSigningKey::from_pkcs8_der(&encoded),
        Err(SigningKeyError::InvalidKeyDer)
    ));
    // The key-manager public import cannot trust a different y either.
    assert!(matches!(
        crate::key_manager::KeyInventory::default().add_private_der(
            "inconsistent-dsa".into(),
            &encoded,
            None,
            crate::key_manager::KeyUsages::SIGN,
            &crate::policy::ResourcePolicy::default(),
        ),
        Err(crate::key_manager::KeyStoreError::Selection(
            "invalid or oversized DSA private key"
        ))
    ));
    Ok(())
}
