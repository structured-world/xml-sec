use super::*;

#[test]
fn cli_loads_every_eddsa_variant_from_donor_pkcs8() {
    // Plain and protected imports must resolve the same modern key family;
    // this test covers the plain CLI branch, not only inventory loading.
    for (algorithm, stem) in [
        (SignatureAlgorithm::Ed25519, "ed25519"),
        (SignatureAlgorithm::Ed25519Ctx, "ed25519"),
        (SignatureAlgorithm::Ed25519Ph, "ed25519"),
        (SignatureAlgorithm::Ed448, "ed448"),
        (SignatureAlgorithm::Ed448Ph, "ed448"),
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(format!(
                "tests/fixtures/xmldsig/keys/eddsa/eddsa-{stem}-key.der"
            ));
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            decode_signing_key(&path, &bytes, PrivateKeyFormat::Pkcs8Der, algorithm, None).is_ok(),
            "{algorithm:?}"
        );
        assert!(
            decode_signing_key(
                &path,
                &bytes[..bytes.len() - 1],
                PrivateKeyFormat::Pkcs8Der,
                algorithm,
                None
            )
            .is_err()
        );
    }
}
