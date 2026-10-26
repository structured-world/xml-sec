use super::*;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};

#[test]
fn signs_non_byte_aligned_modulus_with_dependency_verification() {
    // Exercise our signing encoder at modBits == 1 mod 8 without relying
    // on sad-rsa's unrelated odd-width private DER exporter.
    let private = RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(2049), 2049)
        .expect("deterministic odd-width RSA key");
    let signature = sign(
        &super::super::RustCryptoProvider,
        &private,
        RsaPssParameters::DEFAULT,
        b"odd modulus",
    )
    .expect("odd-width PSS signing");
    let public = RsaPublicKey::from(&private);
    assert_eq!(signature.len(), 257);
    public
        .verify(
            rsa::Pss::<sha2::Sha256>::new(),
            &sha2::Sha256::digest(b"odd modulus"),
            &signature,
        )
        .expect("independent PSS verifier accepts odd-width signature");
}
