use std::cell::Cell;
use xml_sec::provider::CryptoProvider;
use xml_sec::xmldsig::{DsigError, SignatureAlgorithm, VerifyingKey};

pub fn assert_provider_candidate_limits(provider: &dyn CryptoProvider) {
    // A recovering composite cannot bypass the primitive's aggregate ceiling;
    // a deep composite must refuse before reaching an unchecked leaf.
    struct Flat;
    impl VerifyingKey for Flat {
        fn verify_candidate_keys(
            &self,
            visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
        ) -> Result<Option<bool>, DsigError> {
            for _ in 0..128 {
                let _ = visitor(&Leaf);
            }
            Ok(Some(true))
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            panic!("container is not a leaf")
        }
    }
    struct Leaf;
    impl VerifyingKey for Leaf {
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            Ok(false)
        }
    }
    struct Deep<'a>(usize, &'a Cell<usize>);
    impl VerifyingKey for Deep<'_> {
        fn verify_candidate_keys(
            &self,
            visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
        ) -> Result<Option<bool>, DsigError> {
            if self.0 == 0 {
                self.1.set(self.1.get() + 1);
                return Ok(None);
            }
            visitor(&Deep(self.0 - 1, self.1)).map(Some)
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            Ok(false)
        }
    }
    let reached = Cell::new(0);
    for key in [&Flat as &dyn VerifyingKey, &Deep(128, &reached)] {
        assert!(matches!(
            provider.verify(key, SignatureAlgorithm::RsaSha256, &[], &[]),
            Err(DsigError::SharedExecution(
                structured_asn1::memory::MemoryError::WorkExceeded
            ))
        ));
    }
    assert_eq!(reached.get(), 0);
}
