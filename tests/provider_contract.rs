#![cfg(all(feature = "xmldsig", feature = "xmlenc"))]

use std::{borrow::Cow, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use xml_sec::{
    provider::{
        CryptoProvider, KeyRecoveryKey, KeyTransportKey, ProviderCapability, ProviderError,
        ProviderOperation, RustCryptoProvider,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, EncryptedDataBuilder, KeyWrapAlgorithm,
        PrivateKeyDecryptor, RsaOaepParameters, XmlEncError,
    },
};

struct ExternalPublicKey;

impl KeyTransportKey for ExternalPublicKey {
    fn rsa_modulus(&self) -> Cow<'_, [u8]> {
        Cow::Owned(vec![0x80; 256])
    }

    fn rsa_exponent(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&[0x01, 0x00, 0x01])
    }

    fn transport_with_provider(
        &self,
        _provider: &dyn CryptoProvider,
        _parameters: &RsaOaepParameters,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        panic!("the external provider owns this key operation")
    }
}

struct ExternalPrivateKey;

impl KeyRecoveryKey for ExternalPrivateKey {
    fn ciphertext_len(&self) -> usize {
        256
    }

    fn recover_with_provider(
        &self,
        _provider: &dyn CryptoProvider,
        _parameters: &RsaOaepParameters,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        panic!("the external provider owns this key operation")
    }
}

struct ExternalProvider {
    reject_decrypt: bool,
    reject_transport: bool,
}

impl ExternalProvider {
    const FULL: Self = Self {
        reject_decrypt: false,
        reject_transport: false,
    };
    const RECOVERY_ONLY: Self = Self {
        reject_decrypt: false,
        reject_transport: true,
    };
    const REFUSES_DECRYPT: Self = Self {
        reject_decrypt: true,
        reject_transport: true,
    };
}

impl CryptoProvider for ExternalProvider {
    fn name(&self) -> &'static str {
        "external-test-provider"
    }

    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        if self.reject_decrypt && matches!(capability, ProviderCapability::Decrypt(_)) {
            return false;
        }
        if self.reject_transport && matches!(capability, ProviderCapability::KeyTransport(_)) {
            return false;
        }
        RustCryptoProvider.supports(capability)
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        RustCryptoProvider.fill_random(output)
    }

    fn derive_key(
        &self,
        parameters: &xml_sec::provider::KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.derive_key(parameters, secret)
    }

    fn digest(
        &self,
        algorithm: xml_sec::xmldsig::DigestAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.digest(algorithm, data)
    }

    fn sign(
        &self,
        key: &dyn xml_sec::xmldsig::SigningKey,
        algorithm: xml_sec::xmldsig::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
        RustCryptoProvider.sign(key, algorithm, data)
    }

    fn verify(
        &self,
        key: &dyn xml_sec::xmldsig::VerifyingKey,
        algorithm: xml_sec::xmldsig::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, xml_sec::xmldsig::DsigError> {
        RustCryptoProvider.verify(key, algorithm, data, signature)
    }

    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.encrypt_data(algorithm, key, plaintext)
    }

    fn decrypt_data(
        &self,
        _algorithm: DataEncryptionAlgorithm,
        _key: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        assert!(!self.reject_decrypt, "refused decryption was dispatched");
        Ok(b"external plaintext".to_vec())
    }

    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.wrap_key(algorithm, kek, key)
    }

    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.unwrap_key(algorithm, kek, wrapped)
    }

    fn transport_key(
        &self,
        _key: &dyn KeyTransportKey,
        parameters: &RsaOaepParameters,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        assert!(self.supports(ProviderCapability::KeyTransport(parameters)));
        Ok(vec![0xa5; 256])
    }

    fn recover_key(
        &self,
        _key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        assert!(self.supports(ProviderCapability::KeyRecovery(parameters)));
        Ok(vec![0x42; 16])
    }
}

#[test]
fn opaque_provider_keys_cross_the_public_encrypt_and_decrypt_pipelines() {
    // A provider-specific public handle reaches transport without exposing a
    // concrete backend key type to the encryption builder.
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .provider(Arc::new(ExternalProvider::FULL))
        .recipient_key_transport(Arc::new(ExternalPublicKey))
        .encrypt_binary(b"provider contract")
        .expect("external transport provider must produce EncryptedData");
    assert!(encrypted.encrypted_data_xml.contains("rsa-oaep"));

    // The reciprocal public resolver exposes only RSA ciphertext width. The
    // custom provider recovers the content key and decrypts without accessing
    // private key material through RustCrypto.
    let xml = external_encrypted_xml();
    let resolver = PrivateKeyDecryptor::provider_key(Arc::new(ExternalPrivateKey));
    let decrypted = DecryptContext::new(&resolver)
        .provider(&ExternalProvider::RECOVERY_ONLY)
        .decrypt(&xml)
        .expect("external recovery and content decryption must complete");
    assert_eq!(
        decrypted,
        xml_sec::xmlenc::DecryptedContent::Bytes(b"external plaintext".to_vec())
    );
}

#[test]
fn refused_public_capability_fails_before_provider_dispatch() {
    // A provider's capability declaration is authoritative. The facade must
    // return the typed refusal without invoking the corresponding operation.
    let resolver = PrivateKeyDecryptor::provider_key(Arc::new(ExternalPrivateKey));
    let error = DecryptContext::new(&resolver)
        .provider(&ExternalProvider::REFUSES_DECRYPT)
        .decrypt(&external_encrypted_xml())
        .expect_err("refused decryption capability must fail closed");

    assert!(matches!(
        error,
        XmlEncError::Provider(ProviderError::Unsupported {
            operation: ProviderOperation::Decrypt,
            ..
        })
    ));
}

fn external_encrypted_xml() -> String {
    let wrapped = STANDARD.encode(vec![0xa5; 256]);
    let ciphertext = STANDARD.encode(vec![0x5a; 46]);
    format!(
        r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
             xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"
             xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
          <ds:KeyInfo><xenc:EncryptedKey>
            <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>
            </xenc:EncryptionMethod>
            <xenc:CipherData><xenc:CipherValue>{wrapped}</xenc:CipherValue></xenc:CipherData>
          </xenc:EncryptedKey></ds:KeyInfo>
          <xenc:CipherData><xenc:CipherValue>{ciphertext}</xenc:CipherValue></xenc:CipherData>
        </xenc:EncryptedData>"#
    )
}
