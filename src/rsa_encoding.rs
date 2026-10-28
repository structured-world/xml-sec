//! RSA container codecs for the existing `sad-rsa` key types.
//!
//! Only serialization lives here; RSA operations, validation and blinding stay
//! in `sad-rsa`. Adapted from sadco-io/sad-rsa 0.10.2, src/encoding.rs,
//! licensed MIT OR Apache-2.0, copyright its original contributors.

// Copyright (c) 2025-2026 Sadco Security Team
// Copyright (c) 2015-2025 RustCrypto Developers
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use alloc::string::String;
#[cfg(feature = "xmldsig-sign")]
use alloc::vec;
use crypto_bigint::BoxedUint;
#[cfg(feature = "xmldsig-sign")]
use crypto_bigint::{NonZero, Resize};
use pkcs8::{
    Document,
    der::{
        Decode,
        pem::{LineEnding, PemLabel},
    },
};
#[cfg(feature = "xmldsig-sign")]
use pkcs8::{SecretDocument, der::asn1::OctetStringRef};
#[cfg(feature = "xmldsig-sign")]
use rsa::{RsaPrivateKey, traits::PrivateKeyParts};
use rsa::{RsaPublicKey, traits::PublicKeyParts};
#[cfg(feature = "xmldsig-sign")]
use zeroize::Zeroizing;

/// PKCS#1 and PKCS#8 codecs without enabling the RSA dependency's codecs.
#[cfg(feature = "xmldsig-sign")]
pub trait RsaPrivateKeyEncoding: Sized {
    /// Decode a two-prime PKCS#1 key and validate it with `sad-rsa`.
    ///
    /// # Errors
    /// Returns DER decoding errors, an unsupported multiprime version, invalid
    /// integer widths or RSA component-validation failures.
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self>;
    /// Encode a borrowed key as PKCS#1 in a zeroizing document.
    ///
    /// # Errors
    /// Returns an unsupported prime count, unavailable CRT coefficient or
    /// integer/DER encoding failure.
    fn to_pkcs1_der(&self) -> pkcs1::Result<SecretDocument>;
    /// Decode a PKCS#8 key with a validated algorithm identifier.
    ///
    /// # Errors
    /// Returns a malformed container, unsupported algorithm identifier or
    /// parameters, or invalid embedded RSA private key.
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self>;
    /// Encode a borrowed key as PKCS#8 in a zeroizing document.
    ///
    /// # Errors
    /// Propagates private-key encoding failures and DER container errors.
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument>;
    /// Decode a correctly labeled PKCS#1 PEM key.
    ///
    /// # Errors
    /// Returns malformed PEM/base64, an incorrect label or the PKCS#1 decoder's error.
    fn from_pkcs1_pem(pem: &str) -> pkcs1::Result<Self> {
        let (label, doc) = SecretDocument::from_pem(pem)?;
        pkcs1::RsaPrivateKeyRef::validate_pem_label(label)?;
        Self::from_pkcs1_der(doc.as_bytes())
    }
    /// Encode a PKCS#1 PEM key with explicit line endings.
    ///
    /// # Errors
    /// Propagates private-key DER encoding and PEM serialization errors.
    fn to_pkcs1_pem(&self, ending: LineEnding) -> pkcs1::Result<Zeroizing<String>> {
        Ok(self
            .to_pkcs1_der()?
            .to_pem(pkcs1::RsaPrivateKeyRef::PEM_LABEL, ending)?)
    }
    /// Decode a correctly labeled PKCS#8 PEM key.
    ///
    /// # Errors
    /// Returns malformed PEM/base64, an incorrect label or the PKCS#8 decoder's error.
    fn from_pkcs8_pem(pem: &str) -> pkcs8::Result<Self> {
        let (label, doc) = SecretDocument::from_pem(pem)?;
        pkcs8::PrivateKeyInfoRef::validate_pem_label(label)?;
        Self::from_pkcs8_der(doc.as_bytes())
    }
    /// Encode a PKCS#8 PEM key with explicit line endings.
    ///
    /// # Errors
    /// Propagates private-key/container encoding and PEM serialization errors.
    fn to_pkcs8_pem(&self, ending: LineEnding) -> pkcs8::Result<Zeroizing<String>> {
        Ok(self
            .to_pkcs8_der()?
            .to_pem(pkcs8::PrivateKeyInfoRef::PEM_LABEL, ending)?)
    }
    /// Decrypt a protected PKCS#8 container before parsing its key.
    ///
    /// # Errors
    /// Returns malformed or unsupported protection parameters, decryption
    /// failure (including a wrong password), or invalid decrypted PKCS#8 key material.
    fn from_pkcs8_encrypted_der(bytes: &[u8], password: impl AsRef<[u8]>) -> pkcs8::Result<Self> {
        let plaintext = pkcs8::EncryptedPrivateKeyInfoRef::try_from(bytes)?.decrypt(password)?;
        Self::from_pkcs8_der(plaintext.as_bytes())
    }
    /// Decode and decrypt a correctly labeled protected PKCS#8 PEM key.
    ///
    /// # Errors
    /// Returns malformed PEM/base64, an incorrect label or the encrypted-DER
    /// decoder's protection, password or key-material error.
    fn from_pkcs8_encrypted_pem(pem: &str, password: impl AsRef<[u8]>) -> pkcs8::Result<Self> {
        let (label, doc) = SecretDocument::from_pem(pem)?;
        pkcs8::EncryptedPrivateKeyInfoRef::validate_pem_label(label)?;
        Self::from_pkcs8_encrypted_der(doc.as_bytes(), password)
    }
}

/// PKCS#1 and `SubjectPublicKeyInfo` codecs for the existing RSA public key.
pub trait RsaPublicKeyEncoding: Sized {
    /// Decode and validate a PKCS#1 public key.
    ///
    /// # Errors
    /// Returns DER decoding, integer-width or RSA public-component validation errors.
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self>;
    /// Encode a borrowed public key as PKCS#1.
    ///
    /// # Errors
    /// Returns integer or DER document encoding errors.
    fn to_pkcs1_der(&self) -> pkcs1::Result<Document>;
    /// Decode a `SubjectPublicKeyInfo` with a validated algorithm identifier.
    ///
    /// # Errors
    /// Returns invalid DER/bit-string framing, unsupported algorithm parameters
    /// or invalid embedded RSA public components.
    fn from_public_key_der(bytes: &[u8]) -> pkcs8::spki::Result<Self>;
    /// Encode a borrowed public key as `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// Propagates RSA public-key and SPKI container encoding failures.
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document>;
    /// Decode a correctly labeled PKCS#1 PEM public key.
    ///
    /// # Errors
    /// Returns malformed PEM/base64, an incorrect label or the PKCS#1 decoder's error.
    fn from_pkcs1_pem(pem: &str) -> pkcs1::Result<Self> {
        let (label, doc) = Document::from_pem(pem)?;
        pkcs1::RsaPublicKeyRef::validate_pem_label(label)?;
        Self::from_pkcs1_der(doc.as_bytes())
    }
    /// Encode a PKCS#1 public PEM key with explicit line endings.
    ///
    /// # Errors
    /// Propagates public-key DER encoding and PEM serialization errors.
    fn to_pkcs1_pem(&self, ending: LineEnding) -> pkcs1::Result<String> {
        Ok(self
            .to_pkcs1_der()?
            .to_pem(pkcs1::RsaPublicKeyRef::PEM_LABEL, ending)?)
    }
    /// Decode a correctly labeled public-key PEM container.
    ///
    /// # Errors
    /// Returns malformed PEM/base64, an incorrect label or the SPKI decoder's error.
    fn from_public_key_pem(pem: &str) -> pkcs8::spki::Result<Self> {
        let (label, doc) = Document::from_pem(pem)?;
        pkcs8::SubjectPublicKeyInfoRef::validate_pem_label(label)?;
        Self::from_public_key_der(doc.as_bytes())
    }
    /// Encode a public-key PEM container with explicit line endings.
    ///
    /// # Errors
    /// Propagates SPKI container encoding and PEM serialization errors.
    fn to_public_key_pem(&self, ending: LineEnding) -> pkcs8::spki::Result<String> {
        Ok(self
            .to_public_key_der()?
            .to_pem(pkcs8::SubjectPublicKeyInfoRef::PEM_LABEL, ending)?)
    }
}

fn uint(data: &[u8], bits: u32) -> pkcs1::Result<BoxedUint> {
    BoxedUint::from_be_slice(data, bits).map_err(|_| pkcs1::Error::KeyMalformed)
}

fn width(data: &[u8]) -> pkcs1::Result<u32> {
    u32::try_from(data.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(pkcs1::Error::KeyMalformed)
}

#[cfg(feature = "xmldsig-sign")]
impl RsaPrivateKeyEncoding for RsaPrivateKey {
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self> {
        let key = pkcs1::RsaPrivateKeyRef::from_der(bytes)?;
        if key.version() != pkcs1::Version::TwoPrime {
            return Err(pkcs1::Error::Version);
        }
        let bits = width(key.modulus.as_bytes())?;
        // All private fields must fit the existing decoder's modulus-width
        // integers. Reject before constructing any secret bigint workspace.
        for component in [key.private_exponent, key.prime1, key.prime2] {
            if component.as_bytes().len() > key.modulus.as_bytes().len() {
                return Err(pkcs1::Error::KeyMalformed);
            }
        }
        let n = uint(key.modulus.as_bytes(), bits)?;
        let e = uint(
            key.public_exponent.as_bytes(),
            width(key.public_exponent.as_bytes())?,
        )?;
        let d = uint(key.private_exponent.as_bytes(), bits)?;
        let primes = vec![
            uint(key.prime1.as_bytes(), bits)?,
            uint(key.prime2.as_bytes(), bits)?,
        ];
        Self::from_components(n, e, d, primes).map_err(|_| pkcs1::Error::KeyMalformed)
    }

    fn to_pkcs1_der(&self) -> pkcs1::Result<SecretDocument> {
        if self.primes().len() != 2 {
            return Err(pkcs1::Error::Crypto);
        }
        let modulus = self.n().to_be_bytes();
        let public_exponent = self.e().to_be_bytes();
        let private_exponent = Zeroizing::new(self.d().to_be_bytes());
        let prime1 = Zeroizing::new(self.primes()[0].to_be_bytes());
        let prime2 = Zeroizing::new(self.primes()[1].to_be_bytes());
        let bits = self.d().bits_precision();
        let exponent1 = Zeroizing::new(
            (self.d()
                % NonZero::new((&self.primes()[0]).resize_unchecked(bits) - &BoxedUint::one())
                    .unwrap())
            .to_be_bytes(),
        );
        let exponent2 = Zeroizing::new(
            (self.d()
                % NonZero::new((&self.primes()[1]).resize_unchecked(bits) - &BoxedUint::one())
                    .unwrap())
            .to_be_bytes(),
        );
        let coefficient = Zeroizing::new(
            self.crt_coefficient()
                .ok_or(pkcs1::Error::Crypto)?
                .to_be_bytes(),
        );
        Ok(SecretDocument::encode_msg(&pkcs1::RsaPrivateKeyRef {
            modulus: pkcs1::UintRef::new(&modulus)?,
            public_exponent: pkcs1::UintRef::new(&public_exponent)?,
            private_exponent: pkcs1::UintRef::new(&private_exponent)?,
            prime1: pkcs1::UintRef::new(&prime1)?,
            prime2: pkcs1::UintRef::new(&prime2)?,
            exponent1: pkcs1::UintRef::new(&exponent1)?,
            exponent2: pkcs1::UintRef::new(&exponent2)?,
            coefficient: pkcs1::UintRef::new(&coefficient)?,
            other_prime_infos: None,
        })?)
    }

    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(bytes)?;
        verify_algorithm_id(&info.algorithm)?;
        Self::from_pkcs1_der(info.private_key.as_bytes()).map_err(private_error)
    }

    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let key = self.to_pkcs1_der().map_err(private_error)?;
        pkcs8::PrivateKeyInfoRef::new(pkcs1::ALGORITHM_ID, OctetStringRef::new(key.as_bytes())?)
            .try_into()
    }
}

impl RsaPublicKeyEncoding for RsaPublicKey {
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self> {
        let key = pkcs1::RsaPublicKeyRef::from_der(bytes)?;
        let n = uint(key.modulus.as_bytes(), width(key.modulus.as_bytes())?)?;
        let e = uint(
            key.public_exponent.as_bytes(),
            width(key.public_exponent.as_bytes())?,
        )?;
        Self::new(n, e).map_err(|_| pkcs1::Error::KeyMalformed)
    }

    fn to_pkcs1_der(&self) -> pkcs1::Result<Document> {
        let modulus = self.n().to_be_bytes();
        let exponent = self.e().to_be_bytes();
        Ok(Document::encode_msg(&pkcs1::RsaPublicKeyRef {
            modulus: pkcs1::UintRef::new(&modulus)?,
            public_exponent: pkcs1::UintRef::new(&exponent)?,
        })?)
    }

    fn from_public_key_der(bytes: &[u8]) -> pkcs8::spki::Result<Self> {
        // A bare decoder belongs to no operation: it reads under its own
        // standalone hard-ceiling account.
        read_spki_public_key(
            &crate::xmldsig::pkix::CertificateSession::standalone(),
            bytes,
        )
        .ok()
        .flatten()
        .ok_or(pkcs8::spki::Error::KeyMalformed)
    }

    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        let key = self.to_pkcs1_der().map_err(public_error)?;
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs1::ALGORITHM_ID,
            subject_public_key: pkcs8::der::asn1::BitStringRef::new(0, key.as_bytes())?,
        }
        .try_into()
    }
}

/// The software RSA key of an SPKI read under `session`; `None` for another
/// algorithm, a refused identifier or malformed key material.
///
/// # Errors
/// The shared reader's resource refusal under `session`'s account.
pub(crate) fn read_spki_public_key(
    session: &crate::xmldsig::pkix::CertificateSession,
    bytes: &[u8],
) -> Result<Option<RsaPublicKey>, structured_pkix::Error> {
    // The shared PKIX reader owns SPKI and RSAPublicKey syntax.
    let Some(key) = session.admitted_rsa_public_key(bytes, |identifier, _| {
        let algorithm = identifier.algorithm();
        // RFC 3279 section 2.3.1: rsaEncryption parameters SHALL be NULL.
        // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1
        // RFC 4055 sections 1.2 and 3.1 allow absent PSS parameters.
        // https://www.rfc-editor.org/rfc/rfc4055#section-3.1
        // Preserve sad-rsa's parameter-unconstrained import contract;
        // explicit restrictions cannot be retained by its bare RSA type
        // and are therefore not silently discarded by this decoder.
        Ok(if algorithm == structured_pkix::oid::RSA_ENCRYPTION {
            identifier.has_null_parameter()
        } else {
            algorithm == structured_pkix::oid::RSASSA_PSS && identifier.has_no_parameters()
        })
    })?
    else {
        return Ok(None);
    };
    let modulus = key.modulus().as_bytes();
    let exponent = key.exponent().as_bytes();
    let integer = |bytes: &[u8]| width(bytes).and_then(|bits| uint(bytes, bits)).ok();
    let (Some(n), Some(e)) = (integer(modulus), integer(exponent)) else {
        return Ok(None);
    };
    Ok(RsaPublicKey::new(n, e).ok())
}

#[cfg(feature = "xmldsig-sign")]
fn verify_algorithm_id(algorithm: &pkcs8::AlgorithmIdentifierRef<'_>) -> pkcs8::spki::Result<()> {
    match algorithm.oid {
        pkcs1::ALGORITHM_OID => {
            // RFC 3279 section 2.3.1: rsaEncryption parameters SHALL be NULL.
            // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1
            if algorithm.parameters_any()? != pkcs8::der::asn1::Null.into() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        oid if oid == pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10") => {
            // RFC 4055 sections 1.2 and 3.1 allow absent PSS parameters.
            // https://www.rfc-editor.org/rfc/rfc4055#section-3.1
            // Preserve sad-rsa's parameter-unconstrained import contract;
            // explicit restrictions cannot be retained by its bare RSA type
            // and are therefore not silently discarded by this decoder.
            if algorithm.parameters.is_some() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        oid => return Err(pkcs8::spki::Error::OidUnknown { oid }),
    }
    Ok(())
}

#[cfg(feature = "xmldsig-sign")]
fn private_error(error: pkcs1::Error) -> pkcs8::Error {
    match error {
        pkcs1::Error::Asn1(error) => pkcs8::Error::Asn1(error),
        _ => pkcs8::Error::KeyMalformed(pkcs8::KeyError::Invalid),
    }
}

fn public_error(error: pkcs1::Error) -> pkcs8::spki::Error {
    match error {
        pkcs1::Error::Asn1(error) => pkcs8::spki::Error::Asn1(error),
        _ => pkcs8::spki::Error::KeyMalformed,
    }
}
