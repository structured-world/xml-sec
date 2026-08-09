//! X.509 certificate path and revocation validation.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::{
    certificate::X509Certificate, extensions::ParsedExtension, prelude::FromDer,
    revocation_list::CertificateRevocationList, time::ASN1Time, x509::AlgorithmIdentifier,
};

use super::{
    X509DataInfo,
    parse::{distinguished_names_equal, x509_name_to_rfc4514},
};
use crate::provider::X509SignatureAlgorithm;

/// Inputs controlling X.509 certificate-chain validation.
#[derive(Debug, Clone)]
pub struct X509ChainOptions<'a> {
    /// DER-encoded certificates accepted as trust anchors.
    pub trusted_certs: &'a [Vec<u8>],
    /// Time used for certificate, CRL, and revocation checks.
    pub verification_time: SystemTime,
    /// Maximum number of certificates in the validated path, including the anchor.
    pub max_chain_depth: usize,
    /// Whether parsed `<X509CRL>` entries are enforced.
    pub check_crls: bool,
}

/// Certificate-chain validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum X509ChainError {
    /// The selected cryptographic provider rejected path authentication.
    #[error("cryptographic provider rejected X.509 authentication: {0}")]
    Provider(#[from] crate::provider::ProviderError),
    /// The configured path limit cannot contain a certificate.
    #[error("maximum certificate chain depth must be greater than zero")]
    InvalidDepth,
    /// A certificate or CRL is malformed DER.
    #[error("invalid {kind} DER: {message}")]
    InvalidDer {
        /// Object type being parsed.
        kind: &'static str,
        /// Parser diagnostic.
        message: String,
    },
    /// The ordered embedded path cannot be completed to a configured anchor.
    #[error("certificate chain does not terminate at a trusted certificate")]
    UntrustedRoot,
    /// The path contains more certificates than allowed.
    #[error("certificate chain exceeds maximum depth of {0}")]
    DepthExceeded(usize),
    /// A certificate is outside its validity period.
    #[error("certificate at chain position {0} is expired or not yet valid")]
    CertificateNotValid(usize),
    /// An issuer certificate is not authorized to issue certificates.
    #[error("certificate at chain position {0} is not a CA")]
    IssuerNotCa(usize),
    /// A CA path-length constraint is violated.
    #[error("certificate at chain position {position} exceeds path length constraint {limit}")]
    PathLengthExceeded {
        /// Position of the constraining CA certificate.
        position: usize,
        /// Maximum permitted subordinate CA count.
        limit: u32,
    },
    /// A certificate key usage extension forbids the required operation.
    #[error("certificate at chain position {position} does not permit {required}")]
    InvalidKeyUsage {
        /// Position of the certificate in the validated path.
        position: usize,
        /// RFC 5280 key usage required for the operation.
        required: &'static str,
    },
    /// A certificate signature does not verify under its issuer key.
    #[error("certificate signature at chain position {0} is invalid or unsupported")]
    InvalidSignature(usize),
    /// The certificate or CRL declares an algorithm this build cannot verify.
    #[error("unsupported X.509 signature algorithm: {oid}")]
    UnsupportedSignatureAlgorithm {
        /// AlgorithmIdentifier object identifier.
        oid: String,
    },
    /// A CRL is not valid for the selected verification time or issuer.
    #[error("CRL {0} is invalid or cannot be authenticated")]
    InvalidCrl(usize),
    /// A path certificate was revoked by an applicable CRL.
    #[error("certificate at chain position {0} is revoked")]
    Revoked(usize),
}

/// Verify the ordered certificate path parsed from one `<X509Data>` element.
pub fn verify_x509_certificate_chain(
    info: &X509DataInfo,
    options: &X509ChainOptions<'_>,
) -> Result<(), X509ChainError> {
    verify_x509_certificate_chain_with_provider(info, options, crate::provider::default_provider())
}

pub(crate) fn verify_x509_certificate_chain_with_provider(
    info: &X509DataInfo,
    options: &X509ChainOptions<'_>,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<(), X509ChainError> {
    if options.max_chain_depth == 0 {
        return Err(X509ChainError::InvalidDepth);
    }
    if info.certificate_chain.is_empty() {
        return Err(X509ChainError::UntrustedRoot);
    }

    let path_der = info
        .certificate_chain
        .iter()
        .map(|&idx| {
            info.certificates
                .get(idx)
                .map(Vec::as_slice)
                .ok_or(X509ChainError::UntrustedRoot)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let last = parse_certificate(
        path_der
            .last()
            .copied()
            .ok_or(X509ChainError::UntrustedRoot)?,
    )?;
    let trusted_anchors = options
        .trusted_certs
        .iter()
        .map(|der| parse_certificate(der).map(|cert| (der.as_slice(), cert)))
        .collect::<Result<Vec<_>, _>>()?;
    let verification_time = system_time_to_asn1(options.verification_time)?;
    let embedded_anchor = trusted_anchors.iter().any(|(der, _)| *der == last.as_raw());
    if embedded_anchor {
        return validate_path(&path_der, info, options, verification_time, provider);
    }

    // Use the path-edge verifier here too: x509-parser does not verify legacy
    // DSA-SHA1 roots, while our fallback must recognize them for rollover.
    let replace_untrusted_root = if path_der.len() > 1
        && certificate_names_equal(last.subject(), last.issuer())
        && verify_certificate_signature_with_provider(&last, &last, provider)?
    {
        let child = parse_certificate(path_der[path_der.len() - 2])?;
        certificate_names_equal(child.issuer(), last.subject())
            && verify_certificate_signature_with_provider(&child, &last, provider)?
    } else {
        false
    };
    let candidate_base = if replace_untrusted_root {
        &path_der[..path_der.len() - 1]
    } else {
        path_der.as_slice()
    };
    let candidate_child = parse_certificate(
        candidate_base
            .last()
            .copied()
            .ok_or(X509ChainError::UntrustedRoot)?,
    )?;

    let mut first_validation_error = None;
    for (anchor_der, cert) in &trusted_anchors {
        if !certificate_names_equal(cert.subject(), candidate_child.issuer())
            || !verify_certificate_signature_with_provider(&candidate_child, cert, provider)?
        {
            continue;
        }
        let mut candidate_path = candidate_base.to_vec();
        candidate_path.push(anchor_der);
        match validate_path(&candidate_path, info, options, verification_time, provider) {
            Ok(()) => return Ok(()),
            Err(error) => first_validation_error.get_or_insert(error),
        };
    }

    Err(first_validation_error.unwrap_or(X509ChainError::UntrustedRoot))
}

fn validate_path(
    path_der: &[&[u8]],
    info: &X509DataInfo,
    options: &X509ChainOptions<'_>,
    verification_time: ASN1Time,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<(), X509ChainError> {
    if path_der.len() > options.max_chain_depth {
        return Err(X509ChainError::DepthExceeded(options.max_chain_depth));
    }

    let path = path_der
        .iter()
        .map(|der| parse_certificate(der))
        .collect::<Result<Vec<_>, _>>()?;

    for (position, cert) in path.iter().enumerate() {
        if !cert.validity().is_valid_at(verification_time) {
            return Err(X509ChainError::CertificateNotValid(position));
        }
        if position == 0 {
            validate_leaf_key_usage(cert)?;
        } else {
            validate_ca_constraints(cert, position)?;
        }
    }

    for (position, pair) in path.windows(2).enumerate() {
        let [child, issuer] = pair else {
            unreachable!()
        };
        if !certificate_names_equal(child.issuer(), issuer.subject())
            || !verify_certificate_signature_with_provider(child, issuer, provider)?
        {
            return Err(X509ChainError::InvalidSignature(position));
        }
    }

    if options.check_crls {
        verify_crls(&path, &info.crls, verification_time, provider)?;
    }
    Ok(())
}

#[cfg(test)]
fn verify_certificate_signature(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> bool {
    verify_certificate_signature_with_provider(
        certificate,
        issuer,
        crate::provider::default_provider(),
    )
    .unwrap_or(false)
}

fn verify_certificate_signature_with_provider(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, X509ChainError> {
    // RFC 5280 sections 4.1.1.2 and 4.1.2.3 require the outer and signed
    // AlgorithmIdentifier values to be identical. Enforce this independently
    // of the backend so the legacy DSA path cannot bypass the invariant.
    if certificate.signature_algorithm != certificate.tbs_certificate.signature {
        return Ok(false);
    }
    verify_x509_signature_with_provider(
        &certificate.signature_algorithm,
        &certificate.signature_value.data,
        certificate.tbs_certificate.as_ref(),
        issuer.public_key().raw,
        provider,
    )
}

/// Test a candidate certificate-path edge without assigning trust to either
/// certificate. Path construction uses this only to distinguish certificates
/// that share an issuer subject name; full policy validation still happens
/// after the complete path has been assembled.
#[cfg(test)]
pub(crate) fn certificate_signature_matches(certificate_der: &[u8], issuer_der: &[u8]) -> bool {
    certificate_signature_matches_with_provider(
        certificate_der,
        issuer_der,
        crate::provider::default_provider(),
    )
    .unwrap_or(false)
}

pub(crate) fn certificate_signature_matches_with_provider(
    certificate_der: &[u8],
    issuer_der: &[u8],
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, X509ChainError> {
    let (Ok(certificate), Ok(issuer)) = (
        parse_certificate(certificate_der),
        parse_certificate(issuer_der),
    ) else {
        return Ok(false);
    };
    verify_certificate_signature_with_provider(&certificate, &issuer, provider)
}

fn certificate_names_equal(
    left: &x509_parser::x509::X509Name<'_>,
    right: &x509_parser::x509::X509Name<'_>,
) -> bool {
    let (Ok(left), Ok(right)) = (x509_name_to_rfc4514(left), x509_name_to_rfc4514(right)) else {
        return false;
    };
    distinguished_names_equal(&left, &right)
}

#[cfg(test)]
fn verify_crl_signature(crl: &CertificateRevocationList<'_>, issuer: &X509Certificate<'_>) -> bool {
    verify_crl_signature_with_provider(crl, issuer, crate::provider::default_provider())
        .unwrap_or(false)
}

fn verify_crl_signature_with_provider(
    crl: &CertificateRevocationList<'_>,
    issuer: &X509Certificate<'_>,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, X509ChainError> {
    // RFC 5280 sections 5.1.1.2 and 5.1.2.2 impose the same equality rule on
    // CRLs as certificates.
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        return Ok(false);
    }
    verify_x509_signature_with_provider(
        &crl.signature_algorithm,
        &crl.signature_value.data,
        crl.tbs_cert_list.as_ref(),
        issuer.public_key().raw,
        provider,
    )
}

fn verify_x509_signature_with_provider(
    algorithm_identifier: &AlgorithmIdentifier<'_>,
    signature_der: &[u8],
    signed_data: &[u8],
    issuer_spki_der: &[u8],
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, X509ChainError> {
    let algorithm = x509_signature_algorithm(algorithm_identifier)?;
    provider
        .verify_x509_signature(algorithm, signed_data, signature_der, issuer_spki_der)
        .map_err(Into::into)
}

fn x509_signature_algorithm(
    identifier: &AlgorithmIdentifier<'_>,
) -> Result<X509SignatureAlgorithm, X509ChainError> {
    let oid = identifier.algorithm.to_id_string();
    let algorithm = match oid.as_str() {
        "1.2.840.10040.4.3" => X509SignatureAlgorithm::Dsa(super::DigestAlgorithm::Sha1),
        "2.16.840.1.101.3.4.3.2" => X509SignatureAlgorithm::Dsa(super::DigestAlgorithm::Sha256),
        "2.16.840.1.101.3.4.3.3" => X509SignatureAlgorithm::Dsa(super::DigestAlgorithm::Sha384),
        "2.16.840.1.101.3.4.3.4" => X509SignatureAlgorithm::Dsa(super::DigestAlgorithm::Sha512),
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => {
            X509SignatureAlgorithm::RsaPkcs1v15(super::DigestAlgorithm::Sha1)
        }
        "1.2.840.113549.1.1.11" => {
            X509SignatureAlgorithm::RsaPkcs1v15(super::DigestAlgorithm::Sha256)
        }
        "1.2.840.113549.1.1.12" => {
            X509SignatureAlgorithm::RsaPkcs1v15(super::DigestAlgorithm::Sha384)
        }
        "1.2.840.113549.1.1.13" => {
            X509SignatureAlgorithm::RsaPkcs1v15(super::DigestAlgorithm::Sha512)
        }
        "1.2.840.113549.1.1.10" => parse_rsa_pss_algorithm(identifier)?,
        "1.2.840.10045.4.1" => X509SignatureAlgorithm::Ecdsa(super::DigestAlgorithm::Sha1),
        "1.2.840.10045.4.3.2" => X509SignatureAlgorithm::Ecdsa(super::DigestAlgorithm::Sha256),
        "1.2.840.10045.4.3.3" => X509SignatureAlgorithm::Ecdsa(super::DigestAlgorithm::Sha384),
        "1.2.840.10045.4.3.4" => X509SignatureAlgorithm::Ecdsa(super::DigestAlgorithm::Sha512),
        "1.3.101.112" => X509SignatureAlgorithm::Ed25519,
        _ => return Err(X509ChainError::UnsupportedSignatureAlgorithm { oid }),
    };
    Ok(algorithm)
}

fn parse_rsa_pss_algorithm(
    identifier: &AlgorithmIdentifier<'_>,
) -> Result<X509SignatureAlgorithm, X509ChainError> {
    let parameters = identifier
        .parameters
        .as_ref()
        .ok_or_else(|| X509ChainError::InvalidDer {
            kind: "RSASSA-PSS parameters",
            message: "missing parameters".into(),
        })?;
    let parameters = x509_parser::signature_algorithm::RsaSsaPssParams::try_from(parameters)
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "RSASSA-PSS parameters",
            message: error.to_string(),
        })?;
    if parameters.trailer_field() != 1 {
        return Err(X509ChainError::InvalidDer {
            kind: "RSASSA-PSS parameters",
            message: "trailerField must be 1".into(),
        });
    }
    let digest = x509_digest_algorithm(&parameters.hash_algorithm_oid().to_id_string())?;
    let mask = parameters
        .mask_gen_algorithm()
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "RSASSA-PSS parameters",
            message: error.to_string(),
        })?;
    if mask.mgf.to_id_string() != "1.2.840.113549.1.1.8" {
        return Err(X509ChainError::UnsupportedSignatureAlgorithm {
            oid: mask.mgf.to_id_string(),
        });
    }
    let mgf_digest = x509_digest_algorithm(&mask.hash.to_id_string())?;
    let salt_len =
        usize::try_from(parameters.salt_length()).map_err(|_| X509ChainError::InvalidDer {
            kind: "RSASSA-PSS parameters",
            message: "saltLength does not fit this platform".into(),
        })?;
    Ok(X509SignatureAlgorithm::RsaPss {
        digest,
        mgf_digest,
        salt_len,
    })
}

fn x509_digest_algorithm(oid: &str) -> Result<super::DigestAlgorithm, X509ChainError> {
    match oid {
        "1.3.14.3.2.26" => Ok(super::DigestAlgorithm::Sha1),
        "2.16.840.1.101.3.4.2.1" => Ok(super::DigestAlgorithm::Sha256),
        "2.16.840.1.101.3.4.2.2" => Ok(super::DigestAlgorithm::Sha384),
        "2.16.840.1.101.3.4.2.3" => Ok(super::DigestAlgorithm::Sha512),
        _ => Err(X509ChainError::UnsupportedSignatureAlgorithm {
            oid: oid.to_owned(),
        }),
    }
}

fn validate_leaf_key_usage(cert: &X509Certificate<'_>) -> Result<(), X509ChainError> {
    // RFC 5280 section 4.2.1.3 restricts key purpose only when KeyUsage is present.
    if cert
        .key_usage()
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "certificate KeyUsage",
            message: error.to_string(),
        })?
        .is_some_and(|usage| !usage.value.digital_signature() && !usage.value.non_repudiation())
    {
        return Err(X509ChainError::InvalidKeyUsage {
            position: 0,
            required: "digitalSignature or nonRepudiation",
        });
    }
    Ok(())
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>, X509ChainError> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|error| X509ChainError::InvalidDer {
            kind: "certificate",
            message: error.to_string(),
        })?;
    if !rest.is_empty() {
        return Err(X509ChainError::InvalidDer {
            kind: "certificate",
            message: "trailing data".into(),
        });
    }
    Ok(cert)
}

fn system_time_to_asn1(time: SystemTime) -> Result<ASN1Time, X509ChainError> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| X509ChainError::CertificateNotValid(0))?
        .as_secs();
    let timestamp = i64::try_from(seconds).map_err(|_| X509ChainError::CertificateNotValid(0))?;
    ASN1Time::from_timestamp(timestamp).map_err(|error| X509ChainError::InvalidDer {
        kind: "verification time",
        message: error.to_string(),
    })
}

fn validate_ca_constraints(
    cert: &X509Certificate<'_>,
    position: usize,
) -> Result<(), X509ChainError> {
    let constraints = cert
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(value) => Some(value),
            _ => None,
        })
        .filter(|constraints| constraints.ca)
        .ok_or(X509ChainError::IssuerNotCa(position))?;

    if cert
        .key_usage()
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "certificate KeyUsage",
            message: error.to_string(),
        })?
        .is_some_and(|usage| !usage.value.key_cert_sign())
    {
        return Err(X509ChainError::InvalidKeyUsage {
            position,
            required: "keyCertSign",
        });
    }

    if let Some(limit) = constraints.path_len_constraint {
        let subordinate_ca_count = position.saturating_sub(1);
        if subordinate_ca_count > limit as usize {
            return Err(X509ChainError::PathLengthExceeded { position, limit });
        }
    }
    Ok(())
}

fn verify_crls(
    path: &[X509Certificate<'_>],
    crl_der: &[Vec<u8>],
    verification_time: ASN1Time,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<(), X509ChainError> {
    let crls = crl_der
        .iter()
        .enumerate()
        .map(|(idx, der)| {
            let (rest, crl) = CertificateRevocationList::from_der(der).map_err(|error| {
                X509ChainError::InvalidDer {
                    kind: "CRL",
                    message: error.to_string(),
                }
            })?;
            if !rest.is_empty() {
                return Err(X509ChainError::InvalidDer {
                    kind: "CRL",
                    message: "trailing data".into(),
                });
            }
            Ok((idx, crl))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (position, cert) in path.iter().enumerate().take(path.len().saturating_sub(1)) {
        let issuer = &path[position + 1];
        for (crl_index, crl) in crls
            .iter()
            .filter(|(_, crl)| certificate_names_equal(crl.issuer(), cert.issuer()))
        {
            if issuer
                .key_usage()
                .map_err(|error| X509ChainError::InvalidDer {
                    kind: "certificate KeyUsage",
                    message: error.to_string(),
                })?
                .is_some_and(|usage| !usage.value.crl_sign())
            {
                return Err(X509ChainError::InvalidKeyUsage {
                    position: position + 1,
                    required: "cRLSign",
                });
            }
            let time_valid = crl.last_update() <= verification_time
                && crl
                    .next_update()
                    .is_none_or(|next| verification_time <= next);
            if !time_valid || !verify_crl_signature_with_provider(crl, issuer, provider)? {
                return Err(X509ChainError::InvalidCrl(*crl_index));
            }
            if crl.iter_revoked_certificates().any(|revoked| {
                revoked.raw_serial() == cert.raw_serial()
                    && revoked.revocation_date <= verification_time
            }) {
                return Err(X509ChainError::Revoked(position));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::xmldsig::{KeyInfoSource, parse::XMLDSIG_NS, parse_key_info};
    use p256::pkcs8::EncodePublicKey;
    use roxmltree::Document;
    use sha2::{Digest, Sha256, Sha384};
    use signature::hazmat::PrehashSigner;
    use std::time::Duration;
    use x509_parser::oid_registry::{OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, Oid};

    #[test]
    fn x509_ecdsa_hash_oid_does_not_select_the_issuer_curve() {
        // RFC 5758 signature OIDs select the digest while SubjectPublicKeyInfo
        // selects the curve. Both non-default pairings must therefore reach
        // the provider with the issuer's actual curve rather than a curve
        // inferred from the hash OID.
        let data = b"certificate tbs bytes";

        let p384_key = p384::ecdsa::SigningKey::from_slice(&[0x42; 48])
            .expect("fixed P-384 test key must be valid");
        let p384_signature: p384::ecdsa::Signature = p384_key
            .sign_prehash(&Sha256::digest(data))
            .expect("P-384 must sign a SHA-256 prehash");
        let p384_spki = p384_key
            .verifying_key()
            .to_public_key_der()
            .expect("P-384 SPKI must encode");
        assert!(
            verify_x509_signature_with_provider(
                &AlgorithmIdentifier::new(OID_SIG_ECDSA_WITH_SHA256, None),
                p384_signature.to_der().as_bytes(),
                data,
                p384_spki.as_bytes(),
                crate::provider::default_provider(),
            )
            .expect("P-384 with SHA-256 must be a supported X.509 pairing")
        );

        let p256_key = p256::ecdsa::SigningKey::from_slice(&[0x24; 32])
            .expect("fixed P-256 test key must be valid");
        let p256_signature: p256::ecdsa::Signature = p256_key
            .sign_prehash(&Sha384::digest(data))
            .expect("P-256 must sign a SHA-384 prehash");
        let p256_spki = p256_key
            .verifying_key()
            .to_public_key_der()
            .expect("P-256 SPKI must encode");
        assert!(
            verify_x509_signature_with_provider(
                &AlgorithmIdentifier::new(OID_SIG_ECDSA_WITH_SHA384, None),
                p256_signature.to_der().as_bytes(),
                data,
                p256_spki.as_bytes(),
                crate::provider::default_provider(),
            )
            .expect("P-256 with SHA-384 must be a supported X.509 pairing")
        );
    }

    #[test]
    fn path_edge_signature_check_does_not_repeat_name_matching() {
        // Path construction performs RFC 5280 name matching before asking this
        // helper to disambiguate same-name candidates. Only proof of possession
        // of the issuer key belongs in this second gate.
        let issuer_key = rcgen::KeyPair::generate().expect("issuer key generation should succeed");
        let issuer_key_pem = issuer_key.serialize_pem();
        let mut signing_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty issuer SAN list should be valid");
        signing_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "signing name");
        signing_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        signing_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let signing_issuer = rcgen::CertifiedIssuer::self_signed(signing_params, issuer_key)
            .expect("issuer certificate should be self-signable");

        let mut alternate_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty alternate SAN list should be valid");
        alternate_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "name already matched by caller");
        alternate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        alternate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let alternate_issuer = rcgen::CertifiedIssuer::self_signed(
            alternate_params,
            rcgen::KeyPair::from_pem(&issuer_key_pem)
                .expect("serialized issuer key should parse again"),
        )
        .expect("alternate issuer certificate should be self-signable");

        let leaf = rcgen::CertificateParams::new(Vec::new())
            .expect("empty leaf SAN list should be valid")
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &signing_issuer,
            )
            .expect("issuer should sign leaf certificate");

        assert!(certificate_signature_matches(
            leaf.der(),
            alternate_issuer.der()
        ));
    }

    #[test]
    fn certificate_path_edge_preserves_ed25519_verification() {
        // Provider routing must preserve the certificate algorithms accepted by
        // the previous x509-parser verifier rather than narrowing them to the
        // XMLDSig SignatureMethod enum.
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Ed25519 issuer key generation should succeed");
        let mut issuer_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty issuer SAN list should be valid");
        issuer_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Ed25519 issuer");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        issuer_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let issuer = rcgen::CertifiedIssuer::self_signed(issuer_params, issuer_key)
            .expect("Ed25519 issuer certificate should be self-signable");
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Ed25519 leaf key generation should succeed");
        let leaf = rcgen::CertificateParams::new(Vec::new())
            .expect("empty leaf SAN list should be valid")
            .signed_by(&leaf_key, &issuer)
            .expect("Ed25519 issuer should sign leaf certificate");

        assert!(certificate_signature_matches(leaf.der(), issuer.der()));
    }

    #[test]
    fn every_modeled_non_parameterized_x509_algorithm_reaches_the_provider() {
        // Parsing and provider capability are separate contracts. Once an OID
        // has a typed representation, custom providers must get the chance to
        // implement it even when RustCrypto does not.
        for (oid, expected) in [
            (
                "2.16.840.1.101.3.4.3.2",
                X509SignatureAlgorithm::Dsa(super::super::DigestAlgorithm::Sha256),
            ),
            (
                "2.16.840.1.101.3.4.3.3",
                X509SignatureAlgorithm::Dsa(super::super::DigestAlgorithm::Sha384),
            ),
            (
                "2.16.840.1.101.3.4.3.4",
                X509SignatureAlgorithm::Dsa(super::super::DigestAlgorithm::Sha512),
            ),
            (
                "1.2.840.10045.4.1",
                X509SignatureAlgorithm::Ecdsa(super::super::DigestAlgorithm::Sha1),
            ),
            (
                "1.2.840.10045.4.3.4",
                X509SignatureAlgorithm::Ecdsa(super::super::DigestAlgorithm::Sha512),
            ),
        ] {
            let identifier = AlgorithmIdentifier::new(
                Oid::from_str(oid).expect("static signature OID must parse"),
                None,
            );
            assert_eq!(x509_signature_algorithm(&identifier), Ok(expected), "{oid}");
        }
    }

    #[test]
    fn unknown_x509_signature_algorithm_remains_diagnosable() {
        let oid = "1.2.3.4.5";
        let identifier = AlgorithmIdentifier::new(
            Oid::from_str(oid).expect("static unknown OID must parse"),
            None,
        );

        assert_eq!(
            x509_signature_algorithm(&identifier),
            Err(X509ChainError::UnsupportedSignatureAlgorithm { oid: oid.into() })
        );
    }

    #[test]
    fn parses_rsa_pss_certificate_parameters_without_xml_dsig_loss() {
        // RFC 4055 carries the digest, MGF digest, and salt length inside the
        // AlgorithmIdentifier. Preserve all three values at the provider edge.
        let der = [
            0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
            0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
        ];
        let (rest, identifier) = AlgorithmIdentifier::from_der(&der)
            .expect("standard SHA-256 RSA-PSS AlgorithmIdentifier must parse");
        assert!(rest.is_empty());

        assert_eq!(
            x509_signature_algorithm(&identifier),
            Ok(X509SignatureAlgorithm::RsaPss {
                digest: super::super::DigestAlgorithm::Sha256,
                mgf_digest: super::super::DigestAlgorithm::Sha256,
                salt_len: 32,
            })
        );
    }

    #[test]
    fn dsa_rollover_replaces_embedded_root_before_depth_validation() {
        let leaf = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        )
        .to_vec();
        let embedded_root =
            include_bytes!("../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/ca.der")
                .to_vec();

        // Trust-anchor self-signatures are not part of path validation. Changing
        // only that signature gives this test a distinct rollover certificate
        // with the same subject and DSA public key as the embedded stale root.
        let mut rollover_anchor = embedded_root.clone();
        *rollover_anchor
            .last_mut()
            .expect("certificate is non-empty") ^= 1;
        parse_certificate(&rollover_anchor).expect("modified trust anchor remains valid DER");
        let anchors = vec![rollover_anchor];
        let info = X509DataInfo {
            certificates: vec![leaf, embedded_root],
            certificate_chain: vec![0, 1],
            ..X509DataInfo::default()
        };
        let options = X509ChainOptions {
            trusted_certs: &anchors,
            verification_time: UNIX_EPOCH + Duration::from_secs(1_104_580_800),
            max_chain_depth: 2,
            check_crls: false,
        };

        verify_x509_certificate_chain(&info, &options)
            .expect("the stale DSA root must be replaced by the configured anchor");
    }

    #[test]
    fn dsa_certificate_rejects_mismatched_inner_signature_algorithm() {
        // The signed TBSCertificate algorithm is a separate RFC 5280 invariant;
        // a valid signature over the original bytes must not bypass a mismatch
        // in the parsed metadata through the legacy DSA fallback.
        let (_, mut certificate) = X509Certificate::from_der(include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        ))
        .expect("the tracked Merlin certificate is valid DER");
        let (_, issuer) = X509Certificate::from_der(include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/ca.der"
        ))
        .expect("the tracked Merlin issuer is a DER certificate");
        assert!(verify_certificate_signature(&certificate, &issuer));

        certificate.tbs_certificate.signature = issuer.public_key().algorithm.clone();

        assert_ne!(
            certificate.tbs_certificate.signature,
            certificate.signature_algorithm
        );
        assert!(!verify_certificate_signature(&certificate, &issuer));
    }

    #[test]
    fn dsa_sha1_crl_signature_uses_the_same_fallback_as_certificates() {
        let xml = include_str!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt-crl.xml"
        );
        let document = Document::parse(xml).expect("the tracked Merlin document is valid XML");
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .expect("the Merlin document contains KeyInfo");
        let key_info = parse_key_info(key_info_node).expect("the Merlin KeyInfo is valid");
        let KeyInfoSource::X509Data(info) = &key_info.sources[0] else {
            panic!("expected X509Data")
        };
        let (_, issuer) = X509Certificate::from_der(include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/ca.der"
        ))
        .expect("the tracked Merlin issuer is a DER certificate");
        let (_, crl) = CertificateRevocationList::from_der(&info.crls[0])
            .expect("the tracked Merlin CRL is valid DER");

        assert!(verify_crl_signature(&crl, &issuer));
    }

    #[test]
    fn dsa_crl_rejects_mismatched_inner_signature_algorithm() {
        let xml = include_str!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt-crl.xml"
        );
        let document = Document::parse(xml).expect("the tracked Merlin document is valid XML");
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .expect("the Merlin document contains KeyInfo");
        let key_info = parse_key_info(key_info_node).expect("the Merlin KeyInfo is valid");
        let KeyInfoSource::X509Data(info) = &key_info.sources[0] else {
            panic!("expected X509Data")
        };
        let (_, issuer) = X509Certificate::from_der(include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/ca.der"
        ))
        .expect("the tracked Merlin issuer is a DER certificate");
        let (_, mut crl) = CertificateRevocationList::from_der(&info.crls[0])
            .expect("the tracked Merlin CRL is valid DER");
        assert!(verify_crl_signature(&crl, &issuer));

        crl.tbs_cert_list.signature = issuer.public_key().algorithm.clone();

        assert_ne!(crl.tbs_cert_list.signature, crl.signature_algorithm);
        assert!(!verify_crl_signature(&crl, &issuer));
    }
}
