//! X.509 certificate path and revocation validation.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::{
    certificate::X509Certificate, extensions::ParsedExtension, prelude::FromDer,
    revocation_list::CertificateRevocationList, time::ASN1Time,
};

use super::X509DataInfo;

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
        return validate_path(&path_der, info, options, verification_time);
    }

    let replace_untrusted_root = if path_der.len() > 1
        && last.subject() == last.issuer()
        && last.verify_signature(None).is_ok()
    {
        let child = parse_certificate(path_der[path_der.len() - 2])?;
        child.issuer() == last.subject() && child.verify_signature(Some(last.public_key())).is_ok()
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
    for (anchor_der, _) in trusted_anchors.iter().filter(|(_, cert)| {
        cert.subject() == candidate_child.issuer()
            && candidate_child
                .verify_signature(Some(cert.public_key()))
                .is_ok()
    }) {
        let mut candidate_path = candidate_base.to_vec();
        candidate_path.push(anchor_der);
        match validate_path(&candidate_path, info, options, verification_time) {
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
        if child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Err(X509ChainError::InvalidSignature(position));
        }
    }

    if options.check_crls {
        verify_crls(&path, &info.crls, verification_time)?;
    }
    Ok(())
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
        for (crl_index, crl) in crls.iter().filter(|(_, crl)| crl.issuer() == cert.issuer()) {
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
            if !time_valid || crl.verify_signature(issuer.public_key()).is_err() {
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
