//! X.509 certificate path and revocation validation.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, NameConstraints, ParsedExtension},
    prelude::FromDer,
    revocation_list::CertificateRevocationList,
    time::ASN1Time,
    x509::AlgorithmIdentifier,
};

use super::{
    X509DataInfo,
    parse::{distinguished_name_within_subtree, distinguished_names_equal, x509_name_to_rfc4514},
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
    /// A certificate repeats an extension OID, which RFC 5280 forbids.
    #[error("certificate at chain position {position} repeats extension {oid}")]
    DuplicateExtension {
        /// Position of the malformed certificate in the candidate path.
        position: usize,
        /// Repeated extension object identifier.
        oid: String,
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
    /// A subordinate certificate is outside a CA's permitted name space.
    #[error(
        "certificate at chain position {position} violates name constraints from position {constraining_position}"
    )]
    NameConstraintViolation {
        /// Position of the subordinate certificate.
        position: usize,
        /// Position of the CA carrying NameConstraints.
        constraining_position: usize,
    },
    /// A critical certificate extension is not implemented by path validation.
    #[error("certificate at chain position {position} has unsupported critical extension {oid}")]
    UnsupportedCriticalExtension {
        /// Position of the certificate in the validated path.
        position: usize,
        /// Extension object identifier.
        oid: String,
    },
    /// NameConstraints is not a critical CA extension as required by RFC 5280.
    #[error("certificate at chain position {position} has invalid NameConstraints placement")]
    InvalidNameConstraints {
        /// Position of the certificate carrying the invalid extension.
        position: usize,
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
        validate_certificate_serial(cert)?;
        validate_unique_extensions(cert, position)?;
        if !cert.validity().is_valid_at(verification_time) {
            return Err(X509ChainError::CertificateNotValid(position));
        }
        if position == 0 {
            validate_leaf_key_usage(cert)?;
        } else {
            validate_ca_constraints(cert, position)?;
        }
        validate_subject_identity(cert)?;
        validate_critical_extensions(cert, position)?;
    }
    validate_path_length_constraints(&path)?;
    validate_name_constraints(&path)?;

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

fn validate_certificate_serial(cert: &X509Certificate<'_>) -> Result<(), X509ChainError> {
    validate_certificate_serial_bytes(cert.raw_serial())
}

fn validate_certificate_serial_bytes(serial: &[u8]) -> Result<(), X509ChainError> {
    let magnitude = serial.strip_prefix(&[0]).unwrap_or(serial);
    if serial.is_empty()
        || serial[0] & 0x80 != 0
        || magnitude.is_empty()
        || magnitude.len() > 20
        || magnitude.iter().all(|byte| *byte == 0)
    {
        return Err(X509ChainError::InvalidDer {
            kind: "certificate serial number",
            message: "RFC 5280 requires a positive, non-zero value of at most 20 octets".into(),
        });
    }
    Ok(())
}

fn validate_unique_extensions(
    cert: &X509Certificate<'_>,
    position: usize,
) -> Result<(), X509ChainError> {
    let mut seen = std::collections::HashSet::with_capacity(cert.extensions().len());
    for extension in cert.extensions() {
        let oid = extension.oid.to_id_string();
        if !seen.insert(oid.clone()) {
            return Err(X509ChainError::DuplicateExtension { position, oid });
        }
    }
    Ok(())
}

fn validate_subject_identity(cert: &X509Certificate<'_>) -> Result<(), X509ChainError> {
    for attribute in cert.subject().iter_email() {
        let email = attribute
            .as_str()
            .map_err(|error| X509ChainError::InvalidDer {
                kind: "certificate subject emailAddress",
                message: error.to_string(),
            })?;
        if !mailbox_has_valid_syntax(email) {
            return Err(X509ChainError::InvalidDer {
                kind: "certificate subject emailAddress",
                message: format!("invalid RFC 5280 mailbox syntax: {email:?}"),
            });
        }
    }

    let subject_is_empty = cert.subject().iter().next().is_none();
    let mut san_extensions = cert
        .extensions()
        .iter()
        .filter(|extension| extension.oid.to_id_string() == "2.5.29.17");
    let Some(extension) = san_extensions.next() else {
        return if subject_is_empty {
            Err(invalid_subject_identity(
                "an empty subject requires a critical SubjectAlternativeName",
            ))
        } else {
            Ok(())
        };
    };
    if san_extensions.next().is_some() {
        return Err(invalid_subject_identity(
            "an empty subject must not contain duplicate SubjectAlternativeName extensions",
        ));
    }
    let ParsedExtension::SubjectAlternativeName(names) = extension.parsed_extension() else {
        return Err(invalid_subject_identity(
            "SubjectAlternativeName could not be parsed",
        ));
    };
    for name in &names.general_names {
        validate_subject_alternative_name(name)?;
    }
    if subject_is_empty && (!extension.critical || names.general_names.is_empty()) {
        return Err(invalid_subject_identity(
            "an empty subject requires a critical, non-empty SubjectAlternativeName",
        ));
    }
    Ok(())
}

fn validate_subject_alternative_name(name: &GeneralName<'_>) -> Result<(), X509ChainError> {
    match name {
        GeneralName::RFC822Name(value) => validate_rfc5280_mailbox(value),
        GeneralName::DNSName(value) => {
            // RFC 5280 section 4.2.1.6 requires RFC 1034/1123 preferred-name
            // syntax here. RFC 9525 wildcard matching is an application-level
            // TLS identity rule, not certificate-path profile validation.
            validate_rfc5280_dns_name(value)
        }
        GeneralName::URI(value) => validate_rfc5280_uri(value),
        GeneralName::IPAddress(value) if !matches!(value.len(), 4 | 16) => {
            Err(invalid_subject_identity(
                "SubjectAlternativeName iPAddress must contain 4 or 16 octets",
            ))
        }
        GeneralName::Invalid(..) => Err(invalid_subject_identity(
            "SubjectAlternativeName contains a malformed GeneralName",
        )),
        _ => Ok(()),
    }
}

fn validate_rfc5280_mailbox(value: &str) -> Result<(), X509ChainError> {
    if !mailbox_has_valid_syntax(value) {
        return Err(invalid_subject_identity(
            "SubjectAlternativeName rfc822Name has invalid RFC 5280 mailbox syntax",
        ));
    }
    Ok(())
}

fn mailbox_has_valid_syntax(value: &str) -> bool {
    value.rsplit_once('@').is_some_and(|(local, domain)| {
        mailbox_local_part_has_valid_syntax(local) && mailbox_domain_has_valid_syntax(domain)
    })
}

fn mailbox_domain_has_valid_syntax(domain: &str) -> bool {
    let Some(literal) = domain
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return dns_name_has_valid_syntax(domain, false);
    };
    if literal
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("IPv6:"))
    {
        literal[5..].parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        literal.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

fn mailbox_local_part_has_valid_syntax(local: &str) -> bool {
    if let Some(quoted) = local
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        if quoted.is_empty() {
            return false;
        }
        let mut escaped = false;
        for byte in quoted.bytes() {
            if escaped {
                if !(0x20..=0x7e).contains(&byte) {
                    return false;
                }
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' || !(0x20..=0x7e).contains(&byte) {
                return false;
            }
        }
        return !escaped;
    }

    local.split('.').all(|atom| {
        !atom.is_empty()
            && atom.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'/'
                            | b'='
                            | b'?'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'{'
                            | b'|'
                            | b'}'
                            | b'~'
                    )
            })
    })
}

fn validate_rfc5280_uri(value: &str) -> Result<(), X509ChainError> {
    let Some((scheme, scheme_specific)) = value.split_once(':') else {
        return Err(invalid_subject_identity(
            "SubjectAlternativeName URI must be absolute",
        ));
    };
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        || scheme_specific.is_empty()
        || !uri_scheme_specific_part_has_valid_syntax(scheme_specific)
    {
        return Err(invalid_subject_identity(
            "SubjectAlternativeName URI has invalid RFC 3986 syntax",
        ));
    }

    if let Some(authority_and_path) = scheme_specific.strip_prefix("//") {
        let authority = authority_and_path
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if !uri_authority_has_rfc5280_host(authority) {
            return Err(invalid_subject_identity(
                "SubjectAlternativeName URI authority requires a fully qualified host",
            ));
        }
    }
    Ok(())
}

fn uri_scheme_specific_part_has_valid_syntax(value: &str) -> bool {
    if value.bytes().any(|byte| {
        !byte.is_ascii()
            || byte.is_ascii_control()
            || byte == b' '
            || !matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    }) || value.matches('#').count() > 1
    {
        return false;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return false;
        }
        index += if bytes[index] == b'%' { 3 } else { 1 };
    }
    true
}

fn uri_authority_has_rfc5280_host(authority: &str) -> bool {
    parse_uri_authority_host(authority).is_some()
}

#[derive(Clone, Copy)]
enum UriAuthorityHost<'a> {
    Dns(&'a str),
    Ip,
}

fn parse_uri_authority_host(authority: &str) -> Option<UriAuthorityHost<'_>> {
    let host_port = match authority.split_once('@') {
        Some((userinfo, host_port))
            if !host_port.contains('@') && uri_userinfo_has_valid_syntax(userinfo) =>
        {
            host_port
        }
        Some(_) => return None,
        None => authority,
    };
    if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, port) = bracketed.split_once(']')?;
        return (host.parse::<std::net::Ipv6Addr>().is_ok() && uri_port_has_valid_syntax(port))
            .then_some(UriAuthorityHost::Ip);
    }
    let (host, port) = host_port
        .split_once(':')
        .map_or((host_port, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())) {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        Some(UriAuthorityHost::Ip)
    } else if dns_name_has_valid_syntax(host, false) {
        Some(UriAuthorityHost::Dns(host))
    } else {
        None
    }
}

fn uri_port_has_valid_syntax(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn uri_userinfo_has_valid_syntax(userinfo: &str) -> bool {
    let bytes = userinfo.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
            ))
        {
            return false;
        }
        index += 1;
    }
    true
}

fn invalid_subject_identity(message: &str) -> X509ChainError {
    X509ChainError::InvalidDer {
        kind: "certificate subject identity",
        message: message.into(),
    }
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
    match &algorithm {
        X509SignatureAlgorithm::Dsa(_)
        | X509SignatureAlgorithm::Ecdsa(_)
        | X509SignatureAlgorithm::Ed25519 => require_absent_signature_parameters(identifier)?,
        X509SignatureAlgorithm::RsaPkcs1v15(_) => {
            require_null_or_absent_signature_parameters(identifier)?;
        }
        X509SignatureAlgorithm::RsaPss { .. } => {}
    }
    Ok(algorithm)
}

fn require_absent_signature_parameters(
    identifier: &AlgorithmIdentifier<'_>,
) -> Result<(), X509ChainError> {
    if identifier.parameters.is_some() {
        return Err(invalid_signature_parameters(
            identifier,
            "parameters must be absent",
        ));
    }
    Ok(())
}

fn require_null_or_absent_signature_parameters(
    identifier: &AlgorithmIdentifier<'_>,
) -> Result<(), X509ChainError> {
    if identifier
        .parameters
        .as_ref()
        .is_some_and(|parameters| parameters.tag() != x509_parser::asn1_rs::Tag::Null)
    {
        return Err(invalid_signature_parameters(
            identifier,
            "parameters must be NULL or absent",
        ));
    }
    Ok(())
}

fn invalid_signature_parameters(
    identifier: &AlgorithmIdentifier<'_>,
    requirement: &str,
) -> X509ChainError {
    X509ChainError::InvalidDer {
        kind: "X.509 signature AlgorithmIdentifier parameters",
        message: format!("{}: {requirement}", identifier.algorithm),
    }
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
    cert.extensions()
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

    Ok(())
}

fn basic_constraints(
    cert: &X509Certificate<'_>,
) -> Option<x509_parser::extensions::BasicConstraints> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(value) => Some(value.clone()),
            _ => None,
        })
}

fn validate_path_length_constraints(path: &[X509Certificate<'_>]) -> Result<(), X509ChainError> {
    for (position, cert) in path.iter().enumerate().skip(1) {
        let Some(limit) = basic_constraints(cert).and_then(|value| value.path_len_constraint)
        else {
            continue;
        };
        let subordinate_ca_count = path[1..position]
            .iter()
            .filter(|subordinate| {
                basic_constraints(subordinate).is_some_and(|value| value.ca)
                    && !certificate_names_equal(subordinate.subject(), subordinate.issuer())
            })
            .count();
        if subordinate_ca_count > limit as usize {
            return Err(X509ChainError::PathLengthExceeded { position, limit });
        }
    }
    Ok(())
}

fn validate_critical_extensions(
    cert: &X509Certificate<'_>,
    position: usize,
) -> Result<(), X509ChainError> {
    for extension in cert
        .extensions()
        .iter()
        .filter(|extension| extension.critical)
    {
        let oid = extension.oid.to_id_string();
        if !matches!(
            oid.as_str(),
            "2.5.29.15" | "2.5.29.17" | "2.5.29.19" | "2.5.29.30"
        ) {
            return Err(X509ChainError::UnsupportedCriticalExtension { position, oid });
        }
        if matches!(
            extension.parsed_extension(),
            ParsedExtension::UnsupportedExtension { .. }
                | ParsedExtension::ParseError { .. }
                | ParsedExtension::Unparsed
        ) {
            return Err(X509ChainError::UnsupportedCriticalExtension { position, oid });
        }
    }
    Ok(())
}

fn validate_name_constraints(path: &[X509Certificate<'_>]) -> Result<(), X509ChainError> {
    for (position, certificate) in path.iter().enumerate() {
        if let Some(extension) = certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "2.5.29.30")
            && (position == 0 || !extension.critical)
        {
            return Err(X509ChainError::InvalidNameConstraints { position });
        }
    }
    for (constraining_position, issuer) in path.iter().enumerate().skip(1) {
        let Some(extension) = issuer
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "2.5.29.30")
        else {
            continue;
        };
        let ParsedExtension::NameConstraints(constraints) = extension.parsed_extension() else {
            continue;
        };
        validate_name_constraints_der(extension.value, constraining_position)?;
        ensure_supported_name_constraints(constraints, constraining_position)?;
        for (position, subordinate) in path[..constraining_position].iter().enumerate() {
            // The target certificate is always checked. Self-issued CA rollover
            // certificates between it and the constraint issuer are exempt.
            if position != 0 && certificate_names_equal(subordinate.subject(), subordinate.issuer())
            {
                continue;
            }
            validate_certificate_names(subordinate, constraints, position, constraining_position)?;
        }
    }
    Ok(())
}

fn validate_name_constraints_der(
    extension_der: &[u8],
    position: usize,
) -> Result<(), X509ChainError> {
    use der::Decode as _;

    // x509-parser intentionally omits GeneralSubtree distance fields from its
    // public model. Decode the raw extension as well so they cannot silently
    // acquire the zero-minimum, unbounded semantics implemented below.
    let constraints =
        x509_cert::ext::pkix::NameConstraints::from_der(extension_der).map_err(|error| {
            X509ChainError::InvalidDer {
                kind: "NameConstraints",
                message: error.to_string(),
            }
        })?;
    if constraints.permitted_subtrees.is_none() && constraints.excluded_subtrees.is_none()
        || constraints
            .permitted_subtrees
            .as_ref()
            .is_some_and(Vec::is_empty)
        || constraints
            .excluded_subtrees
            .as_ref()
            .is_some_and(Vec::is_empty)
    {
        return Err(X509ChainError::InvalidNameConstraints { position });
    }
    let unsupported = constraints
        .permitted_subtrees
        .iter()
        .flatten()
        .chain(constraints.excluded_subtrees.iter().flatten())
        .any(|subtree| subtree.minimum != 0 || subtree.maximum.is_some());
    if unsupported {
        return Err(X509ChainError::InvalidNameConstraints { position });
    }
    Ok(())
}

fn ensure_supported_name_constraints(
    constraints: &NameConstraints<'_>,
    position: usize,
) -> Result<(), X509ChainError> {
    for subtree in constraints
        .permitted_subtrees
        .iter()
        .flatten()
        .chain(constraints.excluded_subtrees.iter().flatten())
    {
        match &subtree.base {
            GeneralName::DNSName(value) | GeneralName::URI(value) => {
                validate_dns_name_constraint(value)?;
            }
            GeneralName::RFC822Name(value) => validate_email_name_constraint(value)?,
            GeneralName::IPAddress(bytes) => {
                validate_ip_name_constraint(bytes)?;
            }
            _ => {}
        }
        if matches!(
            subtree.base,
            GeneralName::OtherName(..)
                | GeneralName::X400Address(..)
                | GeneralName::EDIPartyName(..)
                | GeneralName::RegisteredID(..)
                | GeneralName::Invalid(..)
        ) {
            return Err(X509ChainError::UnsupportedCriticalExtension {
                position,
                oid: "2.5.29.30".into(),
            });
        }
    }
    Ok(())
}

fn validate_email_name_constraint(value: &str) -> Result<(), X509ChainError> {
    if value.contains('@') {
        if !mailbox_has_valid_syntax(value) {
            return Err(invalid_string_name_constraint(value));
        }
        Ok(())
    } else {
        validate_dns_name_constraint(value)
    }
}

fn validate_dns_name_constraint(value: &str) -> Result<(), X509ChainError> {
    if !dns_name_has_valid_syntax(value, true) {
        return Err(invalid_string_name_constraint(value));
    }
    Ok(())
}

fn validate_rfc5280_dns_name(value: &str) -> Result<(), X509ChainError> {
    if !dns_name_has_valid_syntax(value, false) {
        return Err(X509ChainError::InvalidDer {
            kind: "certificate DNS name",
            message: format!("invalid RFC 5280 dNSName: {value:?}"),
        });
    }
    Ok(())
}

fn dns_name_has_valid_syntax(value: &str, allow_leading_dot: bool) -> bool {
    let domain = if allow_leading_dot {
        value.strip_prefix('.').unwrap_or(value)
    } else {
        value
    };
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return false;
    }
    true
}

fn invalid_string_name_constraint(value: &str) -> X509ChainError {
    X509ChainError::InvalidDer {
        kind: "string name constraint",
        message: format!("invalid RFC 5280 string name constraint: {value:?}"),
    }
}

fn validate_certificate_names(
    certificate: &X509Certificate<'_>,
    constraints: &NameConstraints<'_>,
    position: usize,
    constraining_position: usize,
) -> Result<(), X509ChainError> {
    if certificate.subject().iter().next().is_some() {
        let subject = GeneralName::DirectoryName(certificate.subject().clone());
        validate_general_name(&subject, constraints, position, constraining_position)?;
    }
    for attribute in certificate.subject().iter_email() {
        let email = attribute
            .as_str()
            .map_err(|error| X509ChainError::InvalidDer {
                kind: "certificate subject emailAddress",
                message: error.to_string(),
            })?;
        validate_general_name(
            &GeneralName::RFC822Name(email),
            constraints,
            position,
            constraining_position,
        )?;
    }
    if let Some(names) =
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(value) => Some(&value.general_names),
                _ => None,
            })
    {
        for name in names {
            validate_general_name(name, constraints, position, constraining_position)?;
        }
    }
    Ok(())
}

fn validate_general_name(
    name: &GeneralName<'_>,
    constraints: &NameConstraints<'_>,
    position: usize,
    constraining_position: usize,
) -> Result<(), X509ChainError> {
    let permitted = constraints
        .permitted_subtrees
        .iter()
        .flatten()
        .filter(|subtree| general_names_have_same_form(name, &subtree.base));
    let mut has_permitted_form = false;
    let mut matches_permitted = false;
    for subtree in permitted {
        has_permitted_form = true;
        matches_permitted |=
            general_name_within_subtree(name, &subtree.base)? == NameConstraintMatch::Match;
    }
    let excluded = constraints
        .excluded_subtrees
        .iter()
        .flatten()
        .filter(|subtree| general_names_have_same_form(name, &subtree.base))
        .try_fold(false, |rejected, subtree| {
            general_name_within_subtree(name, &subtree.base)
                .map(|current| rejected || current != NameConstraintMatch::NoMatch)
        })?;
    if excluded || (has_permitted_form && !matches_permitted) {
        return Err(X509ChainError::NameConstraintViolation {
            position,
            constraining_position,
        });
    }
    Ok(())
}

fn general_names_have_same_form(left: &GeneralName<'_>, right: &GeneralName<'_>) -> bool {
    matches!(
        (left, right),
        (GeneralName::RFC822Name(_), GeneralName::RFC822Name(_))
            | (GeneralName::DNSName(_), GeneralName::DNSName(_))
            | (GeneralName::DirectoryName(_), GeneralName::DirectoryName(_))
            | (GeneralName::URI(_), GeneralName::URI(_))
            | (GeneralName::IPAddress(_), GeneralName::IPAddress(_))
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameConstraintMatch {
    Match,
    NoMatch,
    Unevaluable,
}

impl From<bool> for NameConstraintMatch {
    fn from(matched: bool) -> Self {
        if matched { Self::Match } else { Self::NoMatch }
    }
}

fn general_name_within_subtree(
    name: &GeneralName<'_>,
    subtree: &GeneralName<'_>,
) -> Result<NameConstraintMatch, X509ChainError> {
    Ok(match (name, subtree) {
        (GeneralName::DNSName(name), GeneralName::DNSName(subtree)) => {
            dns_name_within_subtree(name, subtree, true).into()
        }
        (GeneralName::RFC822Name(name), GeneralName::RFC822Name(subtree)) => {
            email_within_subtree(name, subtree).into()
        }
        (GeneralName::DirectoryName(name), GeneralName::DirectoryName(subtree)) => {
            let name = x509_name_to_rfc4514(name).map_err(|error| X509ChainError::InvalidDer {
                kind: "certificate name constraint",
                message: error.to_string(),
            })?;
            let subtree =
                x509_name_to_rfc4514(subtree).map_err(|error| X509ChainError::InvalidDer {
                    kind: "certificate name constraint",
                    message: error.to_string(),
                })?;
            distinguished_name_within_subtree(&name, &subtree).into()
        }
        (GeneralName::URI(name), GeneralName::URI(subtree)) => uri_host(name)
            .map_or(NameConstraintMatch::Unevaluable, |host| {
                dns_name_within_subtree(host, subtree, false).into()
            }),
        (GeneralName::IPAddress(name), GeneralName::IPAddress(subtree)) => {
            ip_address_within_subtree(name, subtree)?.into()
        }
        _ => NameConstraintMatch::NoMatch,
    })
}

fn dns_name_within_subtree(name: &str, subtree: &str, include_subdomains: bool) -> bool {
    let name = name.trim_end_matches('.');
    let subtree = subtree.trim_end_matches('.');
    if let Some(domain) = subtree.strip_prefix('.') {
        return name.len() > domain.len()
            && name.as_bytes()[name.len() - domain.len() - 1] == b'.'
            && name[name.len() - domain.len()..].eq_ignore_ascii_case(domain);
    }
    name.eq_ignore_ascii_case(subtree)
        || (include_subdomains
            && name.len() > subtree.len()
            && name.as_bytes()[name.len() - subtree.len() - 1] == b'.'
            && name[name.len() - subtree.len()..].eq_ignore_ascii_case(subtree))
}

fn email_within_subtree(name: &str, subtree: &str) -> bool {
    let Some((local, domain)) = name.rsplit_once('@') else {
        return false;
    };
    if let Some((expected_local, expected_domain)) = subtree.rsplit_once('@') {
        return local == expected_local && domain.eq_ignore_ascii_case(expected_domain);
    }
    dns_name_within_subtree(domain, subtree, false)
}

fn uri_host(uri: &str) -> Option<&str> {
    let authority = uri.split_once("://")?.1;
    let authority = authority.split(['/', '?', '#']).next()?;
    match parse_uri_authority_host(authority)? {
        UriAuthorityHost::Dns(host) => Some(host),
        UriAuthorityHost::Ip => None,
    }
}

fn ip_address_within_subtree(address: &[u8], subtree: &[u8]) -> Result<bool, X509ChainError> {
    if !matches!(address.len(), 4 | 16) {
        return Err(X509ChainError::InvalidDer {
            kind: "IP subject alternative name",
            message: format!("expected 4 or 16 octets, got {}", address.len()),
        });
    }
    let (network, mask) = validate_ip_name_constraint(subtree)?;
    if network.len() != address.len() {
        return Ok(false);
    }
    Ok(address
        .iter()
        .zip(network)
        .zip(mask)
        .all(|((address, network), mask)| address & mask == network & mask))
}

fn validate_ip_name_constraint(subtree: &[u8]) -> Result<(&[u8], &[u8]), X509ChainError> {
    if !matches!(subtree.len(), 8 | 32) {
        return Err(X509ChainError::InvalidDer {
            kind: "IP name constraint",
            message: format!("expected 8 or 32 octets, got {}", subtree.len()),
        });
    }
    let (network, mask) = subtree.split_at(subtree.len() / 2);
    if !ip_mask_is_contiguous(mask) {
        return Err(X509ChainError::InvalidDer {
            kind: "IP name constraint",
            message: "network mask is not contiguous".into(),
        });
    }
    Ok((network, mask))
}

fn ip_mask_is_contiguous(mask: &[u8]) -> bool {
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if zero_seen && set {
                return false;
            }
            zero_seen |= !set;
        }
    }
    true
}

fn certificate_subject_key_identifier<'a>(
    certificate: &'a X509Certificate<'a>,
) -> Option<&'a [u8]> {
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0),
            _ => None,
        })
}

fn crl_authority_key_matches(
    crl: &CertificateRevocationList<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<Option<bool>, X509ChainError> {
    let authority_key = crl
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "2.5.29.35")
        .map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                Ok(identifier.key_identifier.as_ref().map(|key| key.0))
            }
            _ => Err(X509ChainError::InvalidDer {
                kind: "CRL AuthorityKeyIdentifier",
                message: "extension could not be decoded".into(),
            }),
        })
        .transpose()?
        .flatten();
    Ok(authority_key
        .zip(certificate_subject_key_identifier(issuer))
        .map(|(authority, subject)| authority == subject))
}

fn validate_crl_extensions(
    crl: &CertificateRevocationList<'_>,
    crl_index: usize,
) -> Result<(), X509ChainError> {
    validate_crl_extension_uniqueness(crl, crl_index)?;
    validate_crl_extension_semantics(crl, crl_index)
}

fn validate_crl_extension_uniqueness(
    crl: &CertificateRevocationList<'_>,
    crl_index: usize,
) -> Result<(), X509ChainError> {
    crl.tbs_cert_list
        .extensions_map()
        .map_err(|_| X509ChainError::InvalidCrl(crl_index))?;
    for revoked in crl.iter_revoked_certificates() {
        revoked
            .extensions_map()
            .map_err(|_| X509ChainError::InvalidCrl(crl_index))?;
    }
    Ok(())
}

fn validate_crl_extension_semantics(
    crl: &CertificateRevocationList<'_>,
    crl_index: usize,
) -> Result<(), X509ChainError> {
    for extension in crl.extensions() {
        let oid = extension.oid.to_id_string();
        // IssuingDistributionPoint changes which certificates and issuers a CRL
        // covers. Delta CRLs also cannot be treated as complete CRLs: in particular,
        // removeFromCRL has the opposite meaning from a complete-list revocation.
        if matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28")
            || (extension.critical && oid != "2.5.29.35")
        {
            return Err(X509ChainError::InvalidCrl(crl_index));
        }
        if oid == "2.5.29.35"
            && !matches!(
                extension.parsed_extension(),
                ParsedExtension::AuthorityKeyIdentifier(_)
            )
        {
            return Err(X509ChainError::InvalidCrl(crl_index));
        }
    }
    for revoked in crl.iter_revoked_certificates() {
        for extension in revoked.extensions() {
            let oid = extension.oid.to_id_string();
            // certificateIssuer carries the issuer identity for indirect CRLs.
            // No critical entry extension is safe to ignore during serial matching.
            if oid == "2.5.29.29" || extension.critical {
                return Err(X509ChainError::InvalidCrl(crl_index));
            }
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
            // Duplicate OIDs make first-match AKI filtering ambiguous, so this
            // structural invariant must hold before key applicability is tested.
            validate_crl_extension_uniqueness(crl, *crl_index)?;
            let authority_key_match = crl_authority_key_matches(crl, issuer)?;
            if authority_key_match == Some(false) {
                continue;
            }
            if !verify_crl_signature_with_provider(crl, issuer, provider)? {
                if authority_key_match == Some(true) {
                    return Err(X509ChainError::InvalidCrl(*crl_index));
                }
                continue;
            }
            // Extension semantics can reject an applicable CRL, but unrelated
            // untrusted CRL material must not influence the selected path.
            validate_crl_extensions(crl, *crl_index)?;
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
            if !time_valid {
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

    fn generated_certificate_params(common_name: &str, is_ca: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty SAN list should produce valid certificate parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        }
        params
    }

    fn verify_generated_path(
        certificates: Vec<Vec<u8>>,
        trusted_anchor: Vec<u8>,
    ) -> Result<(), X509ChainError> {
        let info = X509DataInfo {
            certificate_chain: (0..certificates.len()).collect(),
            certificates,
            ..X509DataInfo::default()
        };
        let anchors = vec![trusted_anchor];
        verify_x509_certificate_chain(
            &info,
            &X509ChainOptions {
                trusted_certs: &anchors,
                verification_time: SystemTime::now(),
                max_chain_depth: info.certificate_chain.len(),
                check_crls: false,
            },
        )
    }

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
    fn x509_signature_parameters_follow_each_algorithm_profile() {
        use x509_parser::asn1_rs::{Any, Tag};

        // DSA, ECDSA, and Ed25519 signature identifiers require absent
        // parameters. A NULL is not equivalent for these algorithm profiles.
        for oid in [
            "1.2.840.10040.4.3",
            "2.16.840.1.101.3.4.3.2",
            "1.2.840.10045.4.1",
            "1.2.840.10045.4.3.2",
            "1.3.101.112",
        ] {
            let identifier = AlgorithmIdentifier::new(
                Oid::from_str(oid).expect("static signature OID must parse"),
                Some(Any::from_tag_and_data(Tag::Null, &[])),
            );
            assert!(matches!(
                x509_signature_algorithm(&identifier),
                Err(X509ChainError::InvalidDer {
                    kind: "X.509 signature AlgorithmIdentifier parameters",
                    ..
                })
            ));
        }

        // RSA PKCS#1 signature identifiers accept absent and NULL parameters
        // for interoperability, but no other ASN.1 value.
        let rsa_oid =
            Oid::from_str("1.2.840.113549.1.1.11").expect("static RSA signature OID must parse");
        for parameters in [None, Some(Any::from_tag_and_data(Tag::Null, &[]))] {
            assert!(matches!(
                x509_signature_algorithm(&AlgorithmIdentifier::new(rsa_oid.clone(), parameters)),
                Ok(X509SignatureAlgorithm::RsaPkcs1v15(
                    super::super::DigestAlgorithm::Sha256
                ))
            ));
        }
        assert!(matches!(
            x509_signature_algorithm(&AlgorithmIdentifier::new(
                rsa_oid,
                Some(Any::from_tag_and_data(Tag::OctetString, &[])),
            )),
            Err(X509ChainError::InvalidDer {
                kind: "X.509 signature AlgorithmIdentifier parameters",
                ..
            })
        ));
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
    fn path_length_excludes_self_issued_rollover_certificates() {
        // RFC 5280 excludes self-issued rollover CAs from pathLenConstraint;
        // only non-self-issued intermediate CA certificates consume the limit.
        let mut root_params = generated_certificate_params("rollover path authority", true);
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let rollover_params = generated_certificate_params("rollover path authority", true);
        let rollover_key =
            rcgen::KeyPair::generate().expect("rollover key generation should succeed");
        let rollover_certificate = rollover_params
            .signed_by(&rollover_key, &root)
            .expect("root should sign same-name rollover certificate");
        let rollover_issuer = rcgen::Issuer::from_params(&rollover_params, &rollover_key);
        let leaf = generated_certificate_params("rollover path leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &rollover_issuer,
            )
            .expect("rollover key should sign leaf certificate");

        verify_generated_path(
            vec![
                leaf.der().to_vec(),
                rollover_certificate.der().to_vec(),
                root.der().to_vec(),
            ],
            root.der().to_vec(),
        )
        .expect("self-issued rollover must not consume a zero path-length allowance");
    }

    #[test]
    fn ca_name_constraints_reject_disallowed_dns_names() {
        let mut root_params = generated_certificate_params("constrained authority", true);
        root_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("example.com".into())],
            excluded_subtrees: vec![rcgen::GeneralSubtree::DnsName("blocked.example.com".into())],
        });
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("constrained root should be self-signable");

        for (dns_name, accepted) in [
            ("www.example.com", true),
            ("blocked.example.com", false),
            ("www.example.net", false),
        ] {
            let leaf = rcgen::CertificateParams::new(vec![dns_name.into()])
                .expect("DNS SAN should be valid")
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign leaf certificate");
            assert_eq!(
                verify_generated_path(
                    vec![leaf.der().to_vec(), root.der().to_vec()],
                    root.der().to_vec(),
                )
                .is_ok(),
                accepted,
                "unexpected name-constraint result for {dns_name}"
            );
        }
    }

    #[test]
    fn rfc5280_dns_names_require_preferred_name_syntax() {
        let mut root_params = generated_certificate_params("DNS syntax authority", true);
        root_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("example.com".into())],
            excluded_subtrees: Vec::new(),
        });
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("constrained root should be self-signable");

        let mut leaf_params = generated_certificate_params("malformed DNS leaf", false);
        let dns_name = b"bad..example.com";
        let mut san_der = vec![
            0x30,
            u8::try_from(dns_name.len() + 2).expect("test SAN must fit short-form DER"),
            0x82,
        ];
        san_der.push(u8::try_from(dns_name.len()).expect("test DNS name must fit short-form DER"));
        san_der.extend_from_slice(dns_name);
        leaf_params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                san_der,
            ));
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign malformed-DNS leaf");

        assert!(matches!(
            verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            ),
            Err(X509ChainError::InvalidDer {
                kind: "certificate DNS name",
                ..
            })
        ));

        for dns_name in ["*.example.com", "_signing.example.com"] {
            assert!(validate_rfc5280_dns_name(dns_name).is_err(), "{dns_name}");
        }
    }

    #[test]
    fn name_constraint_matchers_cover_email_uri_and_ip_forms() {
        // RFC 5280 gives each GeneralName form distinct subtree semantics;
        // exercise those rules directly so a DNS-only implementation cannot pass.
        assert!(email_within_subtree("ops@example.com", "example.com"));
        assert!(email_within_subtree("ops@example.com", "ops@example.com"));
        assert!(!email_within_subtree(
            "other@example.com",
            "ops@example.com"
        ));
        assert_eq!(
            uri_host("https://user@api.example.com:8443/path"),
            Some("api.example.com")
        );
        assert_eq!(
            uri_host("https://user@other@example.com/path"),
            None,
            "a second userinfo delimiter must not expose a constraint-matchable host"
        );
        assert!(dns_name_within_subtree(
            uri_host("https://api.example.com/path").expect("URI must expose a DNS host"),
            ".example.com",
            false,
        ));
        assert!(
            ip_address_within_subtree(&[192, 0, 2, 42], &[192, 0, 2, 0, 255, 255, 255, 0],)
                .expect("valid IPv4 constraint must evaluate")
        );
        assert!(
            !ip_address_within_subtree(&[192, 0, 3, 42], &[192, 0, 2, 0, 255, 255, 255, 0],)
                .expect("valid non-matching IPv4 constraint must evaluate")
        );
        assert!(matches!(
            ip_address_within_subtree(&[192, 0, 2, 42], &[192, 0, 2, 0, 255, 0, 255, 0],),
            Err(X509ChainError::InvalidDer {
                kind: "IP name constraint",
                ..
            })
        ));
    }

    #[test]
    fn malformed_ip_name_constraints_fail_before_matching() {
        use x509_parser::extensions::GeneralSubtree;

        let name = GeneralName::IPAddress(&[192, 0, 2, 42]);
        for malformed in [
            &[192, 0, 2, 0, 255, 255, 255][..],
            &[192, 0, 2, 0, 255, 0, 255, 0][..],
        ] {
            for permitted in [true, false] {
                let subtree = GeneralSubtree {
                    base: GeneralName::IPAddress(malformed),
                };
                let constraints = NameConstraints {
                    permitted_subtrees: permitted.then(|| vec![subtree.clone()]),
                    excluded_subtrees: (!permitted).then(|| vec![subtree]),
                };
                assert!(matches!(
                    validate_general_name(&name, &constraints, 0, 1),
                    Err(X509ChainError::InvalidDer {
                        kind: "IP name constraint",
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn malformed_string_name_constraints_fail_before_matching() {
        use x509_parser::extensions::GeneralSubtree;

        // Matchers assume admitted string constraints have RFC 5280 syntax.
        // Invalid values must not degrade into ordinary non-matches.
        for malformed in [
            GeneralName::DNSName(""),
            GeneralName::DNSName("example..com"),
            GeneralName::RFC822Name("@example.com"),
            GeneralName::RFC822Name("bad..local@example.com"),
            GeneralName::URI("https://example.com"),
        ] {
            let constraints = NameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: Some(vec![GeneralSubtree { base: malformed }]),
            };
            assert!(matches!(
                ensure_supported_name_constraints(&constraints, 1),
                Err(X509ChainError::InvalidDer {
                    kind: "string name constraint",
                    ..
                })
            ));
        }

        for valid in [
            GeneralName::DNSName("example.com"),
            GeneralName::DNSName(".example.com"),
            GeneralName::RFC822Name("ops@example.com"),
            GeneralName::RFC822Name("example.com"),
            GeneralName::URI(".example.com"),
        ] {
            let constraints = NameConstraints {
                permitted_subtrees: Some(vec![GeneralSubtree { base: valid }]),
                excluded_subtrees: None,
            };
            ensure_supported_name_constraints(&constraints, 1)
                .expect("valid string constraints must remain supported");
        }
    }

    #[test]
    fn empty_name_constraint_collections_are_rejected() {
        use der::Encode as _;
        use x509_cert::ext::pkix::NameConstraints as EncodedNameConstraints;

        // RFC 5280 requires at least one subtree overall and at least one entry
        // in every explicitly present GeneralSubtrees collection.
        for constraints in [
            EncodedNameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: None,
            },
            EncodedNameConstraints {
                permitted_subtrees: Some(Vec::new()),
                excluded_subtrees: None,
            },
            EncodedNameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: Some(Vec::new()),
            },
        ] {
            let der = constraints
                .to_der()
                .expect("malformed NameConstraints test input must encode");
            assert!(matches!(
                validate_name_constraints_der(&der, 1),
                Err(X509ChainError::InvalidNameConstraints { position: 1 })
            ));
        }
    }

    #[test]
    fn unsupported_name_constraint_distances_fail_path_validation() {
        use der::{Encode as _, asn1::Ia5String};
        use x509_cert::ext::pkix::{
            NameConstraints as EncodedNameConstraints,
            constraints::name::GeneralSubtree as EncodedGeneralSubtree,
            name::GeneralName as EncodedGeneralName,
        };

        // x509-parser exposes only GeneralSubtree::base. Exercise the complete
        // extension DER so unsupported distance fields cannot disappear before
        // RFC 5280 path validation sees them.
        for (permitted, minimum, maximum) in [
            (true, 1, None),
            (false, 1, None),
            (true, 0, Some(1)),
            (false, 0, Some(1)),
        ] {
            let dns_name = if permitted {
                "example.com"
            } else {
                "blocked.example.com"
            };
            let subtree = EncodedGeneralSubtree {
                base: EncodedGeneralName::DnsName(
                    Ia5String::new(dns_name.as_bytes()).expect("valid DNS IA5String"),
                ),
                minimum,
                maximum,
            };
            let constraints = EncodedNameConstraints {
                permitted_subtrees: permitted.then(|| vec![subtree.clone()]),
                excluded_subtrees: (!permitted).then(|| vec![subtree]),
            };
            let mut extension = rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 30],
                constraints
                    .to_der()
                    .expect("NameConstraints must encode as DER"),
            );
            extension.set_criticality(true);

            let mut root_params = generated_certificate_params("distance authority", true);
            root_params.custom_extensions.push(extension);
            let root = rcgen::CertifiedIssuer::self_signed(
                root_params,
                rcgen::KeyPair::generate().expect("root key generation should succeed"),
            )
            .expect("constrained root should be self-signable");
            let leaf = rcgen::CertificateParams::new(vec!["www.example.com".into()])
                .expect("leaf DNS SAN should be valid")
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign leaf certificate");

            assert!(matches!(
                verify_generated_path(
                    vec![leaf.der().to_vec(), root.der().to_vec()],
                    root.der().to_vec(),
                ),
                Err(X509ChainError::InvalidNameConstraints { position: 1 })
            ));
        }
    }

    #[test]
    fn name_constraints_cover_subject_email_and_directory_name() {
        // RFC 5280 requires subject emailAddress attributes to be checked even
        // without a SAN, and directoryName constraints compare RDN subtrees.
        let mut permitted_directory = rcgen::DistinguishedName::new();
        permitted_directory.push(rcgen::DnType::OrganizationName, "Example Corp");
        let mut root_params = generated_certificate_params("name authority", true);
        root_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![
                rcgen::GeneralSubtree::Rfc822Name("example.com".into()),
                rcgen::GeneralSubtree::DirectoryName(permitted_directory),
            ],
            excluded_subtrees: Vec::new(),
        });
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("constrained root should be self-signable");

        for (organization, email, accepted) in [
            ("Example Corp", "ops@example.com", true),
            ("Other Corp", "ops@example.com", false),
            ("Example Corp", "ops@example.net", false),
            ("Example Corp", "bad..local@example.com", false),
        ] {
            let mut leaf_params = generated_certificate_params("name-constrained leaf", false);
            leaf_params.distinguished_name = rcgen::DistinguishedName::new();
            leaf_params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, organization);
            leaf_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "name-constrained leaf");
            leaf_params.distinguished_name.push(
                rcgen::DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
                rcgen::DnValue::Ia5String(
                    email
                        .try_into()
                        .expect("test email must be a valid IA5String"),
                ),
            );
            let leaf = leaf_params
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign leaf certificate");
            let result = verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "unexpected subject constraint result for {organization} / {email}: {result:?}",
            );
        }
    }

    #[test]
    fn empty_subject_requires_a_critical_nonempty_san() {
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("subject identity authority", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");

        let mut missing_san = rcgen::CertificateParams::new(Vec::new())
            .expect("empty SAN list should produce certificate parameters");
        missing_san.distinguished_name = rcgen::DistinguishedName::new();
        let missing_san = missing_san
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("test issuer should sign an empty-subject certificate");

        let mut noncritical_san = rcgen::CertificateParams::new(Vec::new())
            .expect("empty SAN list should produce certificate parameters");
        noncritical_san.distinguished_name = rcgen::DistinguishedName::new();
        // GeneralNames ::= SEQUENCE { dNSName [2] "a" }. Using a custom
        // extension is intentional because rcgen correctly marks its normal
        // SAN extension critical whenever the subject is empty.
        noncritical_san
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                vec![0x30, 0x03, 0x82, 0x01, b'a'],
            ));
        let noncritical_san = noncritical_san
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("test issuer should sign a non-critical-SAN certificate");

        for leaf in [missing_san, noncritical_san] {
            assert!(matches!(
                verify_generated_path(
                    vec![leaf.der().to_vec(), root.der().to_vec()],
                    root.der().to_vec(),
                ),
                Err(X509ChainError::InvalidDer {
                    kind: "certificate subject identity",
                    ..
                })
            ));
        }
    }

    #[test]
    fn empty_subject_with_critical_san_skips_directory_name_constraints() {
        // RFC 5280 permits an empty subject when a critical SAN carries the
        // identity. An absent DirectoryName need not match a permitted subtree.
        let mut permitted_directory = rcgen::DistinguishedName::new();
        permitted_directory.push(rcgen::DnType::OrganizationName, "Example Corp");
        let mut root_params = generated_certificate_params("empty-subject authority", true);
        root_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DirectoryName(permitted_directory)],
            excluded_subtrees: Vec::new(),
        });
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("constrained root should be self-signable");
        let mut leaf_params = rcgen::CertificateParams::new(vec!["allowed.example".into()])
            .expect("DNS SAN should be valid");
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign empty-subject leaf");

        verify_generated_path(
            vec![leaf.der().to_vec(), root.der().to_vec()],
            root.der().to_vec(),
        )
        .expect("only present name forms should be constrained");
    }

    #[test]
    fn malformed_general_names_in_san_fail_path_validation() {
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("malformed-SAN root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        for empty_subject in [true, false] {
            let mut leaf_params = generated_certificate_params("malformed-SAN leaf", false);
            if empty_subject {
                leaf_params.distinguished_name = rcgen::DistinguishedName::new();
            }
            // GeneralNames ::= SEQUENCE { dNSName [2] <invalid IA5 octet> }.
            let mut malformed_san = rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                vec![0x30, 0x03, 0x82, 0x01, 0xff],
            );
            malformed_san.set_criticality(true);
            leaf_params.custom_extensions.push(malformed_san);
            let leaf = leaf_params
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign malformed-SAN leaf");

            assert!(matches!(
                verify_generated_path(
                    vec![leaf.der().to_vec(), root.der().to_vec()],
                    root.der().to_vec(),
                ),
                Err(X509ChainError::InvalidDer {
                    kind: "certificate subject identity",
                    ..
                })
            ));
        }
    }

    #[test]
    fn typed_subject_alternative_names_require_rfc5280_syntax() {
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("typed-SAN root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");

        for (tag, value) in [
            (0x81, b"operator@".as_slice()),
            (0x81, b"first..last@example.com".as_slice()),
            (0x86, b"relative/path".as_slice()),
            (0x86, b"https://example.com/%zz".as_slice()),
            (0x86, b"https://user@other@example.com/path".as_slice()),
            (0x86, b"file:///path".as_slice()),
            (0x87, &[192, 0, 2][..]),
        ] {
            for empty_subject in [false, true] {
                let mut leaf_params = generated_certificate_params("typed-SAN leaf", false);
                if empty_subject {
                    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
                }
                let mut san_der = vec![
                    0x30,
                    u8::try_from(value.len() + 2).expect("test SAN must fit short-form DER"),
                    tag,
                    u8::try_from(value.len()).expect("test GeneralName must fit short-form DER"),
                ];
                san_der.extend_from_slice(value);
                let mut san = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], san_der);
                san.set_criticality(true);
                leaf_params.custom_extensions.push(san);
                let leaf = leaf_params
                    .signed_by(
                        &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                        &root,
                    )
                    .expect("root should sign typed-SAN leaf");

                assert!(matches!(
                    verify_generated_path(
                        vec![leaf.der().to_vec(), root.der().to_vec()],
                        root.der().to_vec(),
                    ),
                    Err(X509ChainError::InvalidDer {
                        kind: "certificate subject identity",
                        ..
                    })
                ));
            }
        }

        for (tag, value) in [
            (0x81, b"operator@example.com".as_slice()),
            (0x81, b"operator@[192.0.2.1]".as_slice()),
            (0x81, b"operator@[IPv6:2001:db8::1]".as_slice()),
            (0x81, br#""operator desk"@example.com"#.as_slice()),
            (0x86, b"urn:example:operator".as_slice()),
            (
                0x86,
                b"https://operator@example.com:8443/path?q=1#id".as_slice(),
            ),
            (0x87, &[192, 0, 2, 1][..]),
            (
                0x87,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..],
            ),
        ] {
            let mut leaf_params = rcgen::CertificateParams::new(Vec::new())
                .expect("empty SAN list should produce certificate parameters");
            leaf_params.distinguished_name = rcgen::DistinguishedName::new();
            let mut san_der = vec![
                0x30,
                u8::try_from(value.len() + 2).expect("test SAN must fit short-form DER"),
                tag,
                u8::try_from(value.len()).expect("test GeneralName must fit short-form DER"),
            ];
            san_der.extend_from_slice(value);
            let mut san = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], san_der);
            san.set_criticality(true);
            leaf_params.custom_extensions.push(san);
            let leaf = leaf_params
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign typed-SAN leaf");

            verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            )
            .expect("valid typed SAN identity must satisfy an empty subject");
        }
    }

    fn parsed_merlin_crl(der: &[u8]) -> CertificateRevocationList<'_> {
        CertificateRevocationList::from_der(der)
            .expect("modified Merlin CRL must remain parseable")
            .1
    }

    fn merlin_crl_der() -> Vec<u8> {
        let xml = include_str!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt-crl.xml"
        );
        let document = Document::parse(xml).expect("tracked Merlin document must parse");
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .expect("tracked Merlin document contains KeyInfo");
        let key_info = parse_key_info(key_info_node).expect("tracked Merlin KeyInfo must parse");
        let KeyInfoSource::X509Data(info) = &key_info.sources[0] else {
            panic!("expected X509Data")
        };
        info.crls[0].clone()
    }

    #[test]
    fn duplicate_crl_and_entry_extension_oids_fail_closed() {
        use der::{Decode as _, Encode as _};
        use x509_cert::crl::CertificateList;

        let original = merlin_crl_der();
        let mut duplicate_crl: CertificateList =
            CertificateList::from_der(&original).expect("tracked Merlin CRL must decode");
        let extensions = duplicate_crl
            .tbs_cert_list
            .crl_extensions
            .as_mut()
            .expect("tracked Merlin CRL must contain extensions");
        extensions.push(extensions[0].clone());
        let duplicate_crl = duplicate_crl
            .to_der()
            .expect("duplicate CRL extension test vector must encode");
        assert_eq!(
            validate_crl_extensions(&parsed_merlin_crl(&duplicate_crl), 0),
            Err(X509ChainError::InvalidCrl(0))
        );

        let mut duplicate_entry: CertificateList =
            CertificateList::from_der(&original).expect("tracked Merlin CRL must decode");
        let duplicate = duplicate_entry
            .tbs_cert_list
            .crl_extensions
            .as_ref()
            .and_then(|extensions| extensions.first())
            .expect("tracked Merlin CRL must contain an extension")
            .clone();
        let revoked = duplicate_entry
            .tbs_cert_list
            .revoked_certificates
            .as_mut()
            .and_then(|entries| entries.first_mut())
            .expect("tracked Merlin CRL must contain a revoked entry");
        revoked.crl_entry_extensions = Some(vec![duplicate.clone(), duplicate]);
        let duplicate_entry = duplicate_entry
            .to_der()
            .expect("duplicate entry extension test vector must encode");
        assert_eq!(
            validate_crl_extensions(&parsed_merlin_crl(&duplicate_entry), 0),
            Err(X509ChainError::InvalidCrl(0))
        );
    }

    #[test]
    fn delta_crl_indicator_is_rejected_regardless_of_criticality() {
        use der::{Decode as _, Encode as _, asn1::OctetString};
        use x509_cert::{crl::CertificateList, ext::Extension};

        let original = merlin_crl_der();
        for critical in [false, true] {
            let mut encoded: CertificateList =
                CertificateList::from_der(&original).expect("tracked Merlin CRL must decode");
            encoded
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_default()
                .push(Extension {
                    extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27"),
                    critical,
                    extn_value: OctetString::new([0x02, 0x01, 0x01])
                        .expect("DER INTEGER extension payload must be valid"),
                });
            let encoded = encoded
                .to_der()
                .expect("delta CRL indicator test vector must encode");
            assert_eq!(
                validate_crl_extensions(&parsed_merlin_crl(&encoded), 0),
                Err(X509ChainError::InvalidCrl(0)),
                "delta CRL indicator criticality must not change unsupported semantics"
            );
        }
    }

    #[test]
    fn unevaluable_uri_names_fail_closed_for_both_constraint_forms() {
        use x509_parser::extensions::GeneralSubtree;

        // A URI without a DNS host is not a non-match: treating it that way
        // would bypass excluded URI subtrees while rejecting permitted ones.
        let uri = GeneralName::URI("urn:example:opaque");
        for constraints in [
            NameConstraints {
                permitted_subtrees: Some(vec![GeneralSubtree {
                    base: GeneralName::URI(".example.com"),
                }]),
                excluded_subtrees: None,
            },
            NameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: Some(vec![GeneralSubtree {
                    base: GeneralName::URI(".example.com"),
                }]),
            },
        ] {
            assert_eq!(
                validate_general_name(&uri, &constraints, 0, 1),
                Err(X509ChainError::NameConstraintViolation {
                    position: 0,
                    constraining_position: 1,
                })
            );
        }
    }

    #[test]
    fn unknown_critical_certificate_extension_fails_closed() {
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("critical-extension root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let mut leaf_params = generated_certificate_params("critical-extension leaf", false);
        let mut extension =
            rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![0x05, 0x00]);
        extension.set_criticality(true);
        leaf_params.custom_extensions.push(extension);
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign leaf certificate");

        assert_eq!(
            verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            ),
            Err(X509ChainError::UnsupportedCriticalExtension {
                position: 0,
                oid: "1.2.3.4".into(),
            })
        );
    }

    #[test]
    fn duplicate_certificate_extension_oids_fail_closed() {
        // RFC 5280 forbids repeated extension OIDs. Enforce that certificate-wide
        // invariant before individual extension consumers select a first match.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("duplicate-extension root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let mut leaf_params = generated_certificate_params("duplicate-extension leaf", false);
        for _ in 0..2 {
            leaf_params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 2, 3, 4],
                    vec![0x05, 0x00],
                ));
        }
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign leaf certificate");

        assert_eq!(
            verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            ),
            Err(X509ChainError::DuplicateExtension {
                position: 0,
                oid: "1.2.3.4".into(),
            })
        );
    }

    #[test]
    fn invalid_certificate_serial_numbers_fail_path_validation() {
        for serial in [vec![0], vec![1; 21]] {
            let root = rcgen::CertifiedIssuer::self_signed(
                generated_certificate_params("serial root", true),
                rcgen::KeyPair::generate().expect("root key generation should succeed"),
            )
            .expect("root should be self-signable");
            let mut leaf_params = generated_certificate_params("invalid serial leaf", false);
            leaf_params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
            let leaf = leaf_params
                .signed_by(
                    &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                    &root,
                )
                .expect("root should sign leaf certificate");

            assert!(matches!(
                verify_generated_path(
                    vec![leaf.der().to_vec(), root.der().to_vec()],
                    root.der().to_vec(),
                ),
                Err(X509ChainError::InvalidDer {
                    kind: "certificate serial number",
                    ..
                })
            ));
        }

        assert!(validate_certificate_serial_bytes(&[0x80]).is_err());
        assert!(validate_certificate_serial_bytes(&[1; 20]).is_ok());

        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("serial-padding root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let mut leaf_params = generated_certificate_params("serial-padding leaf", false);
        leaf_params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x80; 20]));
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign a maximum-magnitude serial");

        verify_generated_path(
            vec![leaf.der().to_vec(), root.der().to_vec()],
            root.der().to_vec(),
        )
        .expect("a 20-octet magnitude may require a DER sign-padding octet");
    }

    #[test]
    fn name_constraints_are_rejected_on_end_entity_certificates() {
        // RFC 5280 limits NameConstraints to critical CA extensions; merely
        // parsing the extension on an end entity must not count as processing it.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("name-placement root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let mut leaf_params = generated_certificate_params("name-placement leaf", false);
        leaf_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("example.com".into())],
            excluded_subtrees: Vec::new(),
        });
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign leaf certificate");

        assert!(matches!(
            verify_generated_path(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                root.der().to_vec(),
            ),
            Err(X509ChainError::InvalidNameConstraints { position: 0 })
        ));
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
