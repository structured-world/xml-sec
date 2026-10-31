use crate::{Change, Direction, Error, Profile};
use std::collections::{BTreeMap, BTreeSet};
use toml::{Table, Value};
#[cfg(feature = "xmlenc")]
use xml_sec::policy::{DecryptionPolicy, EncryptionPolicy};
#[cfg(feature = "xmlenc")]
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
};
use xml_sec::{
    policy::{
        CertificateSignatureAlgorithms, CompiledPolicies, DetachedDigestAttestation, DsaKeyPolicy,
        EcdsaSignatureValueEncoding, ExtendedKeyPurpose, HmacPolicy, Instant,
        KemContentAuthentication, KeyAgreementAlgorithm, KeyDerivationAlgorithm,
        KeyEstablishmentPolicy, KeySourceKind, KeySourcePolicy, KeyTrustPolicy, ManifestProcessing,
        OpcRelationshipEdition, PolicySet, PolicyValidity, ResourcePolicy, RsaKeyPolicy,
        RsaPssPermission, SameDocumentIdSemantics, SignatureConstraints, SigningPolicy,
        TimestampTokenEncoding, TransformPolicy, UriPolicy, VerificationPolicy,
        VerificationTrustMode, XmlInputPolicy, XsltStylesheetSemantics,
    },
    provider::{KeyEncapsulationAlgorithm, X509SignatureAlgorithm},
    xmldsig::{
        DigestAlgorithm, RsaPssParameters, SignatureAlgorithm, UriTypeSet, XPathHereSemantics,
    },
};

fn invalid(field: &str) -> Error {
    Error::Schema(format!("unknown, inapplicable or invalid setting {field}"))
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Error> {
    value.as_str().ok_or_else(|| invalid(field))
}
fn boolean(value: &Value, field: &str) -> Result<bool, Error> {
    value.as_bool().ok_or_else(|| invalid(field))
}
fn number(value: &Value, field: &str) -> Result<usize, Error> {
    value
        .as_integer()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| invalid(field))
}

fn timestamp(value: &Value, field: &str) -> Result<Instant, Error> {
    let (seconds, nanos) = if let Some(seconds) = value.as_integer() {
        (seconds, 0)
    } else {
        let t = table(value, field)?;
        if t.len() != 2 {
            return Err(invalid(field));
        }
        let seconds = t
            .get("seconds")
            .and_then(Value::as_integer)
            .ok_or_else(|| invalid(field))?;
        let nanos = t
            .get("nanoseconds")
            .and_then(Value::as_integer)
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v < 1_000_000_000)
            .ok_or_else(|| invalid(field))?;
        (seconds, nanos)
    };
    let nanos = u32::try_from(nanos).map_err(|_| invalid(field))?;
    Instant::new(seconds, nanos).ok_or_else(|| invalid(field))
}

fn timestamp_value(time: Instant) -> Result<Value, Error> {
    // Settings store POSIX seconds, which cannot name an inserted leap second.
    if time.is_leap_second() {
        return Err(invalid("timestamp range"));
    }
    Ok(Value::Table(Table::from_iter([
        ("seconds".into(), Value::Integer(time.seconds())),
        (
            "nanoseconds".into(),
            Value::Integer(i64::from(time.nanos())),
        ),
    ])))
}
fn table<'a>(value: &'a Value, field: &str) -> Result<&'a Table, Error> {
    value.as_table().ok_or_else(|| invalid(field))
}
fn strings<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>, Error> {
    value
        .as_array()
        .ok_or_else(|| invalid(field))?
        .iter()
        .map(|v| string(v, field))
        .collect()
}
fn selected<T: Ord>(
    value: &Value,
    field: &str,
    parse: impl Fn(&Value) -> Result<T, Error>,
) -> Result<BTreeSet<T>, Error> {
    let mut output = BTreeSet::new();
    for value in value.as_array().ok_or_else(|| invalid(field))? {
        if !output.insert(parse(value)?) {
            return Err(Error::Schema(format!("duplicate selection in {field}")));
        }
    }
    Ok(output)
}
fn optional<T: Ord>(
    value: &Value,
    field: &str,
    parse: impl Fn(&Value) -> Result<T, Error>,
) -> Result<Option<BTreeSet<T>>, Error> {
    if value.as_str() == Some("default") {
        Ok(None)
    } else {
        Ok(Some(selected(value, field, parse)?))
    }
}
fn digest(v: &Value) -> Result<DigestAlgorithm, Error> {
    DigestAlgorithm::from_uri(string(v, "digest")?).ok_or_else(|| invalid("digest URI"))
}

fn signature(v: &Value) -> Result<SignatureAlgorithm, Error> {
    if let Some(uri) = v.as_str() {
        return SignatureAlgorithm::from_uri(uri).ok_or_else(|| invalid("signature URI"));
    }
    let t = table(v, "signature")?;
    if t.len() != 4 {
        return Err(invalid("parameterized signature fields"));
    }
    let get = |key| t.get(key).ok_or_else(|| invalid(key));
    let method = SignatureAlgorithm::from_uri(string(get("uri")?, "uri")?)
        .ok_or_else(|| invalid("signature URI"))?;
    if !matches!(method, SignatureAlgorithm::RsaPss(_)) {
        return Err(invalid("parameters on non-PSS method"));
    }
    Ok(SignatureAlgorithm::RsaPss(RsaPssParameters {
        digest: digest(get("digest")?)?,
        mgf_digest: digest(get("mgf_digest")?)?,
        salt_len: number(get("salt_len")?, "salt_len")?,
    }))
}

fn certificate(v: &Value) -> Result<X509SignatureAlgorithm, Error> {
    let t = table(v, "certificate algorithm")?;
    let kind = string(t.get("kind").ok_or_else(|| invalid("kind"))?, "kind")?;
    let d = || digest(t.get("digest").ok_or_else(|| invalid("digest"))?);
    let result = match kind {
        "Dsa" if t.len() == 2 => X509SignatureAlgorithm::Dsa(d()?),
        "RsaPkcs1v15" if t.len() == 2 => X509SignatureAlgorithm::RsaPkcs1v15(d()?),
        "Ecdsa" if t.len() == 2 => X509SignatureAlgorithm::Ecdsa(d()?),
        "RsaPss" if t.len() == 4 => X509SignatureAlgorithm::RsaPss {
            digest: d()?,
            mgf_digest: digest(t.get("mgf_digest").ok_or_else(|| invalid("mgf_digest"))?)?,
            salt_len: number(
                t.get("salt_len").ok_or_else(|| invalid("salt_len"))?,
                "salt_len",
            )?,
        },
        "Ed25519" if t.len() == 1 => X509SignatureAlgorithm::Ed25519,
        "Ed448" if t.len() == 1 => X509SignatureAlgorithm::Ed448,
        "PostQuantum" if t.len() == 2 => {
            match signature(t.get("uri").ok_or_else(|| invalid("uri"))?)? {
                SignatureAlgorithm::PostQuantum(pq) => X509SignatureAlgorithm::PostQuantum(pq),
                _ => return Err(invalid("PQ certificate algorithm")),
            }
        }
        _ => return Err(invalid("certificate algorithm fields")),
    };
    Ok(result)
}

macro_rules! choice {
    ($value:expr, $field:expr, $($variant:path),+ $(,)?) => {{
        let name = string($value, $field)?;
        match name { $(s if stringify!($variant).rsplit("::").next().is_some_and(|v| v.trim() == s) => $variant,)+ _ => return Err(invalid($field)) }
    }};
}

fn signature_constraints(value: &Value) -> Result<SignatureConstraints, Error> {
    Ok(choice!(
        value,
        "signature_constraints",
        SignatureConstraints::General,
        SignatureConstraints::Saml,
        SignatureConstraints::WsSecurity,
        SignatureConstraints::Xades
    ))
}

macro_rules! resource_fields {
    ($apply:ident $(, $arg:expr)*) => { $apply!($($arg,)*
        max_xml_nodes, max_xml_depth, max_xml_namespace_bindings, max_references, max_signatures,
        max_transforms_per_reference, max_xml_base_components, max_xml_base_resolution_bytes,
        max_canonicalized_bytes, max_external_resource_bytes, max_external_resource_total_bytes,
        max_detached_payload_bytes, max_detached_payload_total_bytes,
        max_encryption_plaintext_bytes, max_xml_document_bytes, max_xml_parse_work_bytes,
        max_encryption_recipients, max_encryption_metadata_bytes, max_key_candidates,
        max_x509_work, max_x509_workspace_bytes, max_key_import_kdf_work, max_key_import_kdf_memory_bytes,
        max_key_info_reference_depth, max_base64_transform_input_bytes, max_base64_transform_output_bytes,
        max_xpath_expressions, max_xpath_expression_bytes, max_xpath_expression_complexity,
        max_xpath_context_evaluations, max_xpath_evaluation_work, max_xpath_mirror_string_bytes,
        max_xpath_string_work_bytes, max_xpath_namespace_bindings, max_xpath_namespace_bytes,
        max_xpath_filters, max_node_set_filter_work, max_node_set_entries, max_node_set_owned_string_bytes,
        max_node_set_cumulative_owned_string_bytes, max_opc_parameter_bytes, max_opc_workspace_bytes,
        max_xslt_work, max_xslt_workspace_bytes, max_xslt_output_bytes, max_xslt_recursion_depth
    ) };
}
macro_rules! update_numbers {
    ($p:expr, $v:expr, $($field:ident),+ $(,)?) => {{
        for (key, value) in table($v, "limits")? { match key.as_str() { $(stringify!($field) => $p.$field = number(value, key)?,)+ _ => return Err(invalid(key)) } }
    }};
}
fn resources(p: &mut ResourcePolicy, v: &Value) -> Result<(), Error> {
    resource_fields!(update_numbers, p, v);
    Ok(())
}

fn uris(p: &mut UriPolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "uris")? {
        let list = strings(value, key)?;
        let mut empty = false;
        let mut same = false;
        let mut external = false;
        let mut seen = BTreeSet::new();
        for name in list {
            if !seen.insert(name) {
                return Err(invalid(key));
            }
            match name {
                "empty" => empty = true,
                "same-document" => same = true,
                "external" => external = true,
                _ => return Err(invalid(key)),
            }
        }
        let set = UriTypeSet::new(empty, same, external);
        match key.as_str() {
            "references" => p.references = set,
            "retrieval_methods" => p.retrieval_methods = set,
            "key_info_references" => p.key_info_references = set,
            _ => return Err(invalid(key)),
        }
    }
    Ok(())
}
fn transforms(p: &mut TransformPolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "transforms")? {
        match key.as_str() {
            "allowed_algorithms" => {
                p.allowed_algorithms = optional(value, key, |v| Ok(string(v, key)?.to_owned()))?;
            }
            "xpath_here_semantics" => {
                p.xpath_here_semantics = choice!(
                    value,
                    key,
                    XPathHereSemantics::Specification,
                    XPathHereSemantics::XmlSecLegacy
                );
            }
            "same_document_id_semantics" => {
                p.same_document_id_semantics = choice!(
                    value,
                    key,
                    SameDocumentIdSemantics::Specification,
                    SameDocumentIdSemantics::XmlSecBarename,
                    SameDocumentIdSemantics::XmlSecVisa3d
                );
            }
            "opc_relationship_edition" => {
                p.opc_relationship_edition = choice!(
                    value,
                    key,
                    OpcRelationshipEdition::Ecma2012,
                    OpcRelationshipEdition::Ecma2021
                );
            }
            "xslt_stylesheet_semantics" => {
                p.xslt_stylesheet_semantics = choice!(
                    value,
                    key,
                    XsltStylesheetSemantics::Specification,
                    XsltStylesheetSemantics::Libxmlsec1
                );
            }
            _ => return Err(invalid(key)),
        }
    }
    Ok(())
}
fn key_establishment(p: &mut KeyEstablishmentPolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "key_establishment")? {
        match key.as_str() {
            "agreement_algorithms" => {
                p.agreement_algorithms = optional(value, key, |v| {
                    KeyAgreementAlgorithm::from_uri(string(v, key)?).ok_or_else(|| invalid(key))
                })?;
            }
            "derivation_algorithms" => {
                p.derivation_algorithms = optional(value, key, |v| {
                    KeyDerivationAlgorithm::from_uri(string(v, key)?).ok_or_else(|| invalid(key))
                })?;
            }
            "digest_algorithms" => p.digest_algorithms = optional(value, key, digest)?,
            "encapsulation_algorithms" => {
                p.encapsulation_algorithms = selected(value, key, |v| {
                    KeyEncapsulationAlgorithm::from_uri(string(v, key)?).ok_or_else(|| invalid(key))
                })?;
            }
            "kem_content_authentication" => {
                p.kem_content_authentication = choice!(
                    value,
                    key,
                    KemContentAuthentication::RequireAuthenticatedCipher,
                    KemContentAuthentication::ExternalAuthenticated
                );
            }
            "max_encapsulation_operations" => p.max_encapsulation_operations = number(value, key)?,
            "max_hash_blocks" => p.max_hash_blocks = number(value, key)?,
            "max_owned_bytes" => p.max_owned_bytes = number(value, key)?,
            "max_dh_modulus_bits" => p.max_dh_modulus_bits = number(value, key)?,
            "minimum_dh_modulus_bits" => p.minimum_dh_modulus_bits = number(value, key)?,
            "minimum_dh_subgroup_bits" => p.minimum_dh_subgroup_bits = number(value, key)?,
            "max_modular_work" => p.max_modular_work = number(value, key)?,
            _ => return Err(invalid(key)),
        }
    }
    Ok(())
}
fn validity(p: &mut Option<PolicyValidity>, v: &Value) -> Result<(), Error> {
    if v.as_str() == Some("none") {
        return if p.is_none() {
            Ok(())
        } else {
            Err(invalid("removing authorization"))
        };
    }
    let grant = p
        .as_mut()
        .ok_or_else(|| invalid("validity requires caller-authenticated authorization"))?;
    for (key, value) in table(v, "validity")? {
        match key.as_str() {
            "authorization_id" if string(value, key)? == grant.authorization_id => {}
            "authority" if string(value, key)? == grant.authority => {}
            "reason" if string(value, key)? == grant.reason => {}
            "not_before" => grant.not_before = timestamp(value, key)?,
            "expires_at" => grant.expires_at = timestamp(value, key)?,
            _ => return Err(invalid(key)),
        }
    }
    Ok(())
}
fn hmac(p: &mut HmacPolicy, v: &Value) -> Result<(), Error> {
    update_numbers!(p, v, minimum_key_bits, minimum_output_bits);
    Ok(())
}
fn rsa(p: &mut RsaKeyPolicy, v: &Value) -> Result<(), Error> {
    update_numbers!(p, v, minimum_modulus_bits);
    Ok(())
}
fn dsa(p: &mut DsaKeyPolicy, v: &Value) -> Result<(), Error> {
    update_numbers!(p, v, minimum_modulus_bits);
    Ok(())
}
fn xml(p: &mut XmlInputPolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "xml")? {
        if key != "allow_internal_dtd" {
            return Err(invalid(key));
        }
        p.allow_internal_dtd = boolean(value, key)?;
    }
    Ok(())
}
fn key_sources(p: &mut KeySourcePolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "key_sources")? {
        let source = match key.as_str() {
            "preset_key" => KeySourceKind::PresetKey,
            "key_name" => KeySourceKind::KeyName,
            "key_value" => KeySourceKind::KeyValue,
            "der_encoded_key_value" => KeySourceKind::DerEncodedKeyValue,
            "x509_data" => KeySourceKind::X509Data,
            "key_info_reference" => KeySourceKind::KeyInfoReference,
            _ => return Err(invalid(key)),
        };
        p.set(source, boolean(value, key)?);
    }
    Ok(())
}
fn purpose(v: &Value) -> Result<ExtendedKeyPurpose, Error> {
    if let Some(name) = v.as_str() {
        return Ok(choice!(
            v,
            name,
            ExtendedKeyPurpose::ServerAuth,
            ExtendedKeyPurpose::ClientAuth,
            ExtendedKeyPurpose::CodeSigning,
            ExtendedKeyPurpose::EmailProtection,
            ExtendedKeyPurpose::TimeStamping,
            ExtendedKeyPurpose::OcspSigning
        ));
    }
    let arcs = v
        .as_array()
        .ok_or_else(|| invalid("extended key purpose"))?
        .iter()
        .map(|v| match v {
            Value::String(v) => v.parse::<u64>().map_err(|_| invalid("OID arc")),
            Value::Integer(v) => u64::try_from(*v).map_err(|_| invalid("OID arc")),
            _ => Err(invalid("OID arc")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExtendedKeyPurpose::Other(arcs))
}
fn key_trust(p: &mut KeyTrustPolicy, v: &Value) -> Result<(), Error> {
    for (key, value) in table(v, "key_trust")? {
        match key.as_str() {
            "mode" => {
                p.mode = choice!(
                    value,
                    key,
                    VerificationTrustMode::RequireTrustedKey,
                    VerificationTrustMode::CryptographicOnly
                );
            }
            "verify_x509_chains" => p.verify_x509_chains = boolean(value, key)?,
            "check_crls" => p.check_crls = boolean(value, key)?,
            "max_x509_chain_depth" => p.max_x509_chain_depth = number(value, key)?,
            "max_x509_candidate_paths" => p.max_x509_candidate_paths = number(value, key)?,
            "rsa_keys" => rsa(&mut p.rsa_keys, value)?,
            "dsa_keys" => dsa(&mut p.dsa_keys, value)?,
            "allowed_legacy_signature_algorithms" => {
                p.allowed_legacy_signature_algorithms = selected(value, key, signature)?;
            }
            "parameterized_rsa_pss" => {
                p.parameterized_rsa_pss = choice!(
                    value,
                    key,
                    RsaPssPermission::ExactOnly,
                    RsaPssPermission::SecureSupported,
                    RsaPssPermission::AllSupported
                );
            }
            "certificate_signature_algorithms" => {
                p.certificate_signature_algorithms = if value.as_str() == Some("default") {
                    None
                } else if value.as_str() == Some("AllSupported") {
                    Some(CertificateSignatureAlgorithms::AllSupported)
                } else {
                    Some(CertificateSignatureAlgorithms::Allowlist(selected(
                        value,
                        key,
                        certificate,
                    )?))
                };
            }
            "allowed_extended_key_usages" => {
                p.allowed_extended_key_usages = selected(value, key, purpose)?;
            }
            "verification_time" => {
                p.verification_time = if value.as_str() == Some("system") {
                    None
                } else {
                    Some(timestamp(value, key)?)
                };
            }
            _ => return Err(invalid(key)),
        }
    }
    Ok(())
}

// Reuse the exact same field admissions for sign and verify. Encryption has
// different applicable fields and must not accidentally accept signing knobs.
macro_rules! signature_fields {
    ($p:expr, $key:expr, $value:expr) => {
        match $key.as_str() {
            "validity" => validity(&mut $p.validity, $value)?,
            "signature_constraints" => $p.signature_constraints = signature_constraints($value)?,
            "signature_algorithms" => $p.signature_algorithms = optional($value, $key, signature)?,
            "digest_algorithms" => $p.digest_algorithms = optional($value, $key, digest)?,
            "parameterized_rsa_pss" => {
                $p.parameterized_rsa_pss = choice!(
                    $value,
                    $key,
                    RsaPssPermission::ExactOnly,
                    RsaPssPermission::SecureSupported,
                    RsaPssPermission::AllSupported
                );
            }
            "ecdsa_signature_value_encoding" => {
                $p.ecdsa_signature_value_encoding = choice!(
                    $value,
                    $key,
                    EcdsaSignatureValueEncoding::XmlDsig,
                    EcdsaSignatureValueEncoding::XmlSecAsn1Der
                )
            }
            "manifest_processing" => {
                $p.manifest_processing = choice!(
                    $value,
                    $key,
                    ManifestProcessing::Ignore,
                    ManifestProcessing::Process
                )
            }
            "hmac" => hmac(&mut $p.hmac, $value)?,
            "uris" => uris(&mut $p.uris, $value)?,
            "transforms" => transforms(&mut $p.transforms, $value)?,
            "key_establishment" => key_establishment(&mut $p.key_establishment, $value)?,
            "resources" => resources(&mut $p.resources, $value)?,
            "xml" => xml(&mut $p.xml, $value)?,
            "enabled" => {}
            _ => return Err(invalid($key)),
        }
    };
}
fn fields(t: &Table, syntax_only: bool) -> impl Iterator<Item = (&String, &Value)> {
    t.iter()
        .filter(move |(key, _)| !syntax_only || key.as_str() != "validity")
}
fn verification(p: &mut VerificationPolicy, t: &Table, syntax_only: bool) -> Result<(), Error> {
    for (key, value) in fields(t, syntax_only) {
        match key.as_str() {
            "key_trust" => key_trust(&mut p.key_trust, value)?,
            "key_sources" => key_sources(&mut p.key_sources, value)?,
            "detached_digest_attestation" => {
                p.detached_digest_attestation = choice!(
                    value,
                    key,
                    DetachedDigestAttestation::Forbidden,
                    DetachedDigestAttestation::Accepted
                );
            }
            "timestamp_token_encoding" => {
                p.timestamp_token_encoding = choice!(
                    value,
                    key,
                    TimestampTokenEncoding::Declared,
                    TimestampTokenEncoding::Ber
                );
            }
            _ => signature_fields!(p, key, value),
        }
    }
    Ok(())
}
fn signing(p: &mut SigningPolicy, t: &Table, syntax_only: bool) -> Result<(), Error> {
    for (key, value) in fields(t, syntax_only) {
        match key.as_str() {
            "rsa_keys" => rsa(&mut p.rsa_keys, value)?,
            "dsa_keys" => dsa(&mut p.dsa_keys, value)?,
            _ => signature_fields!(p, key, value),
        }
    }
    Ok(())
}
#[cfg(feature = "xmlenc")]
macro_rules! encryption_fields {
    ($p:expr, $key:expr, $value:expr) => {
        match $key.as_str() {
            "validity" => validity(&mut $p.validity, $value)?,
            "data_algorithms" => {
                $p.data_algorithms = optional($value, $key, |v| {
                    DataEncryptionAlgorithm::from_uri(string(v, $key)?).map_err(|_| invalid($key))
                })?
            }
            "key_transport_algorithms" => {
                $p.key_transport_algorithms = optional($value, $key, |v| {
                    KeyTransportAlgorithm::from_uri(string(v, $key)?).map_err(|_| invalid($key))
                })?
            }
            "key_wrap_algorithms" => {
                $p.key_wrap_algorithms = optional($value, $key, |v| {
                    KeyWrapAlgorithm::from_uri(string(v, $key)?).map_err(|_| invalid($key))
                })?
            }
            "oaep_digests" => {
                $p.oaep_digests = optional($value, $key, |v| {
                    OaepDigestAlgorithm::from_uri(string(v, $key)?).ok_or_else(|| invalid($key))
                })?
            }
            "rsa_keys" => rsa(&mut $p.rsa_keys, $value)?,
            "key_establishment" => key_establishment(&mut $p.key_establishment, $value)?,
            "resources" => resources(&mut $p.resources, $value)?,
            "xml" => xml(&mut $p.xml, $value)?,
            "enabled" => {}
            _ => return Err(invalid($key)),
        }
    };
}
#[cfg(feature = "xmlenc")]
fn encryption(p: &mut EncryptionPolicy, t: &Table, syntax_only: bool) -> Result<(), Error> {
    for (key, value) in fields(t, syntax_only) {
        encryption_fields!(p, key, value);
    }
    Ok(())
}
#[cfg(feature = "xmlenc")]
fn decryption(p: &mut DecryptionPolicy, t: &Table, syntax_only: bool) -> Result<(), Error> {
    for (key, value) in fields(t, syntax_only) {
        match key.as_str() {
            "uris" => uris(&mut p.uris, value)?,
            "transforms" => transforms(&mut p.transforms, value)?,
            _ => encryption_fields!(p, key, value),
        }
    }
    Ok(())
}

fn enabled(t: &Table) -> Result<bool, Error> {
    let enabled = t
        .get("enabled")
        .map(|v| boolean(v, "enabled"))
        .transpose()?
        .unwrap_or(true);
    if !enabled && t.len() != 1 {
        return Err(invalid("disabled operation with settings"));
    }
    Ok(enabled)
}
pub(super) fn validate(operation: &str, t: &Table) -> Result<(), Error> {
    if !enabled(t)? {
        return Ok(());
    }
    // Validate syntax without authorizing a grant or running the provider.
    if let Some(v) = t.get("validity")
        && v.as_str() != Some("none")
    {
        for (key, v) in table(v, "validity")? {
            match key.as_str() {
                "authorization_id" | "authority" | "reason" => {
                    string(v, key)?;
                }
                "not_before" | "expires_at" => {
                    timestamp(v, key)?;
                }
                _ => return Err(invalid(key)),
            }
        }
    }
    match operation {
        "verification" => verification(&mut VerificationPolicy::default(), t, true),
        "signing" => signing(&mut SigningPolicy::default(), t, true),
        #[cfg(feature = "xmlenc")]
        "encryption" => encryption(&mut EncryptionPolicy::default(), t, true),
        #[cfg(feature = "xmlenc")]
        "decryption" => decryption(&mut DecryptionPolicy::default(), t, true),
        _ => Err(invalid(operation)),
    }
}
pub(super) fn apply(profile: &Profile, set: &mut PolicySet) -> Result<(), Error> {
    macro_rules! op {
        ($field:ident, $apply:ident) => {
            if let Some(t) = &profile.$field {
                if !enabled(t)? {
                    set.$field = None;
                } else {
                    let p = set
                        .$field
                        .as_mut()
                        .ok_or_else(|| invalid(concat!("re-enabling ", stringify!($field))))?;
                    $apply(p, t, false)?;
                }
            }
        };
    }
    op!(verification, verification);
    op!(signing, signing);
    #[cfg(feature = "xmlenc")]
    {
        op!(encryption, encryption);
        op!(decryption, decryption);
    }
    Ok(())
}

fn text(v: impl Into<String>) -> Value {
    Value::String(v.into())
}
fn int(v: usize) -> Value {
    Value::Integer(i64::try_from(v).expect("validated policy ceiling fits TOML integer"))
}
fn named(v: impl std::fmt::Debug) -> Value {
    text(format!("{v:?}"))
}
fn sorted<T>(values: impl IntoIterator<Item = T>, convert: impl Fn(T) -> Value) -> Value {
    let mut values: Vec<_> = values.into_iter().map(convert).collect();
    values.sort_by_cached_key(ToString::to_string);
    Value::Array(values)
}
fn optional_value<T: Copy>(set: Option<&BTreeSet<T>>, convert: impl Fn(T) -> Value) -> Value {
    match set {
        None => text("default"),
        Some(set) => sorted(set.iter().copied(), convert),
    }
}
fn signature_value(a: SignatureAlgorithm) -> Value {
    match a {
        SignatureAlgorithm::RsaPss(p) => Value::Table(Table::from_iter([
            ("uri".into(), text(a.uri())),
            ("digest".into(), text(p.digest.uri())),
            ("mgf_digest".into(), text(p.mgf_digest.uri())),
            ("salt_len".into(), int(p.salt_len)),
        ])),
        _ => text(a.uri()),
    }
}
fn certificate_value(a: X509SignatureAlgorithm) -> Result<Value, Error> {
    let (kind, digest) = match a {
        X509SignatureAlgorithm::Dsa(d) => ("Dsa", Some(d)),
        X509SignatureAlgorithm::RsaPkcs1v15(d) => ("RsaPkcs1v15", Some(d)),
        X509SignatureAlgorithm::Ecdsa(d) => ("Ecdsa", Some(d)),
        X509SignatureAlgorithm::RsaPss { digest, .. } => ("RsaPss", Some(digest)),
        X509SignatureAlgorithm::Ed25519 => ("Ed25519", None),
        X509SignatureAlgorithm::Ed448 => ("Ed448", None),
        X509SignatureAlgorithm::PostQuantum(_) => ("PostQuantum", None),
        _ => return Err(invalid("unrepresented certificate algorithm")),
    };
    let mut t = Table::new();
    t.insert("kind".into(), text(kind));
    if let Some(d) = digest {
        t.insert("digest".into(), text(d.uri()));
    }
    if let X509SignatureAlgorithm::RsaPss {
        mgf_digest,
        salt_len,
        ..
    } = a
    {
        t.insert("mgf_digest".into(), text(mgf_digest.uri()));
        t.insert("salt_len".into(), int(salt_len));
    }
    if let X509SignatureAlgorithm::PostQuantum(pq) = a {
        t.insert(
            "uri".into(),
            text(SignatureAlgorithm::PostQuantum(pq).uri()),
        );
    }
    Ok(Value::Table(t))
}
macro_rules! number_snapshot { ($p:expr, $($field:ident),+ $(,)?) => {{
    let ResourcePolicy { $($field: _,)+ } = $p;
    Value::Table(Table::from_iter([$( (stringify!($field).into(), int($p.$field)), )+]))
}}; }
fn resource_snapshot(p: &ResourcePolicy) -> Value {
    resource_fields!(number_snapshot, p)
}
fn uri_snapshot(p: UriPolicy) -> Value {
    let one = |s: UriTypeSet| {
        Value::Array(
            [
                (s.allows(""), "empty"),
                (s.allows("#id"), "same-document"),
                (s.allows("external"), "external"),
            ]
            .into_iter()
            .filter(|(allow, _)| *allow)
            .map(|(_, name)| text(name))
            .collect(),
        )
    };
    Value::Table(Table::from_iter([
        ("references".into(), one(p.references)),
        ("retrieval_methods".into(), one(p.retrieval_methods)),
        ("key_info_references".into(), one(p.key_info_references)),
    ]))
}
fn transform_snapshot(p: &TransformPolicy) -> Value {
    Value::Table(Table::from_iter([
        (
            "allowed_algorithms".into(),
            match &p.allowed_algorithms {
                None => text("default"),
                Some(s) => sorted(s.iter(), |s| text(s.clone())),
            },
        ),
        ("xpath_here_semantics".into(), named(p.xpath_here_semantics)),
        (
            "same_document_id_semantics".into(),
            named(p.same_document_id_semantics),
        ),
        (
            "opc_relationship_edition".into(),
            named(p.opc_relationship_edition),
        ),
        (
            "xslt_stylesheet_semantics".into(),
            named(p.xslt_stylesheet_semantics),
        ),
    ]))
}
fn establishment_snapshot(p: &KeyEstablishmentPolicy) -> Value {
    let KeyEstablishmentPolicy {
        encapsulation_algorithms: _,
        kem_content_authentication: _,
        max_encapsulation_operations: _,
        agreement_algorithms: _,
        derivation_algorithms: _,
        digest_algorithms: _,
        max_hash_blocks: _,
        max_owned_bytes: _,
        max_dh_modulus_bits: _,
        minimum_dh_modulus_bits: _,
        minimum_dh_subgroup_bits: _,
        max_modular_work: _,
    } = p;
    Value::Table(Table::from_iter([
        (
            "encapsulation_algorithms".into(),
            sorted(p.encapsulation_algorithms.iter().copied(), |v| {
                text(v.uri())
            }),
        ),
        (
            "kem_content_authentication".into(),
            named(p.kem_content_authentication),
        ),
        (
            "agreement_algorithms".into(),
            optional_value(p.agreement_algorithms.as_ref(), |v| text(v.uri())),
        ),
        (
            "derivation_algorithms".into(),
            optional_value(p.derivation_algorithms.as_ref(), |v| text(v.uri())),
        ),
        (
            "digest_algorithms".into(),
            optional_value(p.digest_algorithms.as_ref(), |v| text(v.uri())),
        ),
        (
            "max_encapsulation_operations".into(),
            int(p.max_encapsulation_operations),
        ),
        ("max_hash_blocks".into(), int(p.max_hash_blocks)),
        ("max_owned_bytes".into(), int(p.max_owned_bytes)),
        ("max_dh_modulus_bits".into(), int(p.max_dh_modulus_bits)),
        (
            "minimum_dh_modulus_bits".into(),
            int(p.minimum_dh_modulus_bits),
        ),
        (
            "minimum_dh_subgroup_bits".into(),
            int(p.minimum_dh_subgroup_bits),
        ),
        ("max_modular_work".into(), int(p.max_modular_work)),
    ]))
}
fn validity_snapshot(p: Option<&PolicyValidity>) -> Result<Value, Error> {
    Ok(match p {
        None => text("none"),
        Some(p) => Value::Table(Table::from_iter([
            ("authorization_id".into(), text(&p.authorization_id)),
            ("authority".into(), text(&p.authority)),
            ("reason".into(), text(&p.reason)),
            ("not_before".into(), timestamp_value(p.not_before)?),
            ("expires_at".into(), timestamp_value(p.expires_at)?),
        ])),
    })
}
fn xml_snapshot(p: XmlInputPolicy) -> Value {
    Value::Table(Table::from_iter([(
        "allow_internal_dtd".into(),
        Value::Boolean(p.allow_internal_dtd),
    )]))
}
fn rsa_snapshot(p: RsaKeyPolicy) -> Value {
    Value::Table(Table::from_iter([(
        "minimum_modulus_bits".into(),
        int(p.minimum_modulus_bits),
    )]))
}
fn dsa_snapshot(p: DsaKeyPolicy) -> Value {
    Value::Table(Table::from_iter([(
        "minimum_modulus_bits".into(),
        int(p.minimum_modulus_bits),
    )]))
}
fn trust_snapshot(p: &KeyTrustPolicy) -> Result<Value, Error> {
    let KeyTrustPolicy {
        mode: _,
        verify_x509_chains: _,
        max_x509_chain_depth: _,
        max_x509_candidate_paths: _,
        allowed_legacy_signature_algorithms: _,
        parameterized_rsa_pss: _,
        certificate_signature_algorithms: _,
        rsa_keys: _,
        dsa_keys: _,
        allowed_extended_key_usages: _,
        check_crls: _,
        verification_time: _,
    } = p;
    let purpose = |v: &ExtendedKeyPurpose| match v {
        ExtendedKeyPurpose::Other(arcs) => {
            Value::Array(arcs.iter().map(|v| text(v.to_string())).collect())
        }
        v => named(v),
    };
    Ok(Value::Table(Table::from_iter([
        ("mode".into(), named(p.mode)),
        (
            "verify_x509_chains".into(),
            Value::Boolean(p.verify_x509_chains),
        ),
        ("max_x509_chain_depth".into(), int(p.max_x509_chain_depth)),
        (
            "max_x509_candidate_paths".into(),
            int(p.max_x509_candidate_paths),
        ),
        (
            "allowed_legacy_signature_algorithms".into(),
            sorted(
                p.allowed_legacy_signature_algorithms.iter().copied(),
                signature_value,
            ),
        ),
        (
            "parameterized_rsa_pss".into(),
            named(p.parameterized_rsa_pss),
        ),
        (
            "certificate_signature_algorithms".into(),
            match &p.certificate_signature_algorithms {
                None => text("default"),
                Some(CertificateSignatureAlgorithms::AllSupported) => text("AllSupported"),
                Some(CertificateSignatureAlgorithms::Allowlist(set)) => {
                    let values = set
                        .iter()
                        .copied()
                        .map(certificate_value)
                        .collect::<Result<Vec<_>, _>>()?;
                    sorted(values, |v| v)
                }
            },
        ),
        ("rsa_keys".into(), rsa_snapshot(p.rsa_keys)),
        ("dsa_keys".into(), dsa_snapshot(p.dsa_keys)),
        (
            "allowed_extended_key_usages".into(),
            sorted(p.allowed_extended_key_usages.iter(), purpose),
        ),
        ("check_crls".into(), Value::Boolean(p.check_crls)),
        (
            "verification_time".into(),
            match p.verification_time {
                None => text("system"),
                Some(t) => timestamp_value(t)?,
            },
        ),
    ])))
}
fn source_snapshot(p: KeySourcePolicy) -> Value {
    Value::Table(
        KeySourceKind::ALL
            .into_iter()
            .map(|source| {
                let name = match source {
                    KeySourceKind::PresetKey => "preset_key",
                    KeySourceKind::KeyName => "key_name",
                    KeySourceKind::KeyValue => "key_value",
                    KeySourceKind::DerEncodedKeyValue => "der_encoded_key_value",
                    KeySourceKind::X509Data => "x509_data",
                    KeySourceKind::KeyInfoReference => "key_info_reference",
                };
                (name.into(), Value::Boolean(p.contains(source)))
            })
            .collect(),
    )
}
macro_rules! signature_snapshot {
    ($p:expr) => {
        Table::from_iter([
            ("enabled".into(), Value::Boolean(true)),
            ("validity".into(), validity_snapshot($p.validity.as_ref())?),
            (
                "signature_constraints".into(),
                named($p.signature_constraints),
            ),
            (
                "parameterized_rsa_pss".into(),
                named($p.parameterized_rsa_pss),
            ),
            (
                "signature_algorithms".into(),
                optional_value($p.signature_algorithms.as_ref(), signature_value),
            ),
            (
                "digest_algorithms".into(),
                optional_value($p.digest_algorithms.as_ref(), |v| text(v.uri())),
            ),
            (
                "hmac".into(),
                Value::Table(Table::from_iter([
                    ("minimum_key_bits".into(), int($p.hmac.minimum_key_bits)),
                    (
                        "minimum_output_bits".into(),
                        int($p.hmac.minimum_output_bits),
                    ),
                ])),
            ),
            (
                "ecdsa_signature_value_encoding".into(),
                named($p.ecdsa_signature_value_encoding),
            ),
            ("uris".into(), uri_snapshot($p.uris)),
            ("transforms".into(), transform_snapshot(&$p.transforms)),
            ("manifest_processing".into(), named($p.manifest_processing)),
            ("xml".into(), xml_snapshot($p.xml)),
            ("resources".into(), resource_snapshot(&$p.resources)),
            (
                "key_establishment".into(),
                establishment_snapshot(&$p.key_establishment),
            ),
        ])
    };
}
#[cfg(feature = "xmlenc")]
macro_rules! encryption_snapshot {
    ($p:expr) => {
        Table::from_iter([
            ("enabled".into(), Value::Boolean(true)),
            ("validity".into(), validity_snapshot($p.validity.as_ref())?),
            (
                "data_algorithms".into(),
                optional_value($p.data_algorithms.as_ref(), |v| text(v.uri())),
            ),
            (
                "key_transport_algorithms".into(),
                optional_value($p.key_transport_algorithms.as_ref(), |v| text(v.uri())),
            ),
            (
                "key_wrap_algorithms".into(),
                optional_value($p.key_wrap_algorithms.as_ref(), |v| text(v.uri())),
            ),
            (
                "oaep_digests".into(),
                optional_value($p.oaep_digests.as_ref(), |v| text(v.uri())),
            ),
            ("rsa_keys".into(), rsa_snapshot($p.rsa_keys)),
            (
                "key_establishment".into(),
                establishment_snapshot(&$p.key_establishment),
            ),
            ("xml".into(), xml_snapshot($p.xml)),
            ("resources".into(), resource_snapshot(&$p.resources)),
        ])
    };
}
// Each snapshot destructures its policy exhaustively, so a new policy field
// fails to compile until the effective-settings report covers it.
fn verification_snapshot(p: &VerificationPolicy) -> Result<Value, Error> {
    let VerificationPolicy {
        validity: _,
        signature_constraints: _,
        key_establishment: _,
        parameterized_rsa_pss: _,
        signature_algorithms: _,
        digest_algorithms: _,
        hmac: _,
        ecdsa_signature_value_encoding: _,
        key_trust: _,
        key_sources: _,
        uris: _,
        transforms: _,
        manifest_processing: _,
        detached_digest_attestation: _,
        timestamp_token_encoding: _,
        xml: _,
        resources: _,
    } = p;
    let mut t = signature_snapshot!(p);
    t.insert("key_trust".into(), trust_snapshot(&p.key_trust)?);
    t.insert("key_sources".into(), source_snapshot(p.key_sources));
    t.insert(
        "detached_digest_attestation".into(),
        named(p.detached_digest_attestation),
    );
    t.insert(
        "timestamp_token_encoding".into(),
        named(p.timestamp_token_encoding),
    );
    Ok(Value::Table(t))
}

fn signing_snapshot(p: &SigningPolicy) -> Result<Value, Error> {
    let SigningPolicy {
        validity: _,
        signature_constraints: _,
        key_establishment: _,
        parameterized_rsa_pss: _,
        signature_algorithms: _,
        digest_algorithms: _,
        hmac: _,
        ecdsa_signature_value_encoding: _,
        rsa_keys: _,
        dsa_keys: _,
        uris: _,
        transforms: _,
        manifest_processing: _,
        xml: _,
        resources: _,
    } = p;
    let mut t = signature_snapshot!(p);
    t.insert("rsa_keys".into(), rsa_snapshot(p.rsa_keys));
    t.insert("dsa_keys".into(), dsa_snapshot(p.dsa_keys));
    Ok(Value::Table(t))
}

#[cfg(feature = "xmlenc")]
fn encryption_policy_snapshot(p: &EncryptionPolicy) -> Result<Value, Error> {
    let EncryptionPolicy {
        validity: _,
        data_algorithms: _,
        key_transport_algorithms: _,
        key_wrap_algorithms: _,
        oaep_digests: _,
        rsa_keys: _,
        key_establishment: _,
        xml: _,
        resources: _,
    } = p;
    Ok(Value::Table(encryption_snapshot!(p)))
}

#[cfg(feature = "xmlenc")]
fn decryption_snapshot(p: &DecryptionPolicy) -> Result<Value, Error> {
    let DecryptionPolicy {
        validity: _,
        data_algorithms: _,
        key_transport_algorithms: _,
        key_wrap_algorithms: _,
        oaep_digests: _,
        rsa_keys: _,
        key_establishment: _,
        xml: _,
        resources: _,
        uris: _,
        transforms: _,
    } = p;
    let mut t = encryption_snapshot!(p);
    t.insert("uris".into(), uri_snapshot(p.uris));
    t.insert("transforms".into(), transform_snapshot(&p.transforms));
    Ok(Value::Table(t))
}

pub(super) fn snapshot(p: &CompiledPolicies) -> Result<Table, Error> {
    let disabled = || {
        Value::Table(Table::from_iter([(
            "enabled".into(),
            Value::Boolean(false),
        )]))
    };
    let mut output = Table::new();
    output.insert("base".into(), named(p.profile()));
    let verification = p
        .verification()
        .map_or_else(|| Ok(disabled()), verification_snapshot)?;
    output.insert("verification".into(), verification);
    let signing = p
        .signing()
        .map_or_else(|| Ok(disabled()), signing_snapshot)?;
    output.insert("signing".into(), signing);
    #[cfg(feature = "xmlenc")]
    {
        let encryption = p
            .encryption()
            .map_or_else(|| Ok(disabled()), encryption_policy_snapshot)?;
        output.insert("encryption".into(), encryption);
        let decryption = p
            .decryption()
            .map_or_else(|| Ok(disabled()), decryption_snapshot)?;
        output.insert("decryption".into(), decryption);
    }
    Ok(output)
}

fn flatten<'a>(
    table: &'a Table,
    peer: Option<&Table>,
    prefix: &str,
    output: &mut BTreeMap<String, &'a Value>,
) {
    for (key, value) in table {
        let field = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let other = if matches!(value, Value::Table(_)) {
            peer.and_then(|table| table.get(key))
        } else {
            None
        };
        // Presence changes are one validity constraint, not removal of a
        // sentinel plus unrelated additions of its interval and audit fields.
        if key == "validity" && other.and_then(Value::as_str) == Some("none") {
            output.insert(field, value);
            continue;
        }
        match value {
            Value::Table(t)
                if !matches!(
                    key.as_str(),
                    "not_before" | "expires_at" | "verification_time"
                ) =>
            {
                flatten(t, other.and_then(Value::as_table), &field, output);
            }
            _ => {
                output.insert(field, value);
            }
        }
    }
}
fn default_admits(field: &str, value: &Value) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field);
    let uri = value.as_str();
    // Interpret the core field's None contract, not a universal "allow all".
    // This is reporting only; permission enforcement remains in the compiler
    // and operation policies. Keep parsing borrowed and fail conservatively.
    match last {
        "allowed_algorithms" => uri.is_some(),
        "certificate_signature_algorithms" => {
            matches!(certificate(value), Ok(a) if !matches!(a, X509SignatureAlgorithm::PostQuantum(_)))
        }
        "agreement_algorithms" => matches!(
            uri.and_then(KeyAgreementAlgorithm::from_uri),
            Some(KeyAgreementAlgorithm::EcdhEs | KeyAgreementAlgorithm::X25519)
        ),
        "derivation_algorithms" => matches!(
            uri.and_then(KeyDerivationAlgorithm::from_uri),
            Some(
                KeyDerivationAlgorithm::ConcatKdf
                    | KeyDerivationAlgorithm::Hkdf
                    | KeyDerivationAlgorithm::Pbkdf2
            )
        ),
        "digest_algorithms" if field.contains(".key_establishment.") => matches!(
            uri.and_then(DigestAlgorithm::from_uri),
            Some(
                DigestAlgorithm::Sha224
                    | DigestAlgorithm::Sha256
                    | DigestAlgorithm::Sha384
                    | DigestAlgorithm::Sha512
            )
        ),
        "digest_algorithms" => uri.and_then(DigestAlgorithm::from_uri).is_some_and(|a| {
            if field.starts_with("signing.") {
                a.signing_allowed()
            } else {
                !a.requires_explicit_permission()
            }
        }),
        "signature_algorithms" => signature(value).is_ok_and(|a| {
            if field.starts_with("signing.") {
                a.signing_allowed()
            } else {
                !a.requires_explicit_permission()
                    && !matches!(a, SignatureAlgorithm::PostQuantum(_))
            }
        }),
        #[cfg(feature = "xmlenc")]
        "data_algorithms" => uri.is_some_and(|uri| {
            DataEncryptionAlgorithm::from_uri(uri).is_ok_and(|a| !a.requires_explicit_permission())
        }),
        #[cfg(feature = "xmlenc")]
        "key_transport_algorithms" => uri.is_some_and(|uri| {
            KeyTransportAlgorithm::from_uri(uri).is_ok_and(|a| !a.requires_explicit_permission())
        }),
        #[cfg(feature = "xmlenc")]
        "key_wrap_algorithms" => uri.is_some_and(|uri| {
            KeyWrapAlgorithm::from_uri(uri).is_ok_and(|a| !a.requires_explicit_permission())
        }),
        #[cfg(feature = "xmlenc")]
        "oaep_digests" => uri
            .and_then(OaepDigestAlgorithm::from_uri)
            .is_some_and(|a| !a.requires_explicit_permission()),
        _ => false,
    }
}

fn direction(field: &str, old: Option<&Value>, new: Option<&Value>) -> Direction {
    use Direction::{Neutral, Relaxing, Restrictive};
    if field == "base" {
        return Neutral;
    }
    if field.ends_with(".enabled") {
        return if new.and_then(Value::as_bool) == Some(false) {
            Restrictive
        } else {
            Relaxing
        };
    }
    let last = field.rsplit('.').next().unwrap_or(field);
    if last == "validity" {
        return match (old, new) {
            (Some(Value::String(value)), Some(Value::Table(_))) if value == "none" => Restrictive,
            _ => Relaxing,
        };
    }
    if last == "signature_constraints" {
        // General is the identity of typed constraint intersection. Specialized
        // protocol constraints are incomparable, not ordered security levels.
        return match (
            old.map(signature_constraints).transpose(),
            new.map(signature_constraints).transpose(),
        ) {
            (Ok(Some(a)), Ok(Some(b))) if a == b => Neutral,
            (Ok(Some(SignatureConstraints::General)), Ok(Some(_))) => Restrictive,
            _ => Relaxing,
        };
    }
    if last == "certificate_signature_algorithms" {
        // This is the core's deployment-permission ordering, not PKIX syntax:
        // default admits classical algorithms only; AllSupported also admits PQ.
        if old.and_then(Value::as_str) == Some("AllSupported") {
            return Restrictive;
        }
    }
    if old.and_then(Value::as_str) == Some("default")
        && let Some(Value::Array(algorithms)) = new
        && algorithms.iter().all(|v| default_admits(field, v))
    {
        return Restrictive;
    }
    if matches!(last, "not_before" | "expires_at")
        && let (Some(a), Some(b)) = (old, new)
        && let (Ok(a), Ok(b)) = (timestamp(a, last), timestamp(b, last))
    {
        return if (last == "not_before" && b > a) || (last == "expires_at" && b < a) {
            Restrictive
        } else {
            Relaxing
        };
    }
    if let (Some(Value::Integer(a)), Some(Value::Integer(b))) = (old, new) {
        if last.starts_with("max_") || last == "expires_at" {
            return if b < a { Restrictive } else { Relaxing };
        }
        if last.starts_with("minimum_") || last == "not_before" {
            return if b > a { Restrictive } else { Relaxing };
        }
    }
    if let (Some(Value::Array(a)), Some(Value::Array(b))) = (old, new) {
        return if b.iter().all(|v| a.contains(v)) {
            Restrictive
        } else {
            Relaxing
        };
    }
    if let (Some(Value::Boolean(a)), Some(Value::Boolean(b))) = (old, new) {
        let requires = last == "verify_x509_chains" || last == "check_crls";
        return if (*b && requires) || (*a && !requires) {
            Restrictive
        } else {
            Relaxing
        };
    }
    match (old.and_then(Value::as_str), new.and_then(Value::as_str)) {
        (
            _,
            Some(
                "RequireTrustedKey"
                | "Process"
                | "RequireAuthenticatedCipher"
                | "ExactOnly"
                | "Forbidden",
            ),
        )
        | (Some("AllSupported"), Some("SecureSupported")) => Restrictive,
        _ => Relaxing,
    }
}
pub(super) fn diff(old: &Table, new: &Table) -> Vec<Change> {
    let mut a = BTreeMap::new();
    let mut b = BTreeMap::new();
    flatten(old, Some(new), "", &mut a);
    flatten(new, Some(old), "", &mut b);
    a.keys()
        .chain(b.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|field| {
            let before = a.get(field).copied();
            let after = b.get(field).copied();
            if before == after {
                None
            } else {
                let operation = field.split('.').next().unwrap_or(field);
                let gate = format!("{operation}.enabled");
                let classification = if a.get(&gate).and_then(|v| v.as_bool()) == Some(true)
                    && b.get(&gate).and_then(|v| v.as_bool()) == Some(false)
                {
                    Direction::Restrictive
                } else if a.get(&gate).and_then(|v| v.as_bool()) == Some(false)
                    && b.get(&gate).and_then(|v| v.as_bool()) == Some(true)
                {
                    Direction::Relaxing
                } else {
                    direction(field, before, after)
                };
                Some(Change {
                    field: field.clone(),
                    before: before.cloned(),
                    after: after.cloned(),
                    direction: classification,
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod key_source_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_key_establishment_defaults_match_core_permission_checks() {
        // Explicit-only algorithms cannot be classified as safe narrowing of
        // None. Cross-check the report's model against actual core enforcement.
        let policy = KeyEstablishmentPolicy::default();
        let default = text("default");
        for algorithm in [
            KeyAgreementAlgorithm::EcdhEs,
            KeyAgreementAlgorithm::X25519,
            KeyAgreementAlgorithm::X448,
            KeyAgreementAlgorithm::DhEs,
            KeyAgreementAlgorithm::LegacyDh,
        ] {
            let field = "verification.key_establishment.agreement_algorithms";
            let value = text(algorithm.uri());
            let admitted = policy.check_agreement(algorithm).is_ok();
            assert_eq!(default_admits(field, &value), admitted);
            let set = Value::Array(vec![value]);
            assert_eq!(
                direction(field, Some(&default), Some(&set)),
                if admitted {
                    Direction::Restrictive
                } else {
                    Direction::Relaxing
                }
            );
        }
        for algorithm in [
            KeyDerivationAlgorithm::ConcatKdf,
            KeyDerivationAlgorithm::Hkdf,
            KeyDerivationAlgorithm::Pbkdf2,
            KeyDerivationAlgorithm::LegacyDh,
        ] {
            assert_eq!(
                default_admits(
                    "verification.key_establishment.derivation_algorithms",
                    &text(algorithm.uri())
                ),
                policy
                    .check_derivation(algorithm, DigestAlgorithm::Sha256)
                    .is_ok()
            );
        }
        for algorithm in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha3_256,
        ] {
            assert_eq!(
                default_admits(
                    "verification.key_establishment.digest_algorithms",
                    &text(algorithm.uri())
                ),
                policy.check_derivation_digest(algorithm).is_ok()
            );
        }
    }

    #[test]
    fn exact_timestamp_codec_preserves_signed_lower_boundary() {
        // Accepted signed seconds must survive snapshot conversion, including
        // fractional instants whose floor is i64::MIN rather than truncation.
        for seconds in [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX] {
            for nanoseconds in [0, 1, 999_999_999] {
                let value = Value::Table(Table::from_iter([
                    ("seconds".into(), Value::Integer(seconds)),
                    ("nanoseconds".into(), Value::Integer(nanoseconds)),
                ]));
                // Every i64 second is a representable instant on every platform.
                let time = timestamp(&value, "time").unwrap();
                assert_eq!(timestamp_value(time).unwrap(), value);
            }
        }
    }

    #[test]
    fn exact_timestamp_codec_handles_both_sides_of_epoch() {
        // Preserve the epoch's fractional predecessor, not a truncation toward
        // zero, and reject out-of-range nanos before instant construction.
        for (seconds, nanos) in [(0, 0), (-1, 999_999_999), (0, 1), (-100, 0)] {
            let time = Instant::new(seconds, nanos).unwrap();
            let value = timestamp_value(time).unwrap();
            assert_eq!(timestamp(&value, "time").unwrap(), time);
        }
        let invalid_time = Value::Table(Table::from_iter([
            ("seconds".into(), Value::Integer(0)),
            ("nanoseconds".into(), Value::Integer(1_000_000_000)),
        ]));
        assert!(timestamp(&invalid_time, "time").is_err());
    }

    #[test]
    fn exact_certificate_descriptor_round_trips_parameters() {
        // Certificate allowlists retain full digest/MGF/salt identity rather
        // than collapsing distinct PSS tuples to their shared OID.
        for algorithm in [
            X509SignatureAlgorithm::Ed25519,
            X509SignatureAlgorithm::Ed448,
            X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1),
            X509SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha384),
            X509SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256),
            X509SignatureAlgorithm::RsaPss {
                digest: DigestAlgorithm::Sha256,
                mgf_digest: DigestAlgorithm::Sha384,
                salt_len: 17,
            },
        ] {
            assert_eq!(
                certificate(&certificate_value(algorithm).unwrap()).unwrap(),
                algorithm
            );
        }
    }

    #[test]
    fn arbitrary_oid_arcs_round_trip_without_signed_integer_cast() {
        // The entire u64 arc domain remains representable even when TOML's
        // numeric scalar range and the consumer's usize width are narrower.
        let value = Value::Array(vec![text("2"), text(u64::MAX.to_string()), text("1")]);
        assert_eq!(
            purpose(&value).unwrap(),
            ExtendedKeyPurpose::Other(vec![2, u64::MAX, 1])
        );
    }

    #[test]
    fn certificate_permission_diff_preserves_default_pq_boundary() {
        // Default excludes PQ, while AllSupported includes it. Exact classical
        // and mixed sets therefore have different directions from default.
        let field = "verification.key_trust.certificate_signature_algorithms";
        let default = text("default");
        let all = text("AllSupported");
        let classical = Value::Array(vec![
            certificate_value(X509SignatureAlgorithm::Ed25519).unwrap(),
        ]);
        let mixed = Value::Array(vec![
            certificate_value(X509SignatureAlgorithm::Ed25519).unwrap(),
            certificate_value(X509SignatureAlgorithm::PostQuantum(
                xml_sec::xmldsig::PqAlgorithm::MlDsa44,
            ))
            .unwrap(),
        ]);
        assert_eq!(
            direction(field, Some(&all), Some(&default)),
            Direction::Restrictive
        );
        assert_eq!(
            direction(field, Some(&all), Some(&mixed)),
            Direction::Restrictive
        );
        assert_eq!(
            direction(field, Some(&default), Some(&classical)),
            Direction::Restrictive
        );
        assert_eq!(
            direction(field, Some(&default), Some(&mixed)),
            Direction::Relaxing
        );
        assert_eq!(
            direction(field, Some(&classical), Some(&default)),
            Direction::Relaxing
        );
    }
}
