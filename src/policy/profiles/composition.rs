use super::*;
use std::hash::Hash;

impl PolicySet {
    pub(super) fn intersect(&self, other: &Self) -> Result<Self, PolicyViolation> {
        Ok(Self {
            verification: intersect_operation(
                &self.verification,
                &other.verification,
                verification,
            )?,
            signing: intersect_operation(&self.signing, &other.signing, signing)?,
            #[cfg(feature = "xmlenc")]
            encryption: intersect_operation(&self.encryption, &other.encryption, encryption)?,
            #[cfg(feature = "xmlenc")]
            decryption: intersect_operation(&self.decryption, &other.decryption, decryption)?,
        })
    }

    pub(super) fn bind_authorization(
        &mut self,
        grant: PolicyValidity,
        prior: &Self,
    ) -> Result<(), PolicyViolation> {
        fn bind<T>(
            policy: &mut Option<T>,
            prior: &Option<T>,
            grant: &PolicyValidity,
            field: impl Fn(&mut T) -> &mut Option<PolicyValidity>,
            read: impl Fn(&T) -> &Option<PolicyValidity>,
        ) -> Result<(), PolicyViolation> {
            if let Some(policy) = policy {
                let mut validity = grant.clone();
                for inherited in [
                    read(policy).as_ref(),
                    prior.as_ref().and_then(|p| read(p).as_ref()),
                ]
                .into_iter()
                .flatten()
                {
                    validity.not_before = validity.not_before.max(inherited.not_before);
                    validity.expires_at = validity.expires_at.min(inherited.expires_at);
                }
                validity.validate_at(SystemTime::now())?;
                *field(policy) = Some(validity);
            }
            Ok(())
        }
        bind(
            &mut self.verification,
            &prior.verification,
            &grant,
            |p| &mut p.validity,
            |p| &p.validity,
        )?;
        bind(
            &mut self.signing,
            &prior.signing,
            &grant,
            |p| &mut p.validity,
            |p| &p.validity,
        )?;
        #[cfg(feature = "xmlenc")]
        {
            bind(
                &mut self.encryption,
                &prior.encryption,
                &grant,
                |p| &mut p.validity,
                |p| &p.validity,
            )?;
            bind(
                &mut self.decryption,
                &prior.decryption,
                &grant,
                |p| &mut p.validity,
                |p| &p.validity,
            )?;
        }
        Ok(())
    }
}

fn intersect_operation<T>(
    a: &Option<T>,
    b: &Option<T>,
    merge: impl Fn(&T, &T) -> Result<T, PolicyViolation>,
) -> Result<Option<T>, PolicyViolation> {
    match (a, b) {
        (Some(a), Some(b)) => merge(a, b).map(Some),
        _ => Ok(None),
    }
}

// None has field-specific default semantics. In particular it does NOT grant
// every legacy/experimental method. Ask the existing enforcement core instead
// of maintaining another algorithm permission table here.
fn algorithms<T: Copy + Eq + Hash>(
    a: &Option<HashSet<T>>,
    b: &Option<HashSet<T>>,
    accepts_a: impl Fn(T) -> bool,
    accepts_b: impl Fn(T) -> bool,
) -> Option<HashSet<T>> {
    if a.is_none() && b.is_none() {
        return None;
    }
    Some(
        a.iter()
            .chain(b)
            .flat_map(|set| set.iter())
            .copied()
            .filter(|value| accepts_a(*value) && accepts_b(*value))
            .collect(),
    )
}

fn set<T: Clone + Eq + Hash>(a: &HashSet<T>, b: &HashSet<T>) -> HashSet<T> {
    a.intersection(b).cloned().collect()
}

fn optional_set<T: Clone + Eq + Hash>(
    a: &Option<HashSet<T>>,
    b: &Option<HashSet<T>>,
) -> Option<HashSet<T>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(set(a, b)),
        (Some(values), None) | (None, Some(values)) => Some(values.clone()),
        (None, None) => None,
    }
}

fn equal<T: Copy + Eq>(a: T, b: T) -> Result<T, PolicyViolation> {
    if a != b {
        return Err(configuration(
            "policy layers select incompatible interpretation semantics",
        ));
    }
    Ok(a)
}

fn signature_constraints(
    a: SignatureConstraints,
    b: SignatureConstraints,
) -> Result<SignatureConstraints, PolicyViolation> {
    match (a, b) {
        (SignatureConstraints::General, value) | (value, SignatureConstraints::General) => {
            Ok(value)
        }
        _ => equal(a, b),
    }
}

fn validity(
    a: &Option<PolicyValidity>,
    b: &Option<PolicyValidity>,
) -> Result<Option<PolicyValidity>, PolicyViolation> {
    match (a, b) {
        (None, value) | (value, None) => Ok(value.clone()),
        (Some(a), Some(b)) => {
            if a.authorization_id != b.authorization_id
                || a.authority != b.authority
                || a.reason != b.reason
            {
                return Err(configuration(
                    "distinct authorizations require an explicit replacement grant",
                ));
            }
            let mut result = a.clone();
            result.not_before = a.not_before.max(b.not_before);
            result.expires_at = a.expires_at.min(b.expires_at);
            result.validate_at(SystemTime::now())?;
            Ok(Some(result))
        }
    }
}

fn family(a: RsaPssPermission, b: RsaPssPermission) -> RsaPssPermission {
    match (a, b) {
        (RsaPssPermission::ExactOnly, _) | (_, RsaPssPermission::ExactOnly) => {
            RsaPssPermission::ExactOnly
        }
        (RsaPssPermission::SecureSupported, _) | (_, RsaPssPermission::SecureSupported) => {
            RsaPssPermission::SecureSupported
        }
        _ => RsaPssPermission::AllSupported,
    }
}

fn effective_family<T>(
    algorithms: &Option<HashSet<T>>,
    explicit: RsaPssPermission,
    default: RsaPssPermission,
) -> RsaPssPermission {
    if algorithms.is_none() {
        default
    } else {
        explicit
    }
}

fn hmac(a: HmacPolicy, b: HmacPolicy) -> HmacPolicy {
    HmacPolicy {
        minimum_key_bits: a.minimum_key_bits.max(b.minimum_key_bits),
        minimum_output_bits: a.minimum_output_bits.max(b.minimum_output_bits),
    }
}

fn rsa(a: RsaKeyPolicy, b: RsaKeyPolicy) -> RsaKeyPolicy {
    RsaKeyPolicy {
        minimum_modulus_bits: a.minimum_modulus_bits.max(b.minimum_modulus_bits),
    }
}
fn dsa(a: DsaKeyPolicy, b: DsaKeyPolicy) -> DsaKeyPolicy {
    DsaKeyPolicy {
        minimum_modulus_bits: a.minimum_modulus_bits.max(b.minimum_modulus_bits),
    }
}
fn uri_set(a: UriTypeSet, b: UriTypeSet) -> UriTypeSet {
    UriTypeSet::new(
        a.allows("") && b.allows(""),
        a.allows("#id") && b.allows("#id"),
        a.allows("external") && b.allows("external"),
    )
}
fn uris(a: UriPolicy, b: UriPolicy) -> UriPolicy {
    UriPolicy {
        references: uri_set(a.references, b.references),
        retrieval_methods: uri_set(a.retrieval_methods, b.retrieval_methods),
        key_info_references: uri_set(a.key_info_references, b.key_info_references),
    }
}
fn transforms(
    a: &TransformPolicy,
    b: &TransformPolicy,
) -> Result<TransformPolicy, PolicyViolation> {
    Ok(TransformPolicy {
        allowed_algorithms: optional_set(&a.allowed_algorithms, &b.allowed_algorithms),
        xpath_here_semantics: equal(a.xpath_here_semantics, b.xpath_here_semantics)?,
        same_document_id_semantics: equal(
            a.same_document_id_semantics,
            b.same_document_id_semantics,
        )?,
        opc_relationship_edition: equal(a.opc_relationship_edition, b.opc_relationship_edition)?,
    })
}
fn manifests(a: ManifestProcessing, b: ManifestProcessing) -> ManifestProcessing {
    if a == ManifestProcessing::Process || b == ManifestProcessing::Process {
        ManifestProcessing::Process
    } else {
        ManifestProcessing::Ignore
    }
}
fn xml(a: XmlInputPolicy, b: XmlInputPolicy) -> XmlInputPolicy {
    XmlInputPolicy {
        allow_internal_dtd: a.allow_internal_dtd && b.allow_internal_dtd,
    }
}

fn key_establishment(
    a: &KeyEstablishmentPolicy,
    b: &KeyEstablishmentPolicy,
) -> KeyEstablishmentPolicy {
    KeyEstablishmentPolicy {
        encapsulation_algorithms: set(&a.encapsulation_algorithms, &b.encapsulation_algorithms),
        kem_content_authentication: if a.kem_content_authentication
            == KemContentAuthentication::RequireAuthenticatedCipher
            || b.kem_content_authentication == KemContentAuthentication::RequireAuthenticatedCipher
        {
            KemContentAuthentication::RequireAuthenticatedCipher
        } else {
            KemContentAuthentication::ExternalAuthenticated
        },
        agreement_algorithms: algorithms(
            &a.agreement_algorithms,
            &b.agreement_algorithms,
            |v| a.check_agreement(v).is_ok(),
            |v| b.check_agreement(v).is_ok(),
        ),
        derivation_algorithms: algorithms(
            &a.derivation_algorithms,
            &b.derivation_algorithms,
            |v| {
                a.derivation_algorithms
                    .as_ref()
                    .map_or(v != KeyDerivationAlgorithm::LegacyDh, |s| s.contains(&v))
            },
            |v| {
                b.derivation_algorithms
                    .as_ref()
                    .map_or(v != KeyDerivationAlgorithm::LegacyDh, |s| s.contains(&v))
            },
        ),
        digest_algorithms: algorithms(
            &a.digest_algorithms,
            &b.digest_algorithms,
            |v| a.check_derivation_digest(v).is_ok(),
            |v| b.check_derivation_digest(v).is_ok(),
        ),
        max_encapsulation_operations: a
            .max_encapsulation_operations
            .min(b.max_encapsulation_operations),
        max_hash_blocks: a.max_hash_blocks.min(b.max_hash_blocks),
        max_owned_bytes: a.max_owned_bytes.min(b.max_owned_bytes),
        max_dh_modulus_bits: a.max_dh_modulus_bits.min(b.max_dh_modulus_bits),
        minimum_dh_modulus_bits: a.minimum_dh_modulus_bits.max(b.minimum_dh_modulus_bits),
        minimum_dh_subgroup_bits: a.minimum_dh_subgroup_bits.max(b.minimum_dh_subgroup_bits),
        max_modular_work: a.max_modular_work.min(b.max_modular_work),
    }
}

fn resources(a: &ResourcePolicy, b: &ResourcePolicy) -> ResourcePolicy {
    // Exhaustive construction makes adding a resource field a compile-time
    // obligation to define its composition, rather than silently inherit it.
    macro_rules! minima { ($($field:ident),+ $(,)?) => { ResourcePolicy { $($field: a.$field.min(b.$field)),+ } }; }
    minima!(
        max_xml_nodes,
        max_xml_depth,
        max_xml_namespace_bindings,
        max_references,
        max_signatures,
        max_transforms_per_reference,
        max_xml_base_components,
        max_xml_base_resolution_bytes,
        max_canonicalized_bytes,
        max_external_resource_bytes,
        max_external_resource_total_bytes,
        max_encryption_plaintext_bytes,
        max_xml_document_bytes,
        max_xml_parse_work_bytes,
        max_encryption_recipients,
        max_encryption_metadata_bytes,
        max_key_candidates,
        max_x509_work,
        max_x509_workspace_bytes,
        max_key_import_kdf_work,
        max_key_import_kdf_memory_bytes,
        max_key_info_reference_depth,
        max_base64_transform_input_bytes,
        max_base64_transform_output_bytes,
        max_xpath_expressions,
        max_xpath_expression_bytes,
        max_xpath_expression_complexity,
        max_xpath_context_evaluations,
        max_xpath_evaluation_work,
        max_xpath_mirror_string_bytes,
        max_xpath_string_work_bytes,
        max_xpath_namespace_bindings,
        max_xpath_namespace_bytes,
        max_xpath_filters,
        max_node_set_filter_work,
        max_node_set_entries,
        max_node_set_owned_string_bytes,
        max_node_set_cumulative_owned_string_bytes,
        max_opc_parameter_bytes,
        max_opc_workspace_bytes
    )
}

fn key_sources(a: KeySourcePolicy, b: KeySourcePolicy) -> KeySourcePolicy {
    KeySourcePolicy {
        preset_key: a.preset_key && b.preset_key,
        key_name: a.key_name && b.key_name,
        key_value: a.key_value && b.key_value,
        der_encoded_key_value: a.der_encoded_key_value && b.der_encoded_key_value,
        x509_data: a.x509_data && b.x509_data,
        key_info_reference: a.key_info_reference && b.key_info_reference,
    }
}
fn certificate_algorithms(
    a: &Option<CertificateSignatureAlgorithms>,
    b: &Option<CertificateSignatureAlgorithms>,
) -> Option<CertificateSignatureAlgorithms> {
    match (a, b) {
        (Some(CertificateSignatureAlgorithms::Allowlist(values)), other)
        | (other, Some(CertificateSignatureAlgorithms::Allowlist(values))) => {
            Some(CertificateSignatureAlgorithms::Allowlist(
                values
                    .iter()
                    .copied()
                    .filter(|v| {
                        KeyTrustPolicy::check_certificate_signature_algorithm(*v, other.as_ref())
                            .is_ok()
                    })
                    .collect(),
            ))
        }
        (
            Some(CertificateSignatureAlgorithms::AllSupported),
            Some(CertificateSignatureAlgorithms::AllSupported),
        ) => Some(CertificateSignatureAlgorithms::AllSupported),
        _ => None,
    }
}
fn key_trust(a: &KeyTrustPolicy, b: &KeyTrustPolicy) -> Result<KeyTrustPolicy, PolicyViolation> {
    let verification_time = match (a.verification_time, b.verification_time) {
        (Some(a), Some(b)) => Some(equal(a, b)?),
        (a, b) => a.or(b),
    };
    Ok(KeyTrustPolicy {
        mode: if a.mode == VerificationTrustMode::RequireTrustedKey
            || b.mode == VerificationTrustMode::RequireTrustedKey
        {
            VerificationTrustMode::RequireTrustedKey
        } else {
            VerificationTrustMode::CryptographicOnly
        },
        verify_x509_chains: a.verify_x509_chains || b.verify_x509_chains,
        max_x509_chain_depth: a.max_x509_chain_depth.min(b.max_x509_chain_depth),
        max_x509_candidate_paths: a.max_x509_candidate_paths.min(b.max_x509_candidate_paths),
        allowed_legacy_signature_algorithms: a
            .allowed_legacy_signature_algorithms
            .union(&b.allowed_legacy_signature_algorithms)
            .copied()
            .filter(|algorithm| {
                (a.allowed_legacy_signature_algorithms.contains(algorithm)
                    || a.parameterized_rsa_pss.permits(*algorithm))
                    && (b.allowed_legacy_signature_algorithms.contains(algorithm)
                        || b.parameterized_rsa_pss.permits(*algorithm))
            })
            .collect(),
        parameterized_rsa_pss: family(a.parameterized_rsa_pss, b.parameterized_rsa_pss),
        certificate_signature_algorithms: certificate_algorithms(
            &a.certificate_signature_algorithms,
            &b.certificate_signature_algorithms,
        ),
        rsa_keys: rsa(a.rsa_keys, b.rsa_keys),
        dsa_keys: dsa(a.dsa_keys, b.dsa_keys),
        allowed_extended_key_usages: set(
            &a.allowed_extended_key_usages,
            &b.allowed_extended_key_usages,
        ),
        check_crls: a.check_crls || b.check_crls,
        verification_time,
    })
}

fn verification(
    a: &VerificationPolicy,
    b: &VerificationPolicy,
) -> Result<VerificationPolicy, PolicyViolation> {
    Ok(VerificationPolicy {
        validity: validity(&a.validity, &b.validity)?,
        signature_constraints: signature_constraints(
            a.signature_constraints,
            b.signature_constraints,
        )?,
        key_establishment: key_establishment(&a.key_establishment, &b.key_establishment),
        parameterized_rsa_pss: family(
            effective_family(
                &a.signature_algorithms,
                a.parameterized_rsa_pss,
                RsaPssPermission::AllSupported,
            ),
            effective_family(
                &b.signature_algorithms,
                b.parameterized_rsa_pss,
                RsaPssPermission::AllSupported,
            ),
        ),
        signature_algorithms: algorithms(
            &a.signature_algorithms,
            &b.signature_algorithms,
            |v| a.check_signature_algorithm(v).is_ok(),
            |v| b.check_signature_algorithm(v).is_ok(),
        ),
        digest_algorithms: algorithms(
            &a.digest_algorithms,
            &b.digest_algorithms,
            |v| a.check_digest_algorithm(v).is_ok(),
            |v| b.check_digest_algorithm(v).is_ok(),
        ),
        hmac: hmac(a.hmac, b.hmac),
        ecdsa_signature_value_encoding: equal(
            a.ecdsa_signature_value_encoding,
            b.ecdsa_signature_value_encoding,
        )?,
        key_trust: key_trust(&a.key_trust, &b.key_trust)?,
        key_sources: key_sources(a.key_sources, b.key_sources),
        uris: uris(a.uris, b.uris),
        transforms: transforms(&a.transforms, &b.transforms)?,
        manifest_processing: manifests(a.manifest_processing, b.manifest_processing),
        xml: xml(a.xml, b.xml),
        resources: resources(&a.resources, &b.resources),
    })
}
fn signing(a: &SigningPolicy, b: &SigningPolicy) -> Result<SigningPolicy, PolicyViolation> {
    Ok(SigningPolicy {
        validity: validity(&a.validity, &b.validity)?,
        signature_constraints: signature_constraints(
            a.signature_constraints,
            b.signature_constraints,
        )?,
        key_establishment: key_establishment(&a.key_establishment, &b.key_establishment),
        parameterized_rsa_pss: family(
            effective_family(
                &a.signature_algorithms,
                a.parameterized_rsa_pss,
                RsaPssPermission::SecureSupported,
            ),
            effective_family(
                &b.signature_algorithms,
                b.parameterized_rsa_pss,
                RsaPssPermission::SecureSupported,
            ),
        ),
        signature_algorithms: algorithms(
            &a.signature_algorithms,
            &b.signature_algorithms,
            |v| a.check_signature_algorithm(v).is_ok(),
            |v| b.check_signature_algorithm(v).is_ok(),
        ),
        digest_algorithms: algorithms(
            &a.digest_algorithms,
            &b.digest_algorithms,
            |v| a.check_digest_algorithm(v).is_ok(),
            |v| b.check_digest_algorithm(v).is_ok(),
        ),
        hmac: hmac(a.hmac, b.hmac),
        ecdsa_signature_value_encoding: equal(
            a.ecdsa_signature_value_encoding,
            b.ecdsa_signature_value_encoding,
        )?,
        rsa_keys: rsa(a.rsa_keys, b.rsa_keys),
        dsa_keys: dsa(a.dsa_keys, b.dsa_keys),
        uris: uris(a.uris, b.uris),
        transforms: transforms(&a.transforms, &b.transforms)?,
        manifest_processing: manifests(a.manifest_processing, b.manifest_processing),
        xml: xml(a.xml, b.xml),
        resources: resources(&a.resources, &b.resources),
    })
}

#[cfg(feature = "xmlenc")]
fn encryption(
    a: &EncryptionPolicy,
    b: &EncryptionPolicy,
) -> Result<EncryptionPolicy, PolicyViolation> {
    Ok(EncryptionPolicy {
        validity: validity(&a.validity, &b.validity)?,
        data_algorithms: algorithms(
            &a.data_algorithms,
            &b.data_algorithms,
            |v| check_content_algorithm(a.data_algorithms.as_ref(), v, "encryption").is_ok(),
            |v| check_content_algorithm(b.data_algorithms.as_ref(), v, "encryption").is_ok(),
        ),
        key_transport_algorithms: algorithms(
            &a.key_transport_algorithms,
            &b.key_transport_algorithms,
            |v| transport_allowed(&a.key_transport_algorithms, v),
            |v| transport_allowed(&b.key_transport_algorithms, v),
        ),
        key_wrap_algorithms: algorithms(
            &a.key_wrap_algorithms,
            &b.key_wrap_algorithms,
            |v| wrap_allowed(&a.key_wrap_algorithms, v),
            |v| wrap_allowed(&b.key_wrap_algorithms, v),
        ),
        oaep_digests: algorithms(
            &a.oaep_digests,
            &b.oaep_digests,
            |v| oaep_allowed(&a.oaep_digests, v),
            |v| oaep_allowed(&b.oaep_digests, v),
        ),
        rsa_keys: rsa(a.rsa_keys, b.rsa_keys),
        key_establishment: key_establishment(&a.key_establishment, &b.key_establishment),
        xml: xml(a.xml, b.xml),
        resources: resources(&a.resources, &b.resources),
    })
}

#[cfg(feature = "xmlenc")]
fn decryption(
    a: &DecryptionPolicy,
    b: &DecryptionPolicy,
) -> Result<DecryptionPolicy, PolicyViolation> {
    Ok(DecryptionPolicy {
        validity: validity(&a.validity, &b.validity)?,
        data_algorithms: algorithms(
            &a.data_algorithms,
            &b.data_algorithms,
            |v| check_content_algorithm(a.data_algorithms.as_ref(), v, "decryption").is_ok(),
            |v| check_content_algorithm(b.data_algorithms.as_ref(), v, "decryption").is_ok(),
        ),
        key_transport_algorithms: algorithms(
            &a.key_transport_algorithms,
            &b.key_transport_algorithms,
            |v| transport_allowed(&a.key_transport_algorithms, v),
            |v| transport_allowed(&b.key_transport_algorithms, v),
        ),
        key_wrap_algorithms: algorithms(
            &a.key_wrap_algorithms,
            &b.key_wrap_algorithms,
            |v| wrap_allowed(&a.key_wrap_algorithms, v),
            |v| wrap_allowed(&b.key_wrap_algorithms, v),
        ),
        oaep_digests: algorithms(
            &a.oaep_digests,
            &b.oaep_digests,
            |v| oaep_allowed(&a.oaep_digests, v),
            |v| oaep_allowed(&b.oaep_digests, v),
        ),
        rsa_keys: rsa(a.rsa_keys, b.rsa_keys),
        key_establishment: key_establishment(&a.key_establishment, &b.key_establishment),
        xml: xml(a.xml, b.xml),
        resources: resources(&a.resources, &b.resources),
        uris: uris(a.uris, b.uris),
        transforms: transforms(&a.transforms, &b.transforms)?,
    })
}

#[cfg(feature = "xmlenc")]
fn transport_allowed(
    set: &Option<HashSet<KeyTransportAlgorithm>>,
    value: KeyTransportAlgorithm,
) -> bool {
    set.as_ref()
        .map_or(!value.requires_explicit_permission(), |s| {
            s.contains(&value)
        })
}
#[cfg(feature = "xmlenc")]
fn wrap_allowed(set: &Option<HashSet<KeyWrapAlgorithm>>, value: KeyWrapAlgorithm) -> bool {
    set.as_ref()
        .map_or(!value.requires_explicit_permission(), |s| {
            s.contains(&value)
        })
}
#[cfg(feature = "xmlenc")]
fn oaep_allowed(set: &Option<HashSet<OaepDigestAlgorithm>>, value: OaepDigestAlgorithm) -> bool {
    set.as_ref()
        .map_or(!value.requires_explicit_permission(), |s| {
            s.contains(&value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_pss_intersection_keeps_nondefault_secure_tuples() {
        // None accepts arbitrary secure tuples; intersecting it with an
        // explicit family grant must not silently collapse to listed tuples.
        let layer = VerificationPolicy {
            signature_algorithms: Some(HashSet::from([SignatureAlgorithm::HmacSha256])),
            parameterized_rsa_pss: RsaPssPermission::AllSupported,
            ..VerificationPolicy::default()
        };
        let composed =
            verification(&VerificationPolicy::default(), &layer).expect("compatible policies");
        let algorithm = SignatureAlgorithm::RsaPss(crate::xmldsig::RsaPssParameters {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha384,
            salt_len: 17,
        });
        assert!(composed.check_signature_algorithm(algorithm).is_ok());
    }
}
