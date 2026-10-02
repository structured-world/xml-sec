//! Mathematical interoperability tests deliberately do not establish signer trust.

pub fn context<'a>() -> xml_sec::xmldsig::VerifyContext<'a> {
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    xml_sec::xmldsig::VerifyContext::new().policy(policy)
}
