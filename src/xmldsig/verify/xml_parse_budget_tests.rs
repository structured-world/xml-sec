use super::*;

#[test]
fn verification_initial_parse_uses_the_policy_work_budget() {
    // Even a structurally invalid signature must not reach parsing when
    // the immutable operation snapshot denies all XML parse work.
    let xml = "<root/>";
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xml_parse_work_bytes = 0;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(xml)
        .expect_err("a zero parse-work budget must reject the input parse");

    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum: 0,
            actual,
        }) if actual == xml.len()
    ));
}
