use super::{SignatureBuilder, TransformExecutionBudget, XPathSignatureParseBudget};
use crate::c14n::{C14nAlgorithm, C14nMode};
use crate::policy::SigningPolicy;
use crate::provider::KeyEncapsulationAlgorithm;
use crate::xmldsig::{DigestAlgorithm, ReferenceBuilder, SignatureAlgorithm};

#[test]
fn an_encapsulated_key_info_keeps_its_id() {
    // XMLDSig 1.1 §4.5: KeyInfo/@Id names it for a Reference. The KeyInfo
    // that carries an ML-KEM EncryptedKey is the same element, so the Id
    // set by `key_info_id` stays on it and `#key` has a target.
    let mut policy = SigningPolicy::default();
    policy
        .key_establishment
        .encapsulation_algorithms
        .insert(KeyEncapsulationAlgorithm::MlKem768);
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#key"))
    .key_info_id("key");
    let budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut xpath = XPathSignatureParseBudget::from_resources(&policy.resources);
    let template = builder
        .build_template_with_policy_for_signature_output(
            &policy,
            32,
            Some(KeyEncapsulationAlgorithm::MlKem768),
            &budget,
            &mut xpath,
        )
        .expect("template");
    let document = roxmltree::Document::parse(&template).expect("valid XML");
    let key_info = document
        .root_element()
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyInfo")))
        .expect("KeyInfo");
    assert_eq!(key_info.attribute("Id"), Some("key"), "{template}");
}
