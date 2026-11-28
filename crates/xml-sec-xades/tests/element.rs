//! Element canonicalization and owned base64 values of a verified session.

use std::collections::BTreeSet;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::XmlDocument;
use xml_sec::document::NodeIdentity;
use xml_sec::policy::{Instant, VerificationPolicy};
use xml_sec::xmldsig::extension::{self, NodeView, TreeError};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, KeyResolverConfig, ReplayError, VerificationRequest,
    VerifiedSession, VerifyContext, with_verified_request,
};

const ROOT: &[u8] = include_bytes!("fixtures/levels/root.der");
const SIGNED: &str = include_str!("fixtures/levels/b-t.xml");

fn verified<R>(
    configure: impl FnOnce(&mut VerificationPolicy),
    check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>) -> R,
) -> R {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(500_000 * 3600, 0);
    configure(&mut policy);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(SIGNED).expect("fixture parses");
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account,
        |session| Ok(check(&session)),
    )
    .expect("fixture verifies as XMLDSig")
}

/// The first element in document order called `local`.
fn element(session: &VerifiedSession<'_, '_, '_, Memory>, local: &str) -> NodeIdentity {
    fn find(
        session: &VerifiedSession<'_, '_, '_, Memory>,
        node: NodeIdentity,
        local: &str,
    ) -> Option<NodeIdentity> {
        let (view, work) = (session.view(), session.execution());
        let matches = extension::inspect_node(
            view,
            node,
            work,
            |value| matches!(value, NodeView::Element { local_name, .. } if local_name == local),
        )
        .expect("readable node");
        if matches {
            return Some(node);
        }
        let mut child = extension::first_child(view, node, work).expect("readable node");
        while let Some(current) = child {
            if let Some(found) = find(session, current, local) {
                return Some(found);
            }
            child = extension::next_sibling(view, node, current, work).expect("readable node");
        }
        None
    }
    find(session, session.view().root_element(), local).expect("the fixture has the element")
}

#[test]
fn an_element_streams_its_exclusive_canonical_form() {
    // libxml2 produced the imprint the fixture's token signs; here the shape
    // shows the namespace the ancestors declared is rendered where it is used.
    verified(
        |_| {},
        |session| {
            let (value, method) = (
                element(session, "SignatureValue"),
                element(session, "CanonicalizationMethod"),
            );
            let mut output = Vec::new();
            session
                .canonicalize_element(value, method, session.execution(), &mut |bytes: &[u8]| {
                    output.extend_from_slice(bytes);
                    Ok::<_, ()>(())
                })
                .expect("the method is permitted");
            let text = String::from_utf8(output).expect("canonical XML is UTF-8");
            assert!(text.starts_with("<ds:SignatureValue xmlns:ds="), "{text}");
            assert!(text.ends_with("</ds:SignatureValue>"), "{text}");
        },
    );
}

#[test]
fn a_method_outside_the_transform_policy_is_refused() {
    // The timestamp method is an attacker-written node: it obeys the same
    // permission as a Reference transform, before any output.
    verified(
        |policy| {
            policy.transforms.allowed_algorithms =
                Some(BTreeSet::from(["urn:test:other".to_owned()]));
        },
        |session| {
            let (value, method) = (
                element(session, "SignatureValue"),
                element(session, "CanonicalizationMethod"),
            );
            let result = session.canonicalize_element(
                value,
                method,
                session.execution(),
                &mut |_: &[u8]| -> Result<(), ()> { panic!("no output may reach the receiver") },
            );
            assert!(
                matches!(
                    result,
                    Err(ReplayError::Processing(
                        DsigError::AccountedPolicyAlgorithm { .. }
                    ))
                ),
                "{result:?}"
            );
        },
    );
}

#[test]
fn a_replayed_enveloped_transform_removes_only_its_own_signature() {
    // XMLDSig 1.1 §6.6.4: the enveloped-signature transform removes the
    // Signature that contains it, not every input node. Replaying the
    // fixture's document reference from its own Transforms yields the
    // document without that Signature, payload included.
    verified(
        |_| {},
        |session| {
            let (reference, transforms) = (
                element(session, "Reference"),
                element(session, "Transforms"),
            );
            let mut output = Vec::new();
            session
                .select_signature(element(session, "Signature"))
                .expect("the signature verified")
                .replay_transforms(
                    reference,
                    "",
                    Some((transforms, "http://www.w3.org/2000/09/xmldsig#")),
                    &mut |bytes: &[u8]| {
                        output.extend_from_slice(bytes);
                        Ok::<_, ()>(())
                    },
                )
                .expect("the reference replays");
            let text = String::from_utf8(output).expect("canonical XML is UTF-8");
            assert!(text.contains("Levels payload"), "{text:?}");
            assert!(!text.contains("Signature"), "{text:?}");
        },
    );
}

#[test]
fn a_receiver_refusal_keeps_its_own_cause() {
    verified(
        |_| {},
        |session| {
            let (value, method) = (
                element(session, "SignatureValue"),
                element(session, "CanonicalizationMethod"),
            );
            let result = session.canonicalize_element(
                value,
                method,
                session.execution(),
                &mut |_: &[u8]| Err("refused"),
            );
            assert!(matches!(result, Err(ReplayError::Receiver("refused"))));
        },
    );
}

/// The canonical form of `element` without the subtrees of `excluded`.
fn canonical_without(
    session: &VerifiedSession<'_, '_, '_, Memory>,
    element: NodeIdentity,
    excluded: &[NodeIdentity],
    method: NodeIdentity,
) -> Result<String, ReplayError<()>> {
    let mut output = Vec::new();
    session.canonicalize_element_without(
        element,
        excluded,
        method,
        session.execution(),
        &mut |bytes: &[u8]| {
            output.extend_from_slice(bytes);
            Ok(())
        },
    )?;
    Ok(String::from_utf8(output).expect("canonical XML is UTF-8"))
}

#[test]
fn an_excluded_subtree_is_cut_out_of_the_canonical_form() {
    // RFC 6283 hash-tree renewal canonicalizes a sequence with only its
    // earlier chains: the result is the whole element's canonical form with
    // exactly the excluded subtree's bytes removed.
    verified(
        |_| {},
        |session| {
            let (signed, method, cut) = (
                element(session, "SignedInfo"),
                element(session, "CanonicalizationMethod"),
                element(session, "SignatureMethod"),
            );
            let whole = canonical_without(session, signed, &[], method).expect("whole element");
            let start = whole
                .find("<ds:SignatureMethod")
                .expect("the method is signed");
            let end = whole
                .find("</ds:SignatureMethod>")
                .expect("the method has an end tag")
                + "</ds:SignatureMethod>".len();
            let expected = format!("{}{}", &whole[..start], &whole[end..]);
            let pruned =
                canonical_without(session, signed, &[cut], method).expect("pruned element");
            assert_eq!(pruned, expected);
        },
    );
}

#[test]
fn only_a_descendant_element_can_be_excluded() {
    // Excluding the input itself or a node outside it would not be a subset
    // of the input; it is refused before any output.
    verified(
        |_| {},
        |session| {
            let (signed, method, outside) = (
                element(session, "SignedInfo"),
                element(session, "CanonicalizationMethod"),
                element(session, "SignatureValue"),
            );
            for excluded in [signed, outside] {
                let result = canonical_without(session, signed, &[excluded], method);
                assert!(
                    matches!(
                        result,
                        Err(ReplayError::Processing(DsigError::InvalidRequest { .. }))
                    ),
                    "{result:?}"
                );
            }
        },
    );
}

#[test]
fn owned_base64_is_the_scoped_value_and_stays_charged() {
    verified(
        |_| {},
        |session| {
            let value = element(session, "SignatureValue");
            let view = session.view();
            let account = Memory::new(Arc::new(MemoryAccount::new(1 << 16, 1 << 20)));
            let owned = extension::base64_owned(view, value, &account).expect("base64 value");
            assert!(account.used() >= owned.len());
            let scoped = extension::with_base64(view, value, &account, <[u8]>::to_vec)
                .expect("base64 value");
            assert_eq!(&owned[..], &scoped[..]);
            let empty = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
            assert!(matches!(
                extension::base64_owned(view, value, &empty),
                Err(TreeError::Resource(_))
            ));
        },
    );
}
