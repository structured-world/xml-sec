//! Republishing keeps one complete pair of snapshots published whatever an
//! edit does, and loses no concurrent edit. Each test changes process-global
//! state and relies on cargo nextest's process per test.

use std::sync::mpsc;
use std::time::Duration;

use super::{library, republish, signing};

/// The current verification node limit.
fn nodes() -> usize {
    library()
        .expect("the library policy compiles")
        .resources
        .max_xml_nodes
}

/// Asserts that the calling test runs in a process of its own, as cargo
/// nextest runs every test: these tests change the published policy, which
/// is process-global state.
fn own_process() {
    assert_eq!(
        std::env::var("NEXTEST_EXECUTION_MODE").as_deref(),
        Ok("process-per-test"),
        "this test changes the process-global policy and needs a process of its own: run it with cargo nextest"
    );
}

#[test]
fn a_cipher_reference_resolves_ids_as_a_signature_reference_does() {
    // A CipherReference URI `#123` names an element whose registered ID is
    // not an NCName, as libxmlsec1 accepts it in a signature's reference; the
    // decryption snapshot carries the same ID semantics.
    let snapshots = super::snapshots().expect("the library policy compiles");
    assert_eq!(
        snapshots.decryption.transforms.same_document_id_semantics,
        snapshots.verification.transforms.same_document_id_semantics
    );
    assert_ne!(
        snapshots.verification.transforms.same_document_id_semantics,
        xml_sec::policy::SameDocumentIdSemantics::Specification
    );
}

#[test]
fn an_edit_may_read_the_current_snapshots() {
    own_process();
    // An edit that consults the published policy runs without the snapshot
    // lock held, so it neither deadlocks nor panics on reentry.
    let before = nodes();
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        let done = republish(
            |verification| {
                verification.resources.max_xml_nodes = nodes() - 1;
            },
            |signing_policy| {
                let current = signing().expect("the library policy compiles");
                signing_policy.resources.max_xml_nodes = current.resources.max_xml_nodes - 1;
            },
        );
        sent.send(done).expect("the test waits");
    });
    let done = received
        .recv_timeout(Duration::from_secs(10))
        .expect("republishing finishes");
    assert_eq!(done, Some(()));
    assert_eq!(nodes(), before - 1);
}

#[test]
fn a_panicking_edit_leaves_the_snapshots_published() {
    own_process();
    // The previous pair stays published and later republishing still works.
    let before = nodes();
    let panicked = std::panic::catch_unwind(|| {
        republish(|_| panic!("an edit fails"), |_| {});
    });
    assert!(panicked.is_err());
    assert_eq!(nodes(), before);
    assert_eq!(
        republish(
            |verification| verification.resources.max_xml_nodes = before - 1,
            |_| {}
        ),
        Some(())
    );
    assert_eq!(nodes(), before - 1);
}

#[test]
fn an_unrestricted_edit_the_core_refuses_publishes_nothing() {
    own_process();
    // Every published revision holds the core's consistency rules, a
    // setter's as the first: a signing allowlist that keeps its SHA-1
    // methods without their verify-only permission is refused, the published
    // snapshot stays as it was, and a valid edit still lands.
    let before = signing().expect("the library policy compiles");
    assert!(!before.verify_only_signature_algorithms.is_empty());
    assert_eq!(
        republish(
            |_| {},
            |signing_policy| signing_policy.verify_only_signature_algorithms.clear()
        ),
        None
    );
    assert_eq!(
        signing()
            .expect("the library policy compiles")
            .verify_only_signature_algorithms,
        before.verify_only_signature_algorithms
    );
    let before_nodes = nodes();
    assert_eq!(
        republish(
            |verification| verification.resources.max_xml_nodes = before_nodes - 1,
            |_| {}
        ),
        Some(())
    );
    assert_eq!(nodes(), before_nodes - 1);
}

#[test]
fn a_raised_hmac_minimum_leaves_out_the_methods_it_refuses_until_lowered() {
    // libxmlsec1's minimum output length refuses an HMAC method whose output
    // falls short of it: the published methods leave it out, so the revision
    // compiles, and a lower minimum set later admits it again.
    use xml_sec::xmldsig::SignatureAlgorithm::HmacSha256;
    own_process();
    let listed = |minimum: usize| {
        republish(
            |verification| verification.hmac.minimum_output_bits = minimum,
            |signing_policy| signing_policy.hmac.minimum_output_bits = minimum,
        )
        .expect("the revision compiles");
        let methods = |policy: Option<&std::collections::BTreeSet<_>>| {
            policy.is_some_and(|methods| methods.contains(&HmacSha256))
        };
        (
            methods(library().expect("published").signature_algorithms.as_ref()),
            methods(signing().expect("published").signature_algorithms.as_ref()),
        )
    };
    assert_eq!(listed(128), (true, true));
    assert_eq!(listed(384), (false, false));
    assert_eq!(listed(256), (true, true));
}

#[test]
fn concurrent_edits_are_all_kept() {
    // Republishing callers take turns: every decrement lands.
    const EDITS: usize = 50;
    own_process();
    let before = nodes();
    let workers: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..EDITS {
                    republish(
                        |verification| verification.resources.max_xml_nodes -= 1,
                        |_| {},
                    )
                    .expect("the library policy compiles");
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("a worker finishes");
    }
    assert_eq!(nodes(), before - 2 * EDITS);
}
