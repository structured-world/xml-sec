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
