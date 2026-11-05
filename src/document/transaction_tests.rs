//! All-or-nothing [`XmlDocument::transaction`] semantics, including nesting.

use super::{DocumentView, NodeIdentity, XmlDocument};

// A free function keeps the view's lifetime late-bound for `with_view`.
fn root(view: DocumentView<'_>) -> NodeIdentity {
    view.root_element()
}

fn document() -> XmlDocument {
    XmlDocument::parse("<root><a/></root>").expect("fixture parses")
}

fn append(document: &mut XmlDocument, child: &str) {
    let root = document.with_view(root);
    document.append_child(root, child).expect("append commits");
}

#[test]
fn a_successful_transaction_commits_one_generation() {
    // Several commits inside one transaction publish as a single generation,
    // so a reader never observes the intermediate states.
    let mut document = document();
    let start = document.generation();
    document
        .transaction(|document| {
            append(document, "<b/>");
            append(document, "<c/>");
            Ok::<_, ()>(())
        })
        .expect("transaction succeeds");
    assert_eq!(document.as_xml(), "<root><a/><b/><c/></root>");
    assert_eq!(document.generation(), start + 1);
}

#[test]
fn a_failed_transaction_restores_the_document_and_its_identities() {
    // Failure after commits must leave the exact serialization, generation and
    // previously captured identities, not a partially applied mutation.
    let mut document = document();
    let start = document.generation();
    let a = document.with_view(|view| {
        view.document()
            .descendants()
            .find(|node| node.has_tag_name("a"))
            .map(|node| view.node_identity(node))
            .expect("fixture has a")
    });
    let result = document.transaction(|document| {
        append(document, "<b/>");
        Err::<(), _>("refused")
    });
    assert_eq!(result, Err("refused"));
    assert_eq!(document.as_xml(), "<root><a/></root>");
    assert_eq!(document.generation(), start);
    document
        .append_child(a, "<inner/>")
        .expect("an identity captured before the transaction stays valid");
}

#[test]
fn an_inner_failure_keeps_the_outer_commits() {
    // A nested failure is a savepoint: the enclosing transaction keeps what it
    // committed before the inner one began and can still succeed.
    let mut document = document();
    let start = document.generation();
    document
        .transaction(|document| {
            append(document, "<b/>");
            let inner = document.transaction(|document| {
                append(document, "<c/>");
                Err::<(), _>("inner")
            });
            assert_eq!(inner, Err("inner"));
            assert_eq!(document.as_xml(), "<root><a/><b/></root>");
            Ok::<_, &str>(())
        })
        .expect("outer transaction succeeds");
    assert_eq!(document.as_xml(), "<root><a/><b/></root>");
    assert_eq!(document.generation(), start + 1);
}

#[test]
fn an_outer_failure_undoes_an_inner_success() {
    // The enclosing transaction committed nothing before the inner one, so the
    // inner savepoint is its only way back. A single-slot rollback state loses
    // it when the inner transaction finishes.
    let mut document = document();
    let start = document.generation();
    let result = document.transaction(|document| {
        document
            .transaction(|document| {
                append(document, "<b/>");
                Ok::<_, &str>(())
            })
            .expect("inner transaction succeeds");
        append(document, "<c/>");
        Err::<(), _>("outer")
    });
    assert_eq!(result, Err("outer"));
    assert_eq!(document.as_xml(), "<root><a/></root>");
    assert_eq!(document.generation(), start);
}

#[test]
fn an_outer_failure_after_its_own_commit_undoes_everything() {
    // With an outer commit before the inner transaction, the outer frame keeps
    // its own starting cell; the inner success must not replace it.
    let mut document = document();
    let start = document.generation();
    let result = document.transaction(|document| {
        append(document, "<b/>");
        document
            .transaction(|document| {
                append(document, "<c/>");
                Ok::<_, &str>(())
            })
            .expect("inner transaction succeeds");
        Err::<(), _>("outer")
    });
    assert_eq!(result, Err("outer"));
    assert_eq!(document.as_xml(), "<root><a/></root>");
    assert_eq!(document.generation(), start);
}

#[test]
fn an_unwinding_transaction_restores_the_document() {
    // A panic inside the closure is a failure too: the guard rolls back while
    // unwinding, so the caught document is the starting one.
    let mut document = document();
    let start = document.generation();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        document.transaction(|document| -> Result<(), ()> {
            append(document, "<b/>");
            panic!("closure unwinds")
        })
    }));
    assert!(unwound.is_err());
    assert_eq!(document.as_xml(), "<root><a/></root>");
    assert_eq!(document.generation(), start);
}
