//! Canonicalization allocates per serialization, not per start tag: the
//! namespace declarations and attributes of each start tag reuse one buffer
//! each for the whole walk.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt::Write as _;

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_document};

/// Counts fresh allocations per thread. Growing an existing block is not
/// counted: the output buffer grows with the document by design.
struct Counting;

thread_local! {
    // Per thread, so the test harness allocating on its own threads while a
    // serialization is measured does not count. A const initializer without
    // a destructor never allocates, so the allocator may read it.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to the system allocator with the caller's
// layout; only the counter is added.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        // SAFETY: forwarded unchanged from the caller's contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged from the caller's contract.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged from the caller's contract.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// `elements` siblings, each with two attributes, one with a prefix the root
/// declares but does not use: Exclusive C14N declares it on every sibling.
fn document(elements: usize) -> XmlDocument {
    let mut xml = String::from("<root xmlns:a=\"urn:a\">");
    for index in 0..elements {
        write!(xml, "<e id=\"e{index}\" a:k=\"{index}\">text</e>")
            .expect("writing to a String cannot fail");
    }
    xml.push_str("</root>");
    XmlDocument::parse(xml).expect("test document")
}

fn allocations(document: &XmlDocument, algorithm: &C14nAlgorithm) -> usize {
    let before = ALLOCATIONS.get();
    let canonical = canonicalize_document(document, algorithm).expect("canonicalization");
    let count = ALLOCATIONS.get() - before;
    drop(canonical);
    count
}

#[test]
fn start_tags_do_not_allocate_per_element() {
    // A declaration or attribute list allocated per start tag adds one
    // allocation per element: 240 more elements would show as 240 more.
    let small = document(16);
    let large = document(256);
    for mode in [
        C14nMode::Inclusive1_0,
        C14nMode::Inclusive1_1,
        C14nMode::Exclusive1_0,
    ] {
        for with_comments in [false, true] {
            let algorithm = C14nAlgorithm::new(mode, with_comments);
            assert_eq!(
                allocations(&large, &algorithm),
                allocations(&small, &algorithm),
                "{mode:?} (comments: {with_comments}) allocations grow with the element count",
            );
        }
    }
}
