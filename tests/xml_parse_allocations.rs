#![cfg(feature = "xml-backend-xmloxide")]
//! The xmloxide parser hands each start tag's attributes to the semantic tree
//! without a list of its own per element: an attribute costs its name, its
//! value and the element's one attribute list.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};

use xml_sec::{XmlBackend, XmlDocument};

/// Counts fresh allocations of this test binary. Growing an existing block is
/// not counted: arena growth depends on the document size by design.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to the system allocator with the caller's
// layout; only the counter is added.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
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

const ELEMENTS: usize = 256;

/// `ELEMENTS` sibling elements, each with `attribute` in its start tag.
fn source(attribute: &str) -> String {
    let mut xml = String::from("<root>");
    for _ in 0..ELEMENTS {
        write!(xml, "<e{attribute}>text</e>").expect("writing to a String cannot fail");
    }
    xml.push_str("</root>");
    xml
}

fn allocations(xml: &str) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let document =
        XmlDocument::parse_with_backend(xml, XmlBackend::Xmloxide).expect("test document");
    let count = ALLOCATIONS.load(Ordering::Relaxed) - before;
    drop(document);
    count
}

#[test]
fn an_attribute_allocates_its_name_value_and_one_list() {
    // The parser fills one list for the whole parse, which the tree empties at
    // each start tag. A list per start tag that the tree copies from costs one
    // more allocation per element: four instead of three.
    let plain = source("");
    let attributed = source(" a=\"v\"");
    let extra = allocations(&attributed) - allocations(&plain);
    assert!(
        extra <= 3 * ELEMENTS + 1,
        "one attribute on each of {ELEMENTS} elements costs {extra} allocations"
    );
}
