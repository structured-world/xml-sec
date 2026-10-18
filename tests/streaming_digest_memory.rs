//! Terminal C14N streams into the Reference digest: verifying a large payload
//! never holds its whole canonical output in memory.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
    SignatureBuilder, SigningKey, VerificationKey, VerifyContext,
};

/// Live and peak heap bytes of this test binary.
struct Tracking;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to the system allocator with the caller's
// layout; only the byte counters are added.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged from the caller's contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged from the caller's contract.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged from the caller's contract.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            let live = if new_size >= layout.size() {
                LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                    - layout.size()
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed) - layout.size()
                    + new_size
            };
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

const PAYLOAD_KIB: usize = 4096;

#[test]
fn verifying_a_large_reference_never_holds_its_canonical_output() {
    // A single #payload Reference over 4 MiB of text: collecting the canonical
    // bytes before hashing would raise the peak by at least that much. The
    // streamed digest only holds serializer chunks and parser state.
    let block = "deterministic bulk text ".repeat(43);
    let mut unsigned = String::from("<Envelope><Payload Id=\"payload\">");
    for _ in 0..PAYLOAD_KIB {
        unsigned.push_str("<v>");
        unsigned.push_str(&block);
        unsigned.push_str("</v>");
    }
    unsigned.push_str("</Payload></Envelope>");
    let key = RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem"))
        .expect("test key");
    let template = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"))
    .build_template()
    .expect("template");
    let template = unsigned.replace("</Envelope>", &format!("{template}</Envelope>"));
    let signed = SignContext::new(&key)
        .sign_template(&template)
        .expect("signing");
    let verification_key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: key
            .public_key_info()
            .expect("public metadata")
            .spki_der()
            .expect("SPKI")
            .to_vec(),
        certificate_der: None,
        name: None,
    };
    let document = XmlDocument::parse(signed).expect("signed document");
    let canonical_bytes = PAYLOAD_KIB * 1024;

    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let valid = VerifyContext::new()
        .key(&verification_key)
        .verify_all(&document)
        .expect("verification")
        .all_valid();
    let growth = PEAK.load(Ordering::Relaxed) - before;

    assert!(valid);
    assert!(
        growth < canonical_bytes / 8,
        "verification peaked {growth} bytes above the parsed document for \
         {canonical_bytes} canonical bytes"
    );
}
