#![cfg(feature = "xmlenc")]
//! Decryption keeps the `CipherValue` base64 copy no longer than it needs it:
//! the plaintext is not allocated while that copy is still held.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use xml_sec::XmlDocument;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
    SymmetricKeyDecryptor,
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

/// Peak heap growth while `operation` runs, its result dropped afterwards.
fn peak_growth<T>(operation: impl FnOnce() -> T) -> usize {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    drop(operation());
    PEAK.load(Ordering::Relaxed) - before
}

const PAYLOAD: usize = 1 << 20;

#[test]
fn plaintext_is_not_allocated_while_the_base64_copy_is_held() {
    // Decryption peaks about one payload above parsing the same document on
    // its own: the parse's transient buffers are gone by the time the
    // ciphertext and the plaintext are both live. Holding the base64 copy
    // until the plaintext exists adds another payload.
    let payload = vec![0x5a_u8; PAYLOAD];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .direct_key(vec![0x42; 32])
        .encrypt_binary(&payload)
        .expect("encrypt")
        .encrypted_data_xml;
    drop(payload);
    let decryptor = SymmetricKeyDecryptor::new(vec![0x42; 32]);
    let parse = peak_growth(|| XmlDocument::parse(&*encrypted).expect("encrypted document"));
    let decrypt = peak_growth(|| {
        let content = DecryptContext::new(&decryptor)
            .decrypt(&encrypted)
            .expect("decrypt");
        assert!(matches!(&content, DecryptedContent::Bytes(bytes) if bytes.len() == PAYLOAD));
        content
    });
    let above_parse = decrypt.saturating_sub(parse);
    assert!(
        above_parse < PAYLOAD * 3 / 2,
        "decryption peaked {above_parse} bytes above parsing for a {PAYLOAD}-byte payload"
    );
}
