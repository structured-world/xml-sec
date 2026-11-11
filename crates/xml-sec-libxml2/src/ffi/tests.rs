//! The clean C API over tree documents: documents the core parsed into the
//! handle table, operated on in place through a document handle, while the
//! caller keeps reading and changing the tree through the tree functions.

use std::ffi::{CStr, c_int};

use xml_sec_capi::ffi::{
    XsBytes, XsCompileContext, XsDecryptor, XsDocument, XsEncryptor, XsError, XsEvidence, XsKeys,
    XsPolicy, XsPolicyStore, XsProvider, XsSignatureOutcome, XsSigner, XsVerifier, XsVerifyRequest,
    xs_decrypt, xs_decryptor_destroy, xs_decryptor_new, xs_document_destroy, xs_encrypt,
    xs_encryptor_destroy, xs_encryptor_new, xs_error_destroy, xs_error_message,
    xs_evidence_accepted, xs_evidence_destroy, xs_evidence_signature, xs_keys_add_private_pem,
    xs_keys_add_public_pem, xs_keys_destroy, xs_keys_new, xs_policy_destroy,
    xs_policy_store_destroy, xs_policy_store_load, xs_policy_store_new, xs_provider_destroy,
    xs_provider_new_rustcrypto, xs_sign, xs_signer_destroy, xs_signer_new, xs_verifier_destroy,
    xs_verifier_new, xs_verify,
};
use xml_sec_capi::status::{XS_INVALID_ARGUMENT, XS_OK, XS_VERIFICATION, XsStatus};

use super::memory::xsFree;
use super::tree::{
    Doc, Node, xsDocDumpMemory, xsFreeDoc, xsNodeGetChildren, xsNodeGetNext, xsNodeSetContent,
    xsReadMemory,
};
use super::xs_tree_document;
use crate::nodes::{self, XML_ELEMENT_NODE};

fn bytes(text: &str) -> XsBytes {
    XsBytes {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

const MODERN: &str = "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const PRIVATE_KEY: &str = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
const PUBLIC_KEY: &str = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

const TEMPLATE: &str = concat!(
    "<root><p Id=\"payload\">signed</p><other>kept</other><!--note--><?pi data?>",
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>",
    "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
    "<ds:Reference URI=\"#payload\"><ds:Transforms>",
    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    "<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>",
    "<ds:SignatureValue></ds:SignatureValue>",
    "<ds:KeyInfo><ds:KeyName>signer</ds:KeyName></ds:KeyInfo></ds:Signature></root>"
);

/// A provider and the compiled policy of a configuration, released on drop.
struct Policy {
    provider: XsProvider,
    store: XsPolicyStore,
    snapshot: XsPolicy,
}

impl Policy {
    fn modern() -> Self {
        Self::from(MODERN)
    }

    /// The `app` profile of `configuration`.
    fn from(configuration: &str) -> Self {
        let (mut provider, mut store, mut policy) = (
            XsProvider::default(),
            XsPolicyStore::default(),
            XsPolicy::default(),
        );
        let context = XsCompileContext {
            external_resources: 0,
            target_evidence: 1,
        };
        // SAFETY: every pointer names a live local of the declared type.
        unsafe {
            assert_eq!(
                xs_provider_new_rustcrypto(&raw mut provider, std::ptr::null_mut()),
                XS_OK
            );
            assert_eq!(
                xs_policy_store_new(
                    bytes(configuration),
                    bytes("app"),
                    provider,
                    &raw const context,
                    std::ptr::null(),
                    &raw mut store,
                    std::ptr::null_mut(),
                ),
                XS_OK
            );
            assert_eq!(
                xs_policy_store_load(store, &raw mut policy, std::ptr::null_mut()),
                XS_OK
            );
        }
        Self {
            provider,
            store,
            snapshot: policy,
        }
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        assert_eq!(xs_policy_destroy(self.snapshot), XS_OK);
        assert_eq!(xs_policy_store_destroy(self.store), XS_OK);
        assert_eq!(xs_provider_destroy(self.provider), XS_OK);
    }
}

/// A tree document the core parsed, freed on drop.
struct Tree(*mut Doc);

impl Tree {
    fn parse(xml: &str) -> Self {
        // SAFETY: the buffer holds its length in bytes.
        let doc = unsafe {
            xsReadMemory(
                xml.as_ptr().cast(),
                c_int::try_from(xml.len()).expect("a small fixture"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        assert!(!doc.is_null(), "the fixture parses");
        Self(doc)
    }

    /// The document as the tree functions serialize it.
    fn dump(&self) -> String {
        let (mut memory, mut size) = (std::ptr::null_mut(), 0);
        // SAFETY: live outputs; the text is released after copying.
        unsafe {
            xsDocDumpMemory(self.0, &raw mut memory, &raw mut size);
            let text = CStr::from_ptr(memory.cast()).to_string_lossy().into_owned();
            xsFree(memory.cast());
            text
        }
    }

    /// Every node of the tree, in document order.
    fn nodes(&self) -> Vec<*mut Node> {
        fn collect(mut node: *mut Node, found: &mut Vec<*mut Node>) {
            while !node.is_null() {
                found.push(node);
                // SAFETY: the tree functions take any value.
                collect(unsafe { xsNodeGetChildren(node) }, found);
                // SAFETY: as above.
                node = unsafe { xsNodeGetNext(node) };
            }
        }
        let mut found = Vec::new();
        // SAFETY: as above.
        collect(unsafe { xsNodeGetChildren(self.0.cast()) }, &mut found);
        found
    }

    /// The first element named `name`.
    fn element(&self, name: &str) -> *mut Node {
        self.nodes()
            .into_iter()
            .find(|&node| {
                nodes::kind(node) == XML_ELEMENT_NODE && nodes::name(node).as_deref() == Some(name)
            })
            .expect("the element is present")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // SAFETY: freed once.
        unsafe { xsFreeDoc(self.0) };
    }
}

/// A document handle over `tree` for `operation`.
fn handle(policy: &Policy, operation: u32, tree: &Tree) -> XsDocument {
    let (mut document, mut error) = (XsDocument::default(), XsError::default());
    // SAFETY: the outputs are live locals.
    let status = unsafe {
        xs_tree_document(
            policy.snapshot,
            operation,
            tree.0,
            &raw mut document,
            &raw mut error,
        )
    };
    assert!(
        status == XS_OK,
        "the tree did not read for operation {operation}: {}",
        message(error)
    );
    document
}

fn message(error: XsError) -> String {
    let mut text = XsBytes {
        ptr: std::ptr::null(),
        len: 0,
    };
    // SAFETY: a live error handle; the message is copied before its release.
    let copied = unsafe {
        assert_eq!(xs_error_message(error, &raw mut text), XS_OK);
        String::from_utf8_lossy(std::slice::from_raw_parts(text.ptr, text.len)).into_owned()
    };
    assert_eq!(xs_error_destroy(error), XS_OK);
    copied
}

fn sign(policy: &Policy, document: XsDocument) -> XsStatus {
    let (mut keys, mut signer, mut error) =
        (XsKeys::default(), XsSigner::default(), XsError::default());
    // SAFETY: every pointer names a live local or string.
    let status = unsafe {
        assert_eq!(
            xs_keys_new(policy.snapshot, 2, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_private_pem(
                keys,
                bytes("signer"),
                bytes(PRIVATE_KEY),
                bytes(""),
                1,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_signer_new(
                policy.snapshot,
                policy.provider,
                keys,
                bytes("signer"),
                bytes(RSA_SHA256),
                &raw mut signer,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        xs_sign(signer, document, std::ptr::null_mut(), &raw mut error)
    };
    assert!(status == XS_OK, "signing failed: {}", message(error));
    assert_eq!(xs_signer_destroy(signer), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    status
}

/// Verify `document` with the signer's public key, run `between`, then ask
/// whether the evidence is still accepted: whether the first signature is
/// valid, and the acceptance answer or the status refusing it.
fn verify_then(
    policy: &Policy,
    document: XsDocument,
    between: impl FnOnce(),
) -> (bool, Result<bool, XsStatus>) {
    let (mut keys, mut verifier, mut evidence) = (
        XsKeys::default(),
        XsVerifier::default(),
        XsEvidence::default(),
    );
    let ids = [bytes("payload")];
    let request = XsVerifyRequest {
        expected_target_ids: ids.as_ptr(),
        expected_target_count: 1,
        requirement: 0,
        count: 0,
    };
    let mut outcome = XsSignatureOutcome::default();
    // SAFETY: every pointer names a live local, array or string.
    unsafe {
        assert_eq!(
            xs_keys_new(policy.snapshot, 1, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_public_pem(
                keys,
                bytes("signer"),
                bytes(PUBLIC_KEY),
                2,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_verifier_new(
                policy.snapshot,
                policy.provider,
                keys,
                &raw mut verifier,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        let mut error = XsError::default();
        let status = xs_verify(
            verifier,
            document,
            &raw const request,
            std::ptr::null(),
            &raw mut evidence,
            &raw mut error,
        );
        assert!(status == XS_OK, "verification failed: {}", message(error));
        assert_eq!(
            xs_evidence_signature(evidence, 0, &raw mut outcome, std::ptr::null_mut()),
            XS_OK
        );
    }
    between();
    let mut accepted = 0;
    // SAFETY: live handles and a live output.
    let status = unsafe {
        xs_evidence_accepted(evidence, document, &raw mut accepted, std::ptr::null_mut())
    };
    assert_eq!(xs_evidence_destroy(evidence), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    let answer = if status == XS_OK {
        Ok(accepted == 1)
    } else {
        Err(status)
    };
    (outcome.outcome == 1, answer)
}

fn verifies(policy: &Policy, document: XsDocument) -> bool {
    verify_then(policy, document, || ()).0
}

#[test]
fn a_template_signs_in_the_tree_and_every_untouched_node_keeps_its_handle() {
    // The signature values land in the tree: the payload, comments,
    // processing instructions and every node outside the signature values
    // keep their handles, and both the tree and its serialization verify.
    let policy = Policy::modern();
    let tree = Tree::parse(TEMPLATE);
    let before = tree.nodes();
    let signing = handle(&policy, 2, &tree);
    sign(&policy, signing);
    assert_eq!(xs_document_destroy(signing), XS_OK);
    let signed = tree.dump();
    assert!(
        !signed.contains("<ds:SignatureValue></ds:SignatureValue>"),
        "{signed}"
    );
    let after = tree.nodes();
    for node in before {
        assert!(after.contains(&node), "an untouched node lost its handle");
    }
    let verifying = handle(&policy, 1, &tree);
    assert!(verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
    let reparsed = Tree::parse(&signed);
    let verifying = handle(&policy, 1, &reparsed);
    assert!(verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

#[test]
fn a_change_through_the_tree_functions_is_seen_by_the_next_operation() {
    // The document handle reads the tree at every operation: a payload the
    // caller edits after signing no longer verifies, and evidence of the
    // earlier generation is refused.
    let policy = Policy::modern();
    let tree = Tree::parse(TEMPLATE);
    let document = handle(&policy, 2, &tree);
    sign(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    let verifying = handle(&policy, 1, &tree);
    assert_eq!(verify_then(&policy, verifying, || ()), (true, Ok(true)));
    let payload = tree.element("p");
    let edit = || {
        // SAFETY: the content is a NUL-terminated literal.
        let status = unsafe { xsNodeSetContent(payload, c"Signed".as_ptr().cast()) };
        assert_eq!(status, 0);
    };
    assert_eq!(
        verify_then(&policy, verifying, edit),
        (true, Err(XS_VERIFICATION))
    );
    assert!(!verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

/// Encrypt the element with ID `s` of the document behind `document`.
fn encrypt_in(policy: &Policy, document: XsDocument) {
    let (mut keys, mut encryptor) = (XsKeys::default(), XsEncryptor::default());
    // SAFETY: every pointer names a live local or string.
    unsafe {
        assert_eq!(
            xs_keys_new(policy.snapshot, 3, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_public_pem(
                keys,
                bytes("recipient"),
                bytes(PUBLIC_KEY),
                4,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_encryptor_new(
                policy.snapshot,
                policy.provider,
                keys,
                bytes("recipient"),
                bytes(AES256_GCM),
                &raw mut encryptor,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_encrypt(
                encryptor,
                document,
                bytes("s"),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            XS_OK
        );
    }
    assert_eq!(xs_encryptor_destroy(encryptor), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
}

/// Decrypt the one `EncryptedData` of the document behind `document`.
fn decrypt_in(policy: &Policy, document: XsDocument) {
    let (mut keys, mut decryptor) = (XsKeys::default(), XsDecryptor::default());
    // SAFETY: as above.
    unsafe {
        assert_eq!(
            xs_keys_new(policy.snapshot, 4, &raw mut keys, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_keys_add_private_pem(
                keys,
                bytes("recipient"),
                bytes(PRIVATE_KEY),
                bytes(""),
                8,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        assert_eq!(
            xs_decryptor_new(
                policy.snapshot,
                policy.provider,
                keys,
                bytes("recipient"),
                &raw mut decryptor,
                std::ptr::null_mut()
            ),
            XS_OK
        );
        let mut error = XsError::default();
        let status = xs_decrypt(
            decryptor,
            document,
            bytes(""),
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut error,
        );
        assert!(status == XS_OK, "decryption failed: {}", message(error));
    }
    assert_eq!(xs_decryptor_destroy(decryptor), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
}

#[test]
fn an_element_encrypts_and_decrypts_in_the_tree() {
    // The encrypted element is replaced by EncryptedData in the tree and
    // restored by decryption; its siblings keep their handles, and the
    // replaced element's handle is refused afterwards.
    let policy = Policy::modern();
    let tree = Tree::parse(
        "<root><secret Id=\"s\">42<inner a=\"1\"/></secret><public>kept</public></root>",
    );
    let public = tree.element("public");
    let secret = tree.element("secret");
    let before = tree.dump();
    let document = handle(&policy, 3, &tree);
    encrypt_in(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    let encrypted = tree.dump();
    assert!(
        encrypted.contains("EncryptedData") && !encrypted.contains("<secret"),
        "{encrypted}"
    );
    assert!(tree.nodes().contains(&public));
    assert_eq!(nodes::kind(secret), 0, "the replaced element is refused");
    let document = handle(&policy, 4, &tree);
    decrypt_in(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(tree.dump(), before);
    assert!(tree.nodes().contains(&public));
}

#[test]
fn each_operation_reads_the_tree_under_its_own_policy() {
    // A handle created for verification with a small node limit is used to
    // encrypt and decrypt: each operation reads the tree under its own
    // compiled policy, never the one the handle was created for.
    let policy = Policy::from(concat!(
        "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n",
        "[profiles.app.verification.resources]\nmax_xml_nodes = 8\n"
    ));
    let tree = Tree::parse("<root><secret Id=\"s\">42</secret></root>");
    let document = handle(&policy, 1, &tree);
    encrypt_in(&policy, document);
    decrypt_in(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert!(tree.dump().contains("<secret Id=\"s\">42</secret>"));
}

#[test]
fn a_value_that_names_no_document_is_refused() {
    // Null, a node of a document, a forged value and a freed document are
    // refused before any work, never dereferenced.
    let policy = Policy::modern();
    let tree = Tree::parse("<root/>");
    let freed = Tree::parse("<gone/>");
    let gone = freed.0;
    drop(freed);
    let root: *mut Doc = tree.element("root").cast();
    for doc in [
        std::ptr::null_mut(),
        root,
        nodes::pointer_of(usize::MAX - 3),
        gone,
    ] {
        let mut document = XsDocument::default();
        // SAFETY: the outputs are live locals; the value is never read.
        let status = unsafe {
            xs_tree_document(
                policy.snapshot,
                1,
                doc,
                &raw mut document,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, XS_INVALID_ARGUMENT);
    }
}
