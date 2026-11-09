//! The bridge against the linked libxml2: documents libxml2 parsed, operated
//! on in place through the clean C API.

use super::{
    XML_ELEMENT_NODE, XmlDoc, XmlNode, expected_layout, layout_matches, linked_layout,
    xs_libxml2_document,
};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::Mutex;
use xml_sec_capi::ffi::{
    XsBytes, XsCompileContext, XsDecryptor, XsDocument, XsEncryptor, XsError, XsEvidence, XsKeys,
    XsPolicy, XsPolicyStore, XsProvider, XsSignatureOutcome, XsSigner, XsVerifier, XsVerifyRequest,
    xs_decrypt, xs_decryptor_destroy, xs_decryptor_new, xs_document_destroy, xs_document_serialize,
    xs_encrypt, xs_encryptor_destroy, xs_encryptor_new, xs_error_destroy, xs_error_message,
    xs_evidence_accepted, xs_evidence_destroy, xs_evidence_signature, xs_keys_add_private_pem,
    xs_keys_add_public_pem, xs_keys_destroy, xs_keys_new, xs_policy_destroy,
    xs_policy_store_destroy, xs_policy_store_load, xs_policy_store_new, xs_provider_destroy,
    xs_provider_new_rustcrypto, xs_sign, xs_signer_destroy, xs_signer_new, xs_verifier_destroy,
    xs_verifier_new, xs_verify,
};
use xml_sec_capi::status::{XS_DOCUMENT, XS_INVALID_ARGUMENT, XS_OK, XS_VERIFICATION, XsStatus};

unsafe extern "C" {
    fn xmlReadMemory(
        buffer: *const c_char,
        size: c_int,
        url: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut XmlDoc;
    fn xmlFreeDoc(doc: *mut XmlDoc);
    fn xmlDocDumpMemory(doc: *mut XmlDoc, memory: *mut *mut u8, size: *mut c_int);
    fn xmlGetID(doc: *mut XmlDoc, id: *const u8) -> *mut c_void;
    fn xmlNodeSetContent(node: *mut XmlNode, content: *const u8);
    fn xmlNewReference(doc: *mut XmlDoc, name: *const u8) -> *mut XmlNode;
    fn xmlAddChild(parent: *mut XmlNode, node: *mut XmlNode) -> *mut XmlNode;
    static xmlFree: unsafe extern "C" fn(*mut c_void);
}

/// `XML_PARSE_NOENT`: substitute entities, as libxmlsec1 parses.
const SUBSTITUTE_ENTITIES: c_int = 2;

/// The handle table and libxml2's global state are process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

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
    "<root><p Id=\"payload\">signed</p><other>kept</other>",
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

/// A provider and the compiled Modern policy, released on drop.
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

/// A document libxml2 parsed, freed on drop.
struct Libxml(*mut XmlDoc);

impl Libxml {
    fn parse(xml: &str, options: c_int) -> Self {
        Self::parse_bytes(xml.as_bytes(), options)
    }

    /// Parse `xml` in the encoding it declares.
    fn parse_bytes(xml: &[u8], options: c_int) -> Self {
        // SAFETY: the buffer is live for the call; libxml2 copies what it keeps.
        let doc = unsafe {
            xmlReadMemory(
                xml.as_ptr().cast(),
                c_int::try_from(xml.len()).expect("small fixture"),
                std::ptr::null(),
                std::ptr::null(),
                options,
            )
        };
        assert!(!doc.is_null(), "libxml2 parses the fixture");
        Self(doc)
    }

    /// The document as libxml2 serializes it.
    fn dump(&self) -> String {
        let (mut memory, mut size) = (std::ptr::null_mut(), 0);
        // SAFETY: a live document; the outputs are live locals, and the
        // memory libxml2 returns is released with its own `xmlFree`.
        unsafe {
            xmlDocDumpMemory(self.0, &raw mut memory, &raw mut size);
            let text =
                std::slice::from_raw_parts(memory, usize::try_from(size).expect("size")).to_vec();
            xmlFree(memory.cast());
            String::from_utf8(text).expect("libxml2 writes UTF-8")
        }
    }

    /// Every element of the tree, in document order.
    fn elements(&self) -> Vec<*mut XmlNode> {
        let mut found = Vec::new();
        // SAFETY: a live document; the walk reads links only.
        unsafe { collect((*self.0).children, &mut found) };
        found
    }

    /// The first element named `name`.
    fn element(&self, name: &str) -> *mut XmlNode {
        self.elements()
            .into_iter()
            .find(|&node| {
                // SAFETY: element names are NUL-terminated tree strings.
                unsafe { CStr::from_ptr((*node).name.cast()) }.to_bytes() == name.as_bytes()
            })
            .expect("the element is present")
    }
}

/// # Safety
/// `node` is null or a live node with live siblings and descendants.
unsafe fn collect(mut node: *mut XmlNode, found: &mut Vec<*mut XmlNode>) {
    while !node.is_null() {
        // SAFETY: the caller's contract.
        unsafe {
            if (*node).kind == XML_ELEMENT_NODE {
                found.push(node);
            }
            collect((*node).children, found);
            node = (*node).next;
        }
    }
}

impl Drop for Libxml {
    fn drop(&mut self) {
        // SAFETY: parsed by this fixture and freed once.
        unsafe { xmlFreeDoc(self.0) };
    }
}

/// A document handle over `doc` for `operation`.
fn handle(policy: &Policy, operation: u32, doc: &Libxml) -> XsDocument {
    let (mut document, mut error) = (XsDocument::default(), XsError::default());
    // SAFETY: `doc` outlives the handle in every test; the outputs are live.
    let status = unsafe {
        xs_libxml2_document(
            policy.snapshot,
            operation,
            doc.0,
            &raw mut document,
            &raw mut error,
        )
    };
    assert!(
        status == XS_OK,
        "the tree did not project for operation {operation}: {}",
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

/// Verify `document` with the signer's public key; whether its first
/// signature is valid.
fn verifies(policy: &Policy, document: XsDocument) -> bool {
    verify_then(policy, document, || ()).0
}

/// Verify `document` with the signer's public key, run `between`, then ask
/// whether the evidence is still accepted for the document: whether the
/// first signature is valid, and the acceptance answer, or the status
/// refusing evidence of an earlier generation.
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

#[test]
fn the_declared_layout_is_the_linked_headers_layout() {
    // A declaration that disagrees with the linked libxml2 would read the
    // wrong members; the bridge refuses to touch a tree then.
    assert_eq!(linked_layout(), expected_layout());
    assert!(layout_matches());
}

#[test]
fn a_template_signs_in_the_callers_tree_and_verifies_there() {
    // The signature values land in the caller's libxml2 nodes: the payload
    // and every node outside the signature keep their pointers, and both
    // the tree and its libxml2 serialization verify.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse(TEMPLATE, SUBSTITUTE_ENTITIES);
    let (payload, other, signature) = (
        doc.element("p"),
        doc.element("other"),
        doc.element("Signature"),
    );
    let signing = handle(&policy, 2, &doc);
    sign(&policy, signing);
    assert_eq!(xs_document_destroy(signing), XS_OK);
    let signed = doc.dump();
    assert!(
        !signed.contains("<ds:SignatureValue></ds:SignatureValue>"),
        "{signed}"
    );
    let elements = doc.elements();
    for kept in [payload, other, signature] {
        assert!(
            elements.contains(&kept),
            "an untouched element was replaced"
        );
    }
    let verifying = handle(&policy, 1, &doc);
    assert!(verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
    // The same bytes, parsed by libxml2 again, verify as a new tree too.
    let reparsed = Libxml::parse(&signed, SUBSTITUTE_ENTITIES);
    let verifying = handle(&policy, 1, &reparsed);
    assert!(verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

#[test]
fn a_change_the_caller_makes_between_calls_is_seen() {
    // The handle reads the tree at every operation: a payload the caller
    // edits after signing no longer verifies.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse(TEMPLATE, SUBSTITUTE_ENTITIES);
    let document = handle(&policy, 2, &doc);
    sign(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    let verifying = handle(&policy, 1, &doc);
    assert!(verifies(&policy, verifying));
    let payload = doc.element("p");
    // SAFETY: the payload's text child is a live text node with libxml2
    // content; rewriting its first byte keeps the string valid.
    unsafe { *(*(*payload).children).content = b'S' };
    assert!(!verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

#[test]
fn evidence_is_accepted_only_while_the_tree_is_unchanged() {
    // Acceptance answers for the document as it is: evidence of a tree the
    // caller left alone stays accepted, and a change after verification makes
    // it evidence of an earlier generation, refused as for a text document
    // changed after verification.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse(TEMPLATE, 0);
    let document = handle(&policy, 2, &doc);
    sign(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    let verifying = handle(&policy, 1, &doc);
    assert_eq!(verify_then(&policy, verifying, || ()), (true, Ok(true)));
    let payload = doc.element("p");
    let edit = || {
        // SAFETY: the payload's text child is a live text node with libxml2
        // content; rewriting its first byte keeps the string valid.
        unsafe { *(*(*payload).children).content = b'S' };
    };
    assert_eq!(
        verify_then(&policy, verifying, edit),
        (true, Err(XS_VERIFICATION))
    );
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

#[test]
fn an_xml_id_in_the_tree_is_a_reference_target() {
    // xml:id is an ID without any declaration (xml:id 1.0 section 4), so a
    // reference to it resolves in the projected tree as in parsed text.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let xml = TEMPLATE.replace("<p Id=\"payload\">", "<p xml:id=\"payload\">");
    let doc = Libxml::parse(&xml, 0);
    let document = handle(&policy, 2, &doc);
    sign(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    let verifying = handle(&policy, 1, &doc);
    assert!(verifies(&policy, verifying));
    assert_eq!(xs_document_destroy(verifying), XS_OK);
}

/// Encrypt the element with ID `s` of `doc` for the RSA test key.
fn encrypt(policy: &Policy, doc: &Libxml) {
    let document = handle(policy, 3, doc);
    encrypt_in(policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
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

/// Decrypt the one `EncryptedData` of `doc` with the RSA test key.
fn decrypt(policy: &Policy, doc: &Libxml) {
    let document = handle(policy, 4, doc);
    decrypt_in(policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
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
fn each_operation_reads_the_tree_under_its_own_policy() {
    // A handle created for verification with a small node limit is later
    // used to encrypt and decrypt: the encrypted tree is larger than the
    // verification limit allows, but each operation reads the tree under its
    // own compiled policy, never the one the handle was created for.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::from(concat!(
        "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n",
        "[profiles.app.verification.resources]\nmax_xml_nodes = 8\n"
    ));
    let doc = Libxml::parse("<root><secret Id=\"s\">42</secret></root>", 0);
    let document = handle(&policy, 1, &doc);
    encrypt_in(&policy, document);
    decrypt_in(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert!(doc.dump().contains("<secret Id=\"s\">42</secret>"));
}

#[test]
fn an_element_encrypts_and_decrypts_in_the_callers_tree() {
    // The encrypted element is replaced by EncryptedData in the caller's
    // tree and restored by decryption; its siblings keep their pointers.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let xml = "<root><secret Id=\"s\">42<inner a=\"1\"/></secret><public>kept</public></root>";
    let doc = Libxml::parse(xml, SUBSTITUTE_ENTITIES);
    let public = doc.element("public");
    let before = doc.dump();
    encrypt(&policy, &doc);
    let encrypted = doc.dump();
    // The plaintext is gone as markup; the random base64 ciphertext may hold
    // any digit pair, so the bare value is not a check.
    assert!(
        encrypted.contains("EncryptedData")
            && !encrypted.contains("<secret")
            && !encrypted.contains(">42<"),
        "{encrypted}"
    );
    assert!(doc.elements().contains(&public));
    decrypt(&policy, &doc);
    let canonical = |xml: &str| {
        xml_sec::c14n::canonicalize_xml(
            xml.as_bytes(),
            &xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_0, true),
        )
        .expect("canonicalizes")
    };
    assert_eq!(canonical(&doc.dump()), canonical(&before));
    assert!(doc.elements().contains(&public));
}

#[test]
fn the_id_table_names_only_live_attributes_across_encryption() {
    // libxml2's ID table points at attribute nodes: an element the operation
    // removes and frees must leave no entry behind, and the element decryption
    // restores is registered again, so the caller's xmlGetID never returns a
    // freed attribute.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    // The operation selects the element by Id; libxml2 registers its xml:id.
    let doc = Libxml::parse("<root><secret xml:id=\"k\" Id=\"s\">42</secret></root>", 0);
    // SAFETY: a live document and a NUL-terminated name.
    let id = |doc: &Libxml| unsafe { xmlGetID(doc.0, c"k".as_ptr().cast()) };
    assert!(!id(&doc).is_null(), "libxml2 registers xml:id");
    encrypt(&policy, &doc);
    assert!(id(&doc).is_null(), "the freed attribute left the ID table");
    decrypt(&policy, &doc);
    let secret = doc.element("secret");
    // SAFETY: the restored element is live and its first attribute is xml:id.
    let attribute = unsafe { (*secret).properties };
    assert_eq!(
        id(&doc),
        attribute.cast(),
        "the restored attribute is the ID"
    );
}

#[test]
fn a_replacement_that_keeps_an_id_keeps_it_registered() {
    // The replacement's xml:id is created while the replaced element still
    // holds the same value, which libxml2 refuses to register twice; once
    // the operation frees the old element, the new attribute must be the
    // one the ID table names.
    use xml_sec::policy::VerificationPolicy;
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let doc = Libxml::parse("<root><secret xml:id=\"k\" Id=\"s\">old</secret></root>", 0);
    // SAFETY: a live document and a NUL-terminated name.
    let id = |doc: &Libxml| unsafe { xmlGetID(doc.0, c"k".as_ptr().cast()) };
    let mut document = tree_document(&doc, &VerificationPolicy::default());
    let target = document
        .with_view(|view| view.node_for_id("s", &[]))
        .expect("the element is present");
    document
        .replace_element(target, "<secret xml:id=\"k\" Id=\"s\">new</secret>")
        .expect("the element is replaced");
    let secret = doc.element("secret");
    // SAFETY: the replacement is live and its first attribute is xml:id.
    let attribute = unsafe { (*secret).properties };
    assert_eq!(id(&doc), attribute.cast(), "the new attribute is the ID");
}

/// The identity of the document element, for `XmlDocument::with_view`.
fn root_of(view: xml_sec::DocumentView<'_>) -> xml_sec::NodeIdentity {
    view.root_element()
}

#[test]
fn comments_and_instructions_insert_before_the_document_element() {
    // The prolog holds comments, processing instructions and whitespace
    // before the document element (XML 1.0 section 2.8, productions 22 and
    // 27); inserting them there is an edit of the document node's children.
    // Whitespace is not content outside the document element and is not
    // kept as a node of the tree.
    use xml_sec::policy::VerificationPolicy;
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let doc = Libxml::parse("<root>t</root>", 0);
    let root = doc.element("root");
    let mut document = tree_document(&doc, &VerificationPolicy::default());
    let root_identity = |document: &xml_sec::XmlDocument| document.with_view(root_of);
    let target = root_identity(&document);
    document
        .insert_before(target, "<!--before-->\n<?pi data?>")
        .expect("prolog content inserts");
    assert!(
        doc.dump()
            .contains("<!--before-->\n<?pi data?>\n<root>t</root>"),
        "{}",
        doc.dump()
    );
    assert_eq!(doc.element("root"), root, "the document element is kept");
    let refused = document.insert_before(root_identity(&document), "<x/>");
    assert!(
        refused.is_err(),
        "a second element may not precede the document element"
    );
}

#[test]
fn a_document_element_with_xml_attributes_decrypts_in_place() {
    // Decrypting the document element rebuilds it with no context element:
    // its xml: attributes still bind the implicit XML namespace (Namespaces
    // in XML 1.0 section 3), which needs no declaration.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse("<secret Id=\"s\" xml:lang=\"en\">42</secret>", 0);
    encrypt(&policy, &doc);
    decrypt(&policy, &doc);
    let restored = doc.dump();
    assert!(
        restored.contains("<secret Id=\"s\" xml:lang=\"en\">42</secret>"),
        "{restored}"
    );
}

#[test]
fn a_tree_has_no_serialization_for_the_library_to_return() {
    // The caller serializes its tree with libxml2; the handle has no text.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse("<root/>", 0);
    let document = handle(&policy, 1, &doc);
    let mut buffer = std::mem::MaybeUninit::uninit();
    // SAFETY: a live handle and output.
    let status =
        unsafe { xs_document_serialize(document, buffer.as_mut_ptr(), std::ptr::null_mut()) };
    assert_eq!(status, XS_DOCUMENT);
    assert_eq!(xs_document_destroy(document), XS_OK);
}

#[test]
fn a_null_or_foreign_document_is_refused_before_any_work() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let mut document = XsDocument::default();
    // SAFETY: the null document is refused before it is read.
    let status = unsafe {
        xs_libxml2_document(
            policy.snapshot,
            1,
            std::ptr::null_mut(),
            &raw mut document,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_INVALID_ARGUMENT);
    // An element is not a document.
    let doc = Libxml::parse("<root/>", 0);
    let root = doc.element("root");
    // SAFETY: a live node whose type is read and found not to be a document.
    let status = unsafe {
        xs_libxml2_document(
            policy.snapshot,
            1,
            root.cast(),
            &raw mut document,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_INVALID_ARGUMENT);
}

/// `TEMPLATE` under an internal DTD that declares `ident` an ID attribute and
/// an entity the payload's content refers to; the clean C API's policies
/// admit no DTD.
fn dtd_template() -> String {
    let declared = concat!(
        "<!DOCTYPE root [<!ENTITY greeting \"signed\">",
        "<!ATTLIST p ident ID #IMPLIED>]>"
    );
    let body = TEMPLATE.replace(
        "<p Id=\"payload\">signed</p>",
        "<p ident=\"payload\">&greeting;</p>",
    );
    format!("{declared}{body}")
}

/// A tree-backed document over `doc` under `policy`.
fn tree_document(doc: &Libxml, policy: &impl xml_sec::XmlDocumentPolicy) -> xml_sec::XmlDocument {
    xml_sec::XmlDocument::from_external_tree(
        Box::new(super::LibxmlTree {
            doc: doc.0,
            journal: Vec::new(),
        }),
        policy,
    )
    .expect("the tree projects")
}

/// Whether `document`'s signature verifies with the certificate it carries,
/// with `ids` registered; trust is not under test.
fn carried_key_verifies(
    document: &xml_sec::XmlDocument,
    mut policy: xml_sec::policy::VerificationPolicy,
    ids: &[xml_sec::IdAttributeRegistration],
) -> bool {
    policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    let resolver = xml_sec::xmldsig::DefaultKeyResolver::default();
    xml_sec::xmldsig::VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .id_attributes(ids)
        .verify_document(document)
        .expect("verification runs")
        .status
        == xml_sec::xmldsig::DsigStatus::Valid
}

/// Append a signature over `#payload` to `document`'s root, with the test
/// certificate in `KeyInfo` and `ids` registered.
fn sign_payload(
    document: &mut xml_sec::XmlDocument,
    policy: xml_sec::policy::SigningPolicy,
    ids: &[xml_sec::IdAttributeRegistration],
) -> Result<(), xml_sec::xmldsig::SigningError> {
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
        SignatureBuilder, Transform, X509CertificateKeyInfoWriter,
    };
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("the test key parses");
    let certificate = X509CertificateKeyInfoWriter::from_pem(include_str!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .expect("the test certificate parses");
    let canonical = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(canonical.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(canonical)),
        )
        .key_info(true);
    SignContext::new(&key)
        .policy(policy)
        .key_info_writer(&certificate)
        .id_attributes(ids)
        .sign_document_with_builder(document, &builder)
        .map(drop)
}

#[test]
fn caller_registered_ids_resolve_in_the_tree() {
    // An ID attribute the caller registers selects the reference target in
    // the projected tree; without the registration the reference has no
    // target and signing fails.
    use xml_sec::policy::{SigningPolicy, VerificationPolicy};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ids = [xml_sec::IdAttributeRegistration::global("Token")];
    let doc = Libxml::parse("<root><p Token=\"payload\">signed</p></root>", 0);
    let mut document = tree_document(&doc, &SigningPolicy::default());
    sign_payload(&mut document, SigningPolicy::default(), &ids).expect("the tree signs");
    drop(document);
    let verification = VerificationPolicy::default();
    let document = tree_document(&doc, &verification);
    assert!(carried_key_verifies(&document, verification, &ids));
    let unregistered = Libxml::parse("<root><p Token=\"payload\">signed</p></root>", 0);
    let mut document = tree_document(&unregistered, &SigningPolicy::default());
    assert!(
        sign_payload(&mut document, SigningPolicy::default(), &[]).is_err(),
        "an unregistered Token is no ID"
    );
}

#[test]
fn dtd_ids_and_kept_entity_references_are_read_from_the_tree() {
    // Parsed without entity substitution, libxml2 keeps the reference node
    // and types `ident` as an ID from the DTD: the projection reads the
    // entity's replacement (XML 1.0 section 4.4.2) and resolves `#payload`
    // through that ID, so the signature made on this tree verifies on a
    // substituted parse as well.
    use xml_sec::policy::{SigningPolicy, VerificationPolicy, XmlInputPolicy};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let xml = concat!(
        "<!DOCTYPE root [<!ENTITY greeting \"signed\"><!ATTLIST p ident ID #IMPLIED>]>",
        "<root><p ident=\"payload\">&greeting;</p><other>kept</other></root>"
    );
    let dtd = XmlInputPolicy {
        allow_internal_dtd: true,
    };
    let signing = SigningPolicy {
        xml: dtd,
        ..SigningPolicy::default()
    };
    let verification = VerificationPolicy {
        xml: dtd,
        ..VerificationPolicy::default()
    };
    let kept = Libxml::parse(xml, 0);
    let mut document = tree_document(&kept, &signing);
    sign_payload(&mut document, signing, &[]).expect("the tree signs");
    drop(document);
    let dumped = kept.dump();
    assert!(
        dumped.contains("&greeting;"),
        "the reference stays: {dumped}"
    );
    assert!(carried_key_verifies(
        &tree_document(&kept, &verification),
        verification.clone(),
        &[]
    ));
    let substituted = Libxml::parse(&dumped, SUBSTITUTE_ENTITIES);
    assert!(carried_key_verifies(
        &tree_document(&substituted, &verification),
        verification,
        &[]
    ));
}

/// A document whose internal DTD declares `e{levels}`, expanding to
/// `2^levels` copies of `leaf`, and whose root attribute holds a reference to
/// it as an entity-reference child. The application builds that attribute
/// through the tree API, so no parser amplification guard sees it.
fn nested_attribute_entities(levels: usize, leaf: &str) -> Libxml {
    use std::fmt::Write as _;
    let mut dtd = format!("<!ENTITY e0 \"{leaf}\">");
    for level in 1..=levels {
        let below = level - 1;
        write!(dtd, "<!ENTITY e{level} \"&e{below};&e{below};\">").expect("writes to a String");
    }
    let doc = Libxml::parse(&format!("<!DOCTYPE r [{dtd}]><r a=\"x\"/>"), 0);
    let reference = std::ffi::CString::new(format!("&e{levels};")).expect("no NUL");
    // SAFETY: the root's only attribute is live; libxml2 parses the content
    // into an entity-reference child bound to the declaration.
    unsafe {
        let attribute = (*doc.element("r")).properties;
        xmlNodeSetContent(attribute.cast(), reference.as_ptr().cast());
    }
    doc
}

/// As [`nested_attribute_entities`], with each level referring once to the
/// one below, down to a one-byte leaf.
fn chained_attribute_entities(levels: usize) -> Libxml {
    use std::fmt::Write as _;
    let mut dtd = String::from("<!ENTITY e0 \"x\">");
    for level in 1..=levels {
        let below = level - 1;
        write!(dtd, "<!ENTITY e{level} \"&e{below};\">").expect("writes to a String");
    }
    let doc = Libxml::parse(&format!("<!DOCTYPE r [{dtd}]><r a=\"x\"/>"), 0);
    let reference = std::ffi::CString::new(format!("&e{levels};")).expect("no NUL");
    // SAFETY: as in `nested_attribute_entities`.
    unsafe {
        let attribute = (*doc.element("r")).properties;
        xmlNodeSetContent(attribute.cast(), reference.as_ptr().cast());
    }
    doc
}

/// The text of the root element's children and the value of its attribute
/// `a`, as the projection of `doc` under a policy admitting a DTD reads them.
fn projected_root(doc: &Libxml) -> Result<(String, Option<String>), xml_sec::XmlDocumentError> {
    use xml_sec::policy::{VerificationPolicy, XmlInputPolicy};
    let policy = VerificationPolicy {
        xml: XmlInputPolicy {
            allow_internal_dtd: true,
        },
        ..VerificationPolicy::default()
    };
    let document = xml_sec::XmlDocument::from_external_tree(
        Box::new(super::LibxmlTree {
            doc: doc.0,
            journal: Vec::new(),
        }),
        &policy,
    )?;
    Ok(document.with_view(|view| {
        let root = view.document().root_element();
        let text = root.children().filter_map(xml_sec::Node::text).collect();
        (text, root.attribute("a").map(String::from))
    }))
}

#[test]
fn an_entity_with_an_empty_replacement_projects_as_nothing() {
    // XML 1.0 section 2.3 (production 9) admits an empty entity value; libxml2
    // then keeps no replacement nodes for the declaration.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let doc = Libxml::parse("<!DOCTYPE r [<!ENTITY e ''>]><r a=\"x\">t&e;u</r>", 0);
    assert_eq!(
        projected_root(&doc).expect("an empty entity projects"),
        ("tu".to_owned(), Some("x".to_owned()))
    );
}

#[test]
fn a_predefined_entity_reference_projects_as_its_character() {
    // A reference the application builds to a predefined entity
    // (XML 1.0 section 4.6) points to a declaration that holds its character
    // as content and no replacement nodes; in content and in an attribute it
    // reads as that character, as libxml2 itself reads it.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let doc = Libxml::parse("<r a=\"x\">t</r>", 0);
    let root = doc.element("r");
    // SAFETY: a live document and element; the references are new, detached
    // nodes, one appended to the root and one made the attribute's only
    // child in place of its text, which is unlinked and freed.
    unsafe {
        let content = xmlNewReference(doc.0, c"&amp;".as_ptr().cast());
        assert!(!xmlAddChild(root, content).is_null());
        let attribute = (*root).properties;
        let value = xmlNewReference(doc.0, c"&lt;".as_ptr().cast());
        let old = (*attribute).children;
        super::xmlUnlinkNode(old);
        super::xmlFreeNode(old);
        (*attribute).children = value;
        (*attribute).last = value;
        (*value).parent = attribute.cast();
    }
    assert_eq!(
        projected_root(&doc).expect("a predefined reference projects"),
        ("t&".to_owned(), Some("<".to_owned()))
    );
}

#[test]
fn attribute_entity_expansion_is_bounded_while_the_value_is_built() {
    // References the tree keeps inside an attribute value are expanded by
    // the projection; each expansion counts toward the entity ceiling and
    // each piece toward the byte limit before it is copied, so nesting can
    // spend neither time nor memory past the policy (XML 1.0 section 4.4.5).
    use xml_sec::policy::{VerificationPolicy, XmlInputPolicy};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = VerificationPolicy {
        xml: XmlInputPolicy {
            allow_internal_dtd: true,
        },
        ..VerificationPolicy::default()
    };
    // 2^15 expansions of an empty entity: no bytes, only work.
    let empty = nested_attribute_entities(15, "");
    let refused = xml_sec::XmlDocument::from_external_tree(
        Box::new(super::LibxmlTree {
            doc: empty.0,
            journal: Vec::new(),
        }),
        &policy,
    );
    assert!(
        matches!(
            refused,
            Err(xml_sec::XmlDocumentError::Parse(
                xml_sec::ParseError::EntityExpansionLimitReached { .. }
            ))
        ),
        "{:?}",
        refused.err()
    );
    // Deep nesting alone is no reason to refuse: a chain of 100 references
    // is 100 expansions and one byte, within every limit, and the walk keeps
    // its levels on the heap.
    let chain = chained_attribute_entities(100);
    assert_eq!(
        projected_root(&chain)
            .expect("the chain projects")
            .1
            .as_deref(),
        Some("x"),
        "the value is the leaf the chain expands to"
    );
    // 2^16 bytes through 2^11 expansions: refused at the byte limit before
    // the value is built past it.
    let mut limited = policy;
    limited.resources.max_xml_document_bytes = 4_096;
    let large = nested_attribute_entities(11, &"A".repeat(32));
    let refused = xml_sec::XmlDocument::from_external_tree(
        Box::new(super::LibxmlTree {
            doc: large.0,
            journal: Vec::new(),
        }),
        &limited,
    );
    assert!(
        matches!(
            refused,
            Err(xml_sec::XmlDocumentError::Parse(
                xml_sec::ParseError::ByteLimitReached { .. }
            ))
        ),
        "{:?}",
        refused.err()
    );
}

#[test]
fn a_tree_with_a_dtd_is_refused_unless_the_policy_allows_one() {
    // The tree's DTD is the same input risk as a parsed one (XML 1.0
    // section 2.8): the default policy refuses to read it.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let doc = Libxml::parse(&dtd_template(), 0);
    let (mut document, mut error) = (XsDocument::default(), XsError::default());
    // SAFETY: `doc` is live for the call; the outputs are live locals.
    let status = unsafe {
        xs_libxml2_document(policy.snapshot, 1, doc.0, &raw mut document, &raw mut error)
    };
    assert_ne!(status, XS_OK);
    assert!(message(error).contains("DTD"), "the refusal names the DTD");
}

/// Documents whose projection must lose nothing a canonical form shows:
/// namespace scopes and redeclarations, namespaced and `xml:` attributes,
/// comments and processing instructions inside and around the root, CDATA,
/// character references, attribute whitespace and non-ASCII text.
const DIFFERENTIAL: [&str; 4] = [
    concat!(
        "<?xml-stylesheet href=\"a.xsl\"?><!-- before --><r xmlns=\"urn:d\" xmlns:a=\"urn:a\">",
        "<a:e a:k=\"1\" k=\"2\" xml:lang=\"en\"><e xmlns=\"\" xmlns:a=\"urn:other\"><a:x/></e></a:e>",
        "<!-- inside --><?pi data?></r><!-- after -->"
    ),
    "<r>t<![CDATA[<raw> & ]]>u&amp;&lt;&gt;&#x10FFFF;<e/>v<e></e></r>",
    "<r a=\"x&#9;y&#10;z&#13;&quot;&lt;&amp;\" b='&apos;'>\u{e9}\u{4e2d}\u{1f600}</r>",
    "<r xmlns:u=\"urn:u\"><u:e xmlns:u=\"urn:u\"/>  <e>\n  mixed <i>in</i> text\n</e></r>",
];

#[test]
fn a_projected_tree_canonicalizes_as_its_text_does() {
    // Differential check of the projection against the text parser: for each
    // document, the libxml2 tree and the same text give the same inclusive
    // C14N with comments, which renders every node kind and namespace scope
    // (C14N 1.0 section 2).
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_document, canonicalize_xml};
    use xml_sec::policy::VerificationPolicy;
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = VerificationPolicy::default();
    for mode in [C14nMode::Inclusive1_0, C14nMode::Exclusive1_0] {
        let algorithm = C14nAlgorithm::new(mode, true);
        for xml in DIFFERENTIAL {
            let tree = Libxml::parse(xml, 0);
            let projected = canonicalize_document(&tree_document(&tree, &policy), &algorithm)
                .expect("the projection canonicalizes");
            let parsed =
                canonicalize_xml(xml.as_bytes(), &algorithm).expect("the text canonicalizes");
            assert_eq!(
                String::from_utf8_lossy(&projected),
                String::from_utf8_lossy(&parsed),
                "{mode:?}: {xml}"
            );
        }
    }
}

#[test]
fn a_document_in_another_encoding_projects_as_its_characters() {
    // libxml2 decodes a declared encoding into UTF-8 node content, so the
    // projection sees the characters, not the source bytes (XML 1.0 section
    // 4.3.3): ISO-8859-1 0xE9 is U+00E9.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_document};
    use xml_sec::policy::VerificationPolicy;
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let latin = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r a=\"\xe9\">caf\xe9</r>";
    let tree = Libxml::parse_bytes(latin, 0);
    let canonical = canonicalize_document(
        &tree_document(&tree, &VerificationPolicy::default()),
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
    )
    .expect("the projection canonicalizes");
    assert_eq!(canonical, "<r a=\"\u{e9}\">caf\u{e9}</r>".as_bytes());
}

#[test]
fn untouched_nodes_of_every_kind_keep_their_pointers_through_an_operation() {
    // Signing rewrites only the template's values: comments, processing
    // instructions, CDATA and text elsewhere stay the very nodes the caller
    // holds, and the tree's links stay consistent.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = Policy::modern();
    let xml = TEMPLATE.replace(
        "<other>kept</other>",
        "<other>kept<!-- c --><?pi d?><![CDATA[raw]]></other>",
    );
    let doc = Libxml::parse(&xml, 0);
    let other = doc.element("other");
    let before = children(other);
    let document = handle(&policy, 2, &doc);
    sign(&policy, document);
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(children(other), before);
    // SAFETY: a live document; the walk reads links only.
    unsafe { check_links(doc.0.cast(), (*doc.0).children) };
}

/// The child nodes of `parent`, in order.
fn children(parent: *mut XmlNode) -> Vec<*mut XmlNode> {
    let mut found = Vec::new();
    // SAFETY: a live element of a live document.
    let mut child = unsafe { (*parent).children };
    while !child.is_null() {
        found.push(child);
        // SAFETY: as above.
        child = unsafe { (*child).next };
    }
    found
}

/// Assert that every node from `first` on names `parent` as its parent and
/// its neighbours as each other's, and that `parent`'s `last` is the end.
///
/// # Safety
/// `parent` and its descendants are live.
unsafe fn check_links(parent: *mut XmlNode, first: *mut XmlNode) {
    let mut previous: *mut XmlNode = std::ptr::null_mut();
    let mut node = first;
    // SAFETY: the caller's contract.
    unsafe {
        while !node.is_null() {
            assert_eq!((*node).parent, parent);
            assert_eq!((*node).prev, previous);
            if (*node).kind == XML_ELEMENT_NODE {
                check_links(node, (*node).children);
            }
            previous = node;
            node = (*node).next;
        }
        assert_eq!((*parent).last, previous);
    }
}

/// The bytes libxml2 writes for `doc`, in the document's own encoding.
fn dump_bytes(doc: *mut XmlDoc) -> Vec<u8> {
    let (mut memory, mut size) = (std::ptr::null_mut(), 0);
    // SAFETY: a live document; the memory is released with libxml2's `xmlFree`.
    unsafe {
        xmlDocDumpMemory(doc, &raw mut memory, &raw mut size);
        let bytes =
            std::slice::from_raw_parts(memory, usize::try_from(size).expect("size")).to_vec();
        xmlFree(memory.cast());
        bytes
    }
}

/// A document the core parsed becomes a libxml2 document libxml2 writes as
/// it writes its own parse of the same bytes: top-level comments and
/// processing instructions, namespaces, the declared encoding and standalone
/// value, and an `xml:id` registered in the ID table.
#[test]
fn a_core_document_becomes_the_libxml2_document_of_its_source() {
    let _serial = SERIAL.lock().expect("serial");
    let sources: [&[u8]; 4] = [
        b"<a x='1'><b>t</b></a>",
        b"<?xml version='1.0' standalone='yes'?><!--c--><?p v?><d:r xmlns:d='urn:d' xmlns='urn:e'><d:s a='&lt;'/><t/></d:r><!--e-->",
        b"<?xml version='1.0' encoding='ISO-8859-1'?><r>\xE9</r>",
        b"<?xml version='1.0'?><r><s xml:id='k'/></r>",
    ];
    for source in sources {
        let parsed = xml_sec::XmlDocument::parse_bytes(source).expect("the core parses");
        let built = super::new_document(&parsed).expect("the document builds");
        let expected = Libxml::parse_bytes(source, 0);
        assert_eq!(
            String::from_utf8_lossy(&dump_bytes(built)),
            String::from_utf8_lossy(&dump_bytes(expected.0)),
        );
        // SAFETY: the built document is live and freed once.
        unsafe {
            check_links(built.cast(), (*built).children);
            if source.windows(6).any(|window| window == b"xml:id") {
                assert!(!xmlGetID(built, c"k".as_ptr().cast()).is_null());
            }
            xmlFreeDoc(built);
        }
    }
}

/// A document type declaration is refused rather than dropped: the libxml2
/// document would lose the declarations its content depends on.
#[test]
fn a_document_type_declaration_is_not_built() {
    let _serial = SERIAL.lock().expect("serial");
    let policy = xml_sec::policy::VerificationPolicy {
        xml: xml_sec::policy::XmlInputPolicy {
            allow_internal_dtd: true,
        },
        ..Default::default()
    };
    let parsed = xml_sec::XmlDocument::parse_bytes_with_policy(
        b"<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED>]><r id='k'/>",
        &policy,
    )
    .expect("the policy admits the declaration");
    assert!(super::new_document(&parsed).is_err());
}
