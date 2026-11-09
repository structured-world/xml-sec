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
    xs_evidence_destroy, xs_evidence_signature, xs_keys_add_private_pem, xs_keys_add_public_pem,
    xs_keys_destroy, xs_keys_new, xs_policy_destroy, xs_policy_store_destroy, xs_policy_store_load,
    xs_policy_store_new, xs_provider_destroy, xs_provider_new_rustcrypto, xs_sign,
    xs_signer_destroy, xs_signer_new, xs_verifier_destroy, xs_verifier_new, xs_verify,
};
use xml_sec_capi::status::{XS_DOCUMENT, XS_INVALID_ARGUMENT, XS_OK, XsStatus};

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
    assert_eq!(xs_evidence_destroy(evidence), XS_OK);
    assert_eq!(xs_verifier_destroy(verifier), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    outcome.outcome == 1
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

/// Encrypt the element with ID `s` of `doc` for the RSA test key.
fn encrypt(policy: &Policy, doc: &Libxml) {
    let (mut keys, mut encryptor) = (XsKeys::default(), XsEncryptor::default());
    let document = handle(policy, 3, doc);
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
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_encryptor_destroy(encryptor), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
}

/// Decrypt the one `EncryptedData` of `doc` with the RSA test key.
fn decrypt(policy: &Policy, doc: &Libxml) {
    let (mut keys, mut decryptor) = (XsKeys::default(), XsDecryptor::default());
    let document = handle(policy, 4, doc);
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
    assert_eq!(xs_document_destroy(document), XS_OK);
    assert_eq!(xs_decryptor_destroy(decryptor), XS_OK);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
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
    assert!(
        encrypted.contains("EncryptedData") && !encrypted.contains("42"),
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

/// Whether `document`'s signature verifies with the certificate it carries;
/// trust is not under test.
fn carried_key_verifies(
    document: &xml_sec::XmlDocument,
    mut policy: xml_sec::policy::VerificationPolicy,
) -> bool {
    policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    let resolver = xml_sec::xmldsig::DefaultKeyResolver::default();
    xml_sec::xmldsig::VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify_document(document)
        .expect("verification runs")
        .status
        == xml_sec::xmldsig::DsigStatus::Valid
}

#[test]
fn dtd_ids_and_kept_entity_references_are_read_from_the_tree() {
    // Parsed without entity substitution, libxml2 keeps the reference node
    // and types `ident` as an ID from the DTD: the projection reads the
    // entity's replacement (XML 1.0 section 4.4.2) and resolves `#payload`
    // through that ID, so the signature made on this tree verifies on a
    // substituted parse as well.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::policy::{SigningPolicy, VerificationPolicy, XmlInputPolicy};
    use xml_sec::xmldsig::{
        DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
        SignatureBuilder, Transform, X509CertificateKeyInfoWriter,
    };
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
        .policy(signing)
        .key_info_writer(&certificate)
        .sign_document_with_builder(&mut document, &builder)
        .expect("the tree signs");
    drop(document);
    let dumped = kept.dump();
    assert!(
        dumped.contains("&greeting;"),
        "the reference stays: {dumped}"
    );
    assert!(carried_key_verifies(
        &tree_document(&kept, &verification),
        verification.clone()
    ));
    let substituted = Libxml::parse(&dumped, SUBSTITUTE_ENTITIES);
    assert!(carried_key_verifies(
        &tree_document(&substituted, &verification),
        verification
    ));
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
