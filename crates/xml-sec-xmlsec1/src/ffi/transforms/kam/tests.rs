use std::collections::BTreeSet;

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::super::super::app::key_load_memory;
use super::super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::super::crypto::{
    xmlSecCryptoAppDefaultKeysMngrAdoptKey, xmlSecCryptoAppDefaultKeysMngrInit,
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use super::super::super::keys::{xmlSecKeyGenerate, xmlSecKeySetName};
use super::super::super::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use super::super::super::library::{xmlSecInit, xmlSecShutdown};
use super::super::super::symkeys;
use super::super::super::tests::own_process;
use super::super::super::tree::XmlDoc;
use super::super::super::xmlenc::{
    xmlSecEncCtxBinaryEncrypt, xmlSecEncCtxCreate, xmlSecEncCtxDecryptToBuffer, xmlSecEncCtxDestroy,
};
use super::*;

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;
/// `xmlSecKeyDataTypeSession`.
const TYPE_SESSION: c_uint = 0x0008;

const ORIGINATOR_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-key.pem");
const ORIGINATOR_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-pubkey.pem");
const RECIPIENT_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-second-key.pem");
const RECIPIENT_PUBLIC: &[u8] = include_bytes!(
    "../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-second-pubkey.pem"
);
const RSA_KEY: &[u8] = include_bytes!("../../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
/// The donor's ECDH-ES template: an AES-128-GCM `EncryptedData` whose key an
/// `EncryptedKey` wraps with AES-256 KW under a key the `AgreementMethod`
/// agrees on by `ConcatKDF` over SHA-256, the parties named by `KeyName`.
const TEMPLATE: &str = include_str!(
    "../../../../../../tests/fixtures/xmlenc/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm.tmpl"
);

/// Initializes the library and its crypto, runs `test` and shuts both down.
fn with_library(test: impl FnOnce()) {
    own_process();
    // SAFETY: the library initialized and shut down on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
    }
    test();
    // SAFETY: every object of the test is released.
    unsafe {
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The PEM key `pem`, loaded.
fn pem_key(pem: &[u8]) -> *mut XmlSecKey {
    // SAFETY: the fixture's bytes; no password is needed.
    let key = unsafe {
        key_load_memory(
            pem.as_ptr(),
            pem.len(),
            FORMAT_PEM,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(!key.is_null(), "the fixture loads");
    key.cast()
}

/// A keys manager holding each PEM key under its name.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn manager(keys: &[(&[u8], &CStr)]) -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract; each key is adopted by the manager.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(xmlSecCryptoAppDefaultKeysMngrInit(mngr.cast()), 0);
        for (pem, name) in keys {
            let key = pem_key(pem);
            assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
            assert_eq!(
                xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr.cast(), key.cast()),
                0
            );
        }
        mngr
    }
}

/// The originator's side: its private key and the recipient's public key.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn originator() -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract.
    unsafe {
        manager(&[
            (ORIGINATOR_KEY, c"originator-key-name"),
            (RECIPIENT_PUBLIC, c"recipient-key-name"),
        ])
    }
}

/// `template` read as a document.
fn document(template: &str) -> *mut XmlDoc {
    // SAFETY: the template's bytes.
    let doc = unsafe {
        xsReadMemory(
            template.as_ptr().cast(),
            c_int::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!doc.is_null(), "the template parses");
    doc.cast()
}

/// Encrypts `plaintext` into `doc` with a fresh AES-128 session key, the
/// agreement run by the side `mngr` holds; whether it succeeded.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn encrypt(doc: *mut XmlDoc, mngr: *mut XmlSecKeysMngr, plaintext: &[u8]) -> bool {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
        (*ctx).key_info_write_ctx.max_encrypted_key_level = 3;
        (*ctx).enc_key = xmlSecKeyGenerate(symkeys::aes(), 128, TYPE_SESSION);
        let done = xmlSecEncCtxBinaryEncrypt(
            ctx,
            xsDocGetRootElement(doc.cast()),
            plaintext.as_ptr(),
            plaintext.len(),
        ) == 0;
        xmlSecEncCtxDestroy(ctx);
        done
    }
}

/// What decrypting `doc` with a context over `mngr` yields, `None` when it
/// fails.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn decrypted(doc: *mut XmlDoc, mngr: *mut XmlSecKeysMngr) -> Option<Vec<u8>> {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
        let result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc.cast()));
        let plaintext = (!result.is_null()).then(|| {
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec()
        });
        xmlSecEncCtxDestroy(ctx);
        plaintext
    }
}

/// Encrypts with [`originator`] into `template`, then decrypts with the
/// recipient side `keys` holds: the plaintext, `None` when the decryption
/// fails. The encryption must succeed.
fn round_trip(template: &str, keys: &[(&[u8], &CStr)]) -> Option<Vec<u8>> {
    let plaintext = b"agreed content";
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(template);
        let sender = originator();
        assert!(encrypt(doc, sender, plaintext), "the originator encrypts");
        let recipient = manager(keys);
        let result = decrypted(doc, recipient);
        xmlSecKeysMngrDestroy(recipient);
        xmlSecKeysMngrDestroy(sender);
        xsFreeDoc(doc.cast());
        result
    }
}

/// Whether the originator side ([`originator`]) encrypts into `template`.
fn encrypts(template: &str) -> bool {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(template);
        let sender = originator();
        let sent = encrypt(doc, sender, b"content");
        xmlSecKeysMngrDestroy(sender);
        xsFreeDoc(doc.cast());
        sent
    }
}

/// The recipient's side: its private key and the originator's public key.
const RECIPIENT: [(&[u8], &CStr); 2] = [
    (RECIPIENT_KEY, c"recipient-key-name"),
    (ORIGINATOR_PUBLIC, c"originator-key-name"),
];

#[test]
fn both_parties_agree_on_the_key_encryption_key() {
    // The originator agrees with its private key and the recipient's public
    // key, the recipient with its private key and the originator's public
    // key: ECDH-ES gives both the same secret (XML Encryption 1.1 section
    // 5.6.4), so the session key the originator wrapped unwraps.
    with_library(|| {
        assert_eq!(
            round_trip(TEMPLATE, &RECIPIENT).as_deref(),
            Some(&b"agreed content"[..])
        );
    });
}

#[test]
fn a_recipient_without_the_originators_key_agrees_on_nothing() {
    // The recipient's keys manager knows no originator key: the agreement
    // finds no peer and the decryption fails rather than using some other
    // key for the role.
    with_library(|| {
        assert_eq!(
            round_trip(TEMPLATE, &[(RECIPIENT_KEY, c"recipient-key-name")]),
            None
        );
    });
}

#[test]
fn another_originator_key_yields_a_key_that_does_not_unwrap() {
    // The recipient holds a different public key under the originator's
    // name: the agreement succeeds on another secret, whose KEK fails the
    // key wrap's integrity check, so nothing decrypts.
    with_library(|| {
        assert_eq!(
            round_trip(
                TEMPLATE,
                &[
                    (RECIPIENT_KEY, c"recipient-key-name"),
                    (RECIPIENT_PUBLIC, c"originator-key-name"),
                ],
            ),
            None
        );
    });
}

#[test]
fn a_key_of_another_family_is_no_party() {
    // An RSA key under the originator's name is not an EC key: the role's
    // requirements, the agreement's key-data klass, refuse it.
    with_library(|| {
        assert_eq!(
            round_trip(
                TEMPLATE,
                &[
                    (RECIPIENT_KEY, c"recipient-key-name"),
                    (RSA_KEY, c"originator-key-name"),
                ],
            ),
            None
        );
    });
}

#[test]
fn an_agreement_names_both_parties_in_order() {
    // libxmlsec1 requires OriginatorKeyInfo then RecipientKeyInfo and nothing
    // after them, though the schema lets both be omitted: a template without
    // the recipient's role, with the roles swapped, or with an element after
    // them agrees on nothing, while the template as it is does.
    with_library(|| {
        assert!(encrypts(TEMPLATE));
        let start = TEMPLATE.find("<xenc:RecipientKeyInfo").expect("the role");
        let end = TEMPLATE.find("</xenc:RecipientKeyInfo>").expect("the role")
            + "</xenc:RecipientKeyInfo>".len();
        let recipient_role = &TEMPLATE[start..end];
        let without = format!("{}{}", &TEMPLATE[..start], &TEMPLATE[end..]);
        assert!(!encrypts(&without));
        let swapped = without.replace(
            "<xenc:OriginatorKeyInfo",
            &format!("{recipient_role}<xenc:OriginatorKeyInfo"),
        );
        assert!(!encrypts(&swapped));
        let trailing = TEMPLATE.replace(
            "</xenc:AgreementMethod>",
            "<extra xmlns=\"urn:extra\"/></xenc:AgreementMethod>",
        );
        assert!(!encrypts(&trailing));
    });
}

#[test]
fn an_agreement_needs_a_known_derivation() {
    // The KeyDerivationMethod names an algorithm no klass implements: the
    // registry refuses it before any key is looked up.
    with_library(|| {
        let unknown = TEMPLATE.replace(
            "http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "urn:unknown:kdf",
        );
        assert!(!encrypts(&unknown));
    });
}

#[test]
fn the_policy_decides_whether_the_parties_may_agree() {
    // The agreement runs under the operation's key establishment policy: one
    // admitting no agreement refuses it before any provider work, one
    // admitting ECDH-ES derives the key, and either way the attempt is
    // charged to the operation's allowance.
    with_library(|| {
        let mine = pem_key(RECIPIENT_KEY);
        let peer = pem_key(ORIGINATOR_PUBLIC);
        let method_xml = "<xenc11:KeyDerivationMethod \
             xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
             xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" \
             Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\
             <xenc11:ConcatKDFParams AlgorithmID=\"00\" PartyUInfo=\"00\" PartyVInfo=\"00\">\
             <dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>";
        let method = xml_sec::xmlenc::parse_key_derivation_method(
            method_xml,
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .expect("the method parses");
        // SAFETY: the keys loaded above, released below.
        unsafe {
            let mine_material = material_of(xmlSecKeyGetValue(mine)).expect("an EC key");
            let peer_material = material_of(xmlSecKeyGetValue(peer)).expect("an EC key");
            let refusing = xml_sec::policy::KeyEstablishmentPolicy {
                agreement_algorithms: Some(BTreeSet::new()),
                ..xml_sec::policy::KeyEstablishmentPolicy::default()
            };
            let mut usage = xml_sec::key_establishment::KeyEstablishmentUsage::default();
            let refused = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                mine_material,
                peer_material,
                &refusing,
                &mut usage,
            );
            assert!(
                matches!(refused, Err(XmlEncError::Policy(_))),
                "{refused:?}"
            );
            let admitting = xml_sec::policy::KeyEstablishmentPolicy::default();
            let derived = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                mine_material,
                peer_material,
                &admitting,
                &mut usage,
            )
            .expect("ECDH-ES is admitted by default");
            assert_eq!(derived.len(), 32);
            let charged = KeyEstablishmentBudget::resume(&admitting, usage).expect("valid");
            assert!(charged.hash_blocks() > 0, "the derivation was charged");
            // The public key alone holds no private key to agree with.
            let public_only = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                peer_material,
                mine_material,
                &admitting,
                &mut usage,
            );
            assert!(matches!(public_only, Err(XmlEncError::KeyNotFound)));
            xmlSecKeyDestroy(mine);
            xmlSecKeyDestroy(peer);
        }
    });
}

#[test]
fn a_concat_kdf_defaults_to_its_digest_width() {
    // A reader that expects no width gets the ConcatKDF digest's output, as
    // libxmlsec1 falls back to it; any other derivation has no default.
    let parse = |xml: &str| {
        xml_sec::xmlenc::parse_key_derivation_method(
            xml,
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .expect("the method parses")
    };
    let concat = parse(
        "<xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
         xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" \
         Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\
         <xenc11:ConcatKDFParams AlgorithmID=\"00\" PartyUInfo=\"00\" PartyVInfo=\"00\">\
         <dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"/>\
         </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>",
    );
    assert_eq!(default_width(&concat), 48);
    let hkdf = parse(
        "<xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
         Algorithm=\"http://www.w3.org/2021/04/xmldsig-more#hkdf\">\
         <m:HKDFParams xmlns:m=\"http://www.w3.org/2021/04/xmldsig-more#\">\
         <m:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
         <m:KeyLength>32</m:KeyLength></m:HKDFParams></xenc11:KeyDerivationMethod>",
    );
    assert_eq!(default_width(&hkdf), 0);
}
