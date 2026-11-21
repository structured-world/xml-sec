use super::*;

use xml_sec::provider::{CryptoProvider, KdfContext, KdfParameters, RUST_CRYPTO_PROVIDER};
use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use crate::ffi::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::crypto::{
    xmlSecCryptoAppDefaultKeysMngrAdoptKey, xmlSecCryptoAppDefaultKeysMngrInit,
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use crate::ffi::keys::xmlSecKeyReadMemory;
use crate::ffi::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use crate::ffi::library::{xmlSecInit, xmlSecShutdown};
use crate::ffi::symkeys;
use crate::ffi::tests::own_process;
use crate::ffi::xmlenc::{
    xmlSecEncCtxBinaryEncrypt, xmlSecEncCtxCreate, xmlSecEncCtxDecryptToBuffer, xmlSecEncCtxDestroy,
};

const MASTER: &[u8] = b"the master key";

/// An AES-256-GCM `EncryptedData` template whose key is derived by PBKDF2
/// from the master key `master`, with `extra` after the method; the element's
/// `Id` is `data`.
fn template(master: &str, extra: &str) -> String {
    format!(
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" \
         xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
         xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Id=\"data\">\
         <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>\
         <ds:KeyInfo><xenc11:DerivedKey>\
         <xenc11:KeyDerivationMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\">\
         <xenc11:PBKDF2-params><xenc11:Salt><xenc11:Specified>c2FsdA==</xenc11:Specified>\
         </xenc11:Salt><xenc11:IterationCount>2</xenc11:IterationCount>\
         <xenc11:KeyLength>32</xenc11:KeyLength>\
         <xenc11:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
         </xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>{extra}\
         <xenc11:DerivedKeyName>session</xenc11:DerivedKeyName>\
         <xenc11:MasterKeyName>{master}</xenc11:MasterKeyName>\
         </xenc11:DerivedKey></ds:KeyInfo>\
         <xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>"
    )
}

/// The key the template derives from [`MASTER`], computed by the provider
/// itself.
fn derived() -> Vec<u8> {
    RUST_CRYPTO_PROVIDER
        .derive_key(
            &KdfParameters {
                algorithm: "http://www.w3.org/2009/xmlenc11#pbkdf2",
                digest: Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
                salt: b"salt",
                info: KdfContext::Octets(&[]),
                iterations: 2,
                output_len: 32,
            },
            MASTER,
        )
        .expect("the provider derives")
}

/// A keys manager holding the PBKDF2 master key [`MASTER`] named `name`.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn manager_with_master(name: &std::ffi::CStr) -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract; the key is adopted by the manager.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(xmlSecCryptoAppDefaultKeysMngrInit(mngr.cast()), 0);
        let key = xmlSecKeyReadMemory(symkeys::pbkdf2(), MASTER.as_ptr(), MASTER.len());
        assert!(!key.is_null());
        assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
        assert_eq!(
            xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr.cast(), key.cast()),
            0
        );
        mngr
    }
}

/// The template filled by encrypting `plaintext` with the key the provider
/// derives, set on the context so no `KeyInfo` is read to find it.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn encrypted_with_derived(
    plaintext: &[u8],
    template: &str,
) -> *mut crate::ffi::tree::XmlDoc {
    // SAFETY: by the caller's contract; a document and context created
    // here, the document handed to the caller.
    unsafe {
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            c_int::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let key = derived();
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = xmlSecKeyReadMemory(symkeys::aes(), key.as_ptr(), key.len());
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(
                ctx,
                xsDocGetRootElement(doc),
                plaintext.as_ptr(),
                plaintext.len()
            ),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        doc.cast()
    }
}

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

/// What decrypting `doc` with a context over `mngr` yields, `None` when it
/// fails.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn decrypted(
    doc: *mut crate::ffi::tree::XmlDoc,
    mngr: *mut XmlSecKeysMngr,
    flags: std::ffi::c_uint,
) -> Option<Vec<u8>> {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        (*ctx).key_info_read_ctx.flags = flags;
        let result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc.cast()));
        let plaintext = (!result.is_null()).then(|| {
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec()
        });
        xmlSecEncCtxDestroy(ctx);
        plaintext
    }
}

#[test]
fn a_derived_key_decrypts_what_its_derivation_encrypted() {
    // The recipient derives from its master key, found by MasterKeyName,
    // the key the provider derives from the same parameters: the content
    // encrypted under that key decrypts. Writing the template's KeyInfo left
    // the DerivedKey as the template named it.
    with_library(|| {
        let plaintext = b"derived content";
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = encrypted_with_derived(plaintext, &template("master", ""));
            let mngr = manager_with_master(c"master");
            assert_eq!(decrypted(doc, mngr, 0).as_deref(), Some(&plaintext[..]));
            xmlSecKeysMngrDestroy(mngr);
            xsFreeDoc(doc.cast());
        }
    });
}

#[test]
fn a_derived_key_needs_its_master_key() {
    // A master key named otherwise is not the one the DerivedKey names: the
    // derivation finds no key and the decryption fails, as libxmlsec1's
    // does, unless the context stops on that failure, which fails the read
    // itself.
    with_library(|| {
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = encrypted_with_derived(b"content", &template("master", ""));
            let mngr = manager_with_master(c"another");
            assert_eq!(decrypted(doc, mngr, 0), None);
            assert_eq!(
                decrypted(doc, mngr, FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION),
                None
            );
            xmlSecKeysMngrDestroy(mngr);
            xsFreeDoc(doc.cast());
        }
    });
}

#[test]
fn a_reference_list_names_the_data_the_derived_key_serves() {
    // The ReferenceList lists the data encrypted under the derived key (XML
    // Encryption 1.1 section 3.5.2): a list naming this EncryptedData
    // decrypts it, one naming other data does not. Departure: libxmlsec1
    // reads past the list and decrypts either.
    with_library(|| {
        let plaintext = b"listed";
        let list = |uri: &str| {
            format!("<xenc:ReferenceList><xenc:DataReference URI=\"{uri}\"/></xenc:ReferenceList>")
        };
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let mngr = manager_with_master(c"master");
            for (uri, expected) in [("#data", Some(&plaintext[..])), ("#other", None)] {
                let doc = encrypted_with_derived(plaintext, &template("master", &list(uri)));
                assert_eq!(decrypted(doc, mngr, 0).as_deref(), expected, "{uri}");
                xsFreeDoc(doc.cast());
            }
            xmlSecKeysMngrDestroy(mngr);
        }
    });
}

#[test]
fn a_derived_key_serves_only_the_data_its_list_names() {
    // The read derives the key of the first DerivedKey, whose list names
    // other data; the second names this EncryptedData but its master key is
    // absent. The first key decrypts nothing outside its list, whichever
    // DerivedKey of the KeyInfo the decryption asks for its key.
    with_library(|| {
        let second = "<xenc11:DerivedKey>\
             <xenc11:KeyDerivationMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\">\
             <xenc11:PBKDF2-params><xenc11:Salt><xenc11:Specified>c2FsdA==</xenc11:Specified>\
             </xenc11:Salt><xenc11:IterationCount>2</xenc11:IterationCount>\
             <xenc11:KeyLength>32</xenc11:KeyLength>\
             <xenc11:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
             </xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>\
             <xenc:ReferenceList><xenc:DataReference URI=\"#data\"/></xenc:ReferenceList>\
             <xenc11:MasterKeyName>absent</xenc11:MasterKeyName></xenc11:DerivedKey>";
        let xml = template(
            "master",
            "<xenc:ReferenceList><xenc:DataReference URI=\"#other\"/></xenc:ReferenceList>",
        )
        .replace("</ds:KeyInfo>", &format!("{second}</ds:KeyInfo>"));
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = encrypted_with_derived(b"listed elsewhere", &xml);
            let mngr = manager_with_master(c"master");
            assert_eq!(decrypted(doc, mngr, 0), None);
            xmlSecKeysMngrDestroy(mngr);
            xsFreeDoc(doc.cast());
        }
    });
}

#[test]
fn a_key_not_derived_does_not_stand_for_a_derivation() {
    // A key the caller set on the context is no key a DerivedKey derived:
    // the KeyInfo is not read, so no derivation runs under the policy, and
    // the EncryptedData whose key is derived does not decrypt with it.
    with_library(|| {
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = encrypted_with_derived(b"content", &template("master", ""));
            let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
            let key = derived();
            (*ctx).enc_key = xmlSecKeyReadMemory(symkeys::aes(), key.as_ptr(), key.len());
            assert!(xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc.cast())).is_null());
            xmlSecEncCtxDestroy(ctx);
            xsFreeDoc(doc.cast());
        }
    });
}

#[test]
fn a_generation_derives_under_the_policy_of_its_operation() {
    // A generation on a fresh context reads its method before the chain
    // holds it: the derivation still runs under the policy of the operation
    // the KeyInfo context names, a decryption admitting no derivation here.
    with_library(|| {
        let mut pinned = crate::ffi::policy::Pinned::current(here!("test"))
            .expect("the library policy compiles");
        std::sync::Arc::make_mut(&mut pinned.decryption)
            .key_establishment
            .derivation_algorithms = Some(std::collections::BTreeSet::new());
        let named = generated_name(&template("master", ""), c"master", |enc| {
            // SAFETY: the generating context's own transform context.
            unsafe { crate::ffi::transforms::ctx::pin_run(&raw mut (*enc).transform_ctx, &pinned) };
        });
        assert_eq!(named, Generated::Nothing);
    });
}

#[test]
fn a_derivation_reads_the_derived_key_element_strictly() {
    // libxmlsec1 requires the KeyDerivationMethod first and refuses any
    // child after MasterKeyName: such a DerivedKey derives no key.
    with_library(|| {
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let mngr = manager_with_master(c"master");
            for xml in [
                template("master", "").replace(
                    "<xenc11:MasterKeyName>master</xenc11:MasterKeyName>",
                    "<xenc11:MasterKeyName>master</xenc11:MasterKeyName><xenc11:Extra/>",
                ),
                template("master", "").replace("xenc11:KeyDerivationMethod", "xenc11:Method"),
            ] {
                let doc = encrypted_with_derived(b"content", &xml);
                assert_eq!(decrypted(doc, mngr, 0), None, "{xml}");
                xsFreeDoc(doc.cast());
            }
            xmlSecKeysMngrDestroy(mngr);
        }
    });
}

/// What a direct generation yields.
#[derive(Debug, PartialEq, Eq)]
enum Generated {
    /// No key.
    Nothing,
    /// A key without a name.
    Unnamed,
    /// A key with this name.
    Named(Vec<u8>),
}

/// What a direct generation derives from the `DerivedKey` of `xml` for a
/// decrypting `KeyInfo` context, with the master key stored under `master`;
/// `prepare` adjusts the fresh generating context first. Runs within
/// [`with_library`].
fn generated_name(
    xml: &str,
    master: &std::ffi::CStr,
    prepare: impl FnOnce(*mut XmlSecEncCtx),
) -> Generated {
    // SAFETY: a document, keys manager and contexts created and released
    // here.
    unsafe {
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            c_int::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        let mngr = manager_with_master(master);
        let ctx = xmlSecEncCtxCreate(mngr);
        let key_info = &raw mut (*ctx).key_info_read_ctx;
        (*key_info).operation = crate::ffi::transforms::OPERATION_DECRYPT;
        (*key_info).key_req.key_id = symkeys::aes();
        (*key_info).key_req.key_bits_size = 256;
        assert_eq!(xmlSecKeyInfoCtxCreateEncCtx(key_info), 0);
        let enc = (*key_info).enc_ctx.cast::<XmlSecEncCtx>();
        prepare(enc);
        let node = crate::ffi::xmltree::xmlSecFindNode(
            xsDocGetRootElement(doc).cast(),
            strings::xmlSecNodeDerivedKey.as_ptr(),
            strings::xmlSecEnc11Ns.as_ptr(),
        );
        let key = xmlSecEncCtxDerivedKeyGenerate(enc, symkeys::aes(), node, key_info);
        let name = if key.is_null() {
            Generated::Nothing
        } else if (*key).name.is_null() {
            Generated::Unnamed
        } else {
            Generated::Named(
                std::ffi::CStr::from_ptr((*key).name.cast())
                    .to_bytes()
                    .to_vec(),
            )
        };
        if !key.is_null() {
            xmlSecKeyDestroy(key);
        }
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        name
    }
}

#[test]
fn the_derived_key_is_named_by_its_derived_key_name() {
    // The derived key carries the DerivedKeyName, as libxmlsec1 names it.
    with_library(|| {
        assert_eq!(
            generated_name(&template("master", ""), c"master", |_| {}),
            Generated::Named(b"session".to_vec())
        );
    });
}

#[test]
fn derived_key_names_keep_their_white_space_unless_the_policy_trims_it() {
    // XML Encryption 1.1 section 3.5.2: white space is significant in
    // DerivedKeyName, and MasterKeyName is read the same way, so padded names
    // find the master key stored under them and name the derived key as
    // written. libxmlsec1 trims both, which KeyNameSemantics::Libxmlsec1
    // selects.
    with_library(|| {
        let xml = template(" master ", "").replace(
            "<xenc11:DerivedKeyName>session</xenc11:DerivedKeyName>",
            "<xenc11:DerivedKeyName> session </xenc11:DerivedKeyName>",
        );
        assert_eq!(generated_name(&xml, c"master", |_| {}), Generated::Nothing);
        assert_eq!(
            generated_name(&xml, c" master ", |_| {}),
            Generated::Named(b" session ".to_vec())
        );
        let mut pinned = crate::ffi::policy::Pinned::current(here!("test"))
            .expect("the library policy compiles");
        std::sync::Arc::make_mut(&mut pinned.decryption)
            .xml
            .key_names = xml_sec::policy::KeyNameSemantics::Libxmlsec1;
        let trimmed = generated_name(&xml, c"master", |enc| {
            // SAFETY: the generating context's own transform context.
            unsafe { crate::ffi::transforms::ctx::pin_run(&raw mut (*enc).transform_ctx, &pinned) };
        });
        assert_eq!(trimmed, Generated::Named(b"session".to_vec()));
        // The decryption takes the key derived for the padded names: the core
        // reads the DerivedKey with the same names.
        let plaintext = b"padded names";
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = encrypted_with_derived(plaintext, &xml);
            let mngr = manager_with_master(c" master ");
            assert_eq!(decrypted(doc, mngr, 0).as_deref(), Some(&plaintext[..]));
            xmlSecKeysMngrDestroy(mngr);
            xsFreeDoc(doc.cast());
        }
    });
}

#[test]
fn a_generation_checks_libxmlsec1s_preconditions() {
    // A context that has read a method already, or a missing argument, is
    // refused before anything is read.
    // SAFETY: null arguments only.
    unsafe {
        assert!(
            xmlSecEncCtxDerivedKeyGenerate(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            )
            .is_null()
        );
    }
}
