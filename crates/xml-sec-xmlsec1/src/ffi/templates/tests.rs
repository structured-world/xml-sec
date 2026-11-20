//! A template is built with the attributes asked for, or not at all.

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::{xmlSecTmplSignatureCreate, xmlSecTmplSignatureEnsureKeyInfo};
use crate::ffi::transforms::builtin::xmlSecTransformExclC14NGetKlass;
use crate::ffi::xmltree::xmlSecFindChild;

/// An attribute value the tree refuses: not UTF-8.
const REFUSED: &[u8] = b"\xff\0";

#[test]
fn a_refused_attribute_fails_the_template_call() {
    // The tree refuses an `Id` it cannot hold; the call fails instead of
    // returning an element without the attribute it was asked for, and an
    // element it created for the call is taken back.
    let xml = "<r/>";
    // SAFETY: the bytes and their length; every object is released here.
    unsafe {
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            i32::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null(), "the document parses");
        let method = xmlSecTransformExclC14NGetKlass();
        assert!(
            xmlSecTmplSignatureCreate(doc, method, method, REFUSED.as_ptr()).is_null(),
            "a Signature without the Id it was asked for"
        );
        let sign = xmlSecTmplSignatureCreate(doc, method, method, std::ptr::null());
        assert!(!sign.is_null(), "a template without an Id");
        assert!(
            xmlSecTmplSignatureEnsureKeyInfo(sign, REFUSED.as_ptr()).is_null(),
            "a KeyInfo without the Id it was asked for"
        );
        assert!(
            xmlSecFindChild(
                sign,
                super::name(&super::xmlSecNodeKeyInfo),
                super::name(&super::xmlSecDSigNs)
            )
            .is_null(),
            "the KeyInfo created for the call is taken back"
        );
        assert!(!xsDocGetRootElement(doc).is_null());
        super::xsFreeNode(sign);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_refused_transform_attribute_fails_and_takes_its_child_back() {
    // An InclusiveNamespaces whose PrefixList, or an XPath2 filter whose
    // Filter, the tree refuses is no part of the template: the call fails
    // and the transform keeps no child without the attribute it asked for.
    let xml = "<Transform/>";
    // SAFETY: the bytes and their length; every object is released here.
    unsafe {
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            i32::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null(), "the document parses");
        let transform = xsDocGetRootElement(doc);
        assert_eq!(
            super::xmlSecTmplTransformAddC14NInclNamespaces(transform, REFUSED.as_ptr()),
            -1
        );
        assert!(
            xmlSecFindChild(
                transform,
                super::name(&super::xmlSecNodeInclusiveNamespaces),
                super::name(&super::xmlSecNsExcC14N)
            )
            .is_null(),
            "no InclusiveNamespaces without its PrefixList"
        );
        assert_eq!(
            super::xmlSecTmplTransformAddXPath2(
                transform,
                REFUSED.as_ptr(),
                c"true()".as_ptr().cast(),
                std::ptr::null()
            ),
            -1
        );
        assert!(
            xmlSecFindChild(
                transform,
                super::name(&super::xmlSecNodeXPath),
                super::name(&super::xmlSecXPath2Ns)
            )
            .is_null(),
            "no XPath filter without its Filter"
        );
        xsFreeDoc(doc);
    }
}

#[test]
fn empty_oaep_params_write_an_empty_element() {
    // libxmlsec1 takes no buffer and no size as empty OAEP parameters and
    // writes an empty OAEPparams, which reads back as an empty label; a size
    // without a buffer is refused before any child is added.
    let xml = "<EncryptionMethod/>";
    // SAFETY: the bytes and their length; every object is released here.
    unsafe {
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            i32::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null(), "the document parses");
        let method = xsDocGetRootElement(doc);
        let params = || {
            xmlSecFindChild(
                method,
                super::name(&super::xmlSecNodeRsaOAEPparams),
                super::name(&super::xmlSecEncNs),
            )
        };
        assert_eq!(
            super::xmlSecTmplTransformAddRsaOaepParam(method, std::ptr::null(), 5),
            -1
        );
        assert!(params().is_null(), "no OAEPparams for a refused call");
        assert_eq!(
            super::xmlSecTmplTransformAddRsaOaepParam(method, std::ptr::null(), 0),
            0
        );
        let added = params();
        assert!(!added.is_null(), "an OAEPparams for empty parameters");
        assert!(super::nodes::first_child(added).is_null(), "it is empty");
        xsFreeDoc(doc);
    }
}
