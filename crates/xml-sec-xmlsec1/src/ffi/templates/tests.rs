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
