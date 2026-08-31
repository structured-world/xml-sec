//! Private lexical XML event adapter.
//!
//! The XSLT semantic arena owns names, namespaces, identity, and tree rules.
//! Keeping the tokenizer behind this module prevents its types and encoding
//! assumptions from becoming part of that contract.

pub(crate) use quick_xml::events::{BytesStart, Event};
pub(crate) use quick_xml::{Reader, XmlVersion};
