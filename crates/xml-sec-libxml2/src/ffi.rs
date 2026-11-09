//! The libxml2 boundary: the crate's only `unsafe` code.
//!
//! [`LibxmlTree`] implements the core's external-tree contract over a
//! caller's `xmlDoc`: it walks the tree into the core's projection, builds
//! the nodes of validated fragments with libxml2's own constructors, links
//! and unlinks nodes by their pointers, and keeps what it needs to undo its
//! edits until the core releases them. `SAFETY.md` records the invariants
//! every `unsafe` block below relies on.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

use xml_sec::document::external::{
    ExternalNode, ExternalTree, Fragment, FragmentEvent, TreeEdit, TreeEditError, TreeSink,
};
use xml_sec::{ParseError, XmlDocument};
use xml_sec_capi::ffi::{XsDocument, XsError, XsPolicy};
use xml_sec_capi::status::{XS_INTERNAL, XS_INVALID_ARGUMENT, XsStatus};

#[cfg(test)]
mod tests;

type XmlChar = u8;

// The declarations are public so that crates over the bridge read trees
// through the one set of declarations `layout_matches` verifies.

/// `xmlNs`: a namespace declaration.
#[repr(C)]
pub struct XmlNs {
    pub next: *mut XmlNs,
    pub kind: c_int,
    pub href: *const XmlChar,
    pub prefix: *const XmlChar,
}

/// `xmlAttr`, up to the last member the bridge reads.
#[repr(C)]
pub struct XmlAttr {
    pub private: *mut c_void,
    pub kind: c_int,
    pub name: *const XmlChar,
    pub children: *mut XmlNode,
    pub last: *mut XmlNode,
    pub parent: *mut XmlNode,
    pub next: *mut XmlAttr,
    pub prev: *mut XmlAttr,
    pub doc: *mut XmlDoc,
    pub ns: *mut XmlNs,
    pub atype: c_int,
}

/// `xmlNode`, up to the last member the bridge reads.
#[repr(C)]
pub struct XmlNode {
    pub private: *mut c_void,
    pub kind: c_int,
    pub name: *const XmlChar,
    pub children: *mut XmlNode,
    pub last: *mut XmlNode,
    pub parent: *mut XmlNode,
    pub next: *mut XmlNode,
    pub prev: *mut XmlNode,
    pub doc: *mut XmlDoc,
    pub ns: *mut XmlNs,
    pub content: *mut XmlChar,
    pub properties: *mut XmlAttr,
    pub ns_def: *mut XmlNs,
}

/// `xmlEntity`, the declaration an entity reference's `children` points to,
/// up to the last member the bridge reads.
#[repr(C)]
pub struct XmlEntity {
    private: *mut c_void,
    kind: c_int,
    name: *const XmlChar,
    children: *mut XmlNode,
    last: *mut XmlNode,
    parent: *mut c_void,
    next: *mut XmlNode,
    prev: *mut XmlNode,
    doc: *mut XmlDoc,
    orig: *mut XmlChar,
    content: *mut XmlChar,
    length: c_int,
    etype: c_int,
}

/// `xmlDoc`, up to the last member the bridge reads. Its first members are
/// the common part every libxml2 node shares, so the document is the parent
/// of its top-level nodes like any element.
#[repr(C)]
pub struct XmlDoc {
    pub private: *mut c_void,
    pub kind: c_int,
    pub name: *mut c_char,
    pub children: *mut XmlNode,
    pub last: *mut XmlNode,
    pub parent: *mut XmlNode,
    pub next: *mut XmlNode,
    pub prev: *mut XmlNode,
    pub doc: *mut XmlDoc,
    pub compression: c_int,
    pub standalone: c_int,
    pub int_subset: *mut c_void,
    pub ext_subset: *mut c_void,
    pub old_ns: *mut XmlNs,
    pub version: *const XmlChar,
    pub encoding: *const XmlChar,
}

/// `xmlNodeSet`: an `XPath` node set. Namespace members are `xmlNs` copies
/// whose `next` names the element they belong to.
#[repr(C)]
pub struct XmlNodeSet {
    pub node_nr: c_int,
    pub node_max: c_int,
    pub node_tab: *mut *mut XmlNode,
}

/// `XML_ELEMENT_NODE`.
pub const XML_ELEMENT_NODE: c_int = 1;
/// `XML_ATTRIBUTE_NODE`.
pub const XML_ATTRIBUTE_NODE: c_int = 2;
/// `XML_TEXT_NODE`.
pub const XML_TEXT_NODE: c_int = 3;
/// `XML_CDATA_SECTION_NODE`.
pub const XML_CDATA_SECTION_NODE: c_int = 4;
/// `XML_ENTITY_REF_NODE`.
pub const XML_ENTITY_REF_NODE: c_int = 5;
/// `XML_PI_NODE`.
pub const XML_PI_NODE: c_int = 7;
/// `XML_COMMENT_NODE`.
pub const XML_COMMENT_NODE: c_int = 8;
/// `XML_DOCUMENT_NODE`.
pub const XML_DOCUMENT_NODE: c_int = 9;
/// `XML_DTD_NODE`.
pub const XML_DTD_NODE: c_int = 14;
/// `XML_NAMESPACE_DECL`: a namespace node of an `XPath` node set.
pub const XML_NAMESPACE_DECL: c_int = 18;
/// `XML_XINCLUDE_START`.
pub const XML_XINCLUDE_START: c_int = 19;
/// `XML_XINCLUDE_END`.
pub const XML_XINCLUDE_END: c_int = 20;
const XML_ATTRIBUTE_ID: c_int = 2;
const XML_INTERNAL_PREDEFINED_ENTITY: c_int = 6;

unsafe extern "C" {
    static xs_libxml2_layout: [usize; 0];
    static xs_libxml2_layout_len: usize;

    fn xmlNewDocNode(
        doc: *mut XmlDoc,
        ns: *mut XmlNs,
        name: *const XmlChar,
        content: *const XmlChar,
    ) -> *mut XmlNode;
    fn xmlNewNs(node: *mut XmlNode, href: *const XmlChar, prefix: *const XmlChar) -> *mut XmlNs;
    fn xmlNewNsProp(
        node: *mut XmlNode,
        ns: *mut XmlNs,
        name: *const XmlChar,
        value: *const XmlChar,
    ) -> *mut XmlAttr;
    fn xmlNewDocText(doc: *const XmlDoc, content: *const XmlChar) -> *mut XmlNode;
    fn xmlNewDocComment(doc: *mut XmlDoc, content: *const XmlChar) -> *mut XmlNode;
    fn xmlNewDocPI(doc: *mut XmlDoc, name: *const XmlChar, content: *const XmlChar)
    -> *mut XmlNode;
    fn xmlSearchNs(doc: *mut XmlDoc, node: *mut XmlNode, prefix: *const XmlChar) -> *mut XmlNs;
    fn xmlUnlinkNode(node: *mut XmlNode);
    fn xmlFreeNode(node: *mut XmlNode);
    fn xmlNewDoc(version: *const XmlChar) -> *mut XmlDoc;
    fn xmlFreeDoc(doc: *mut XmlDoc);
    fn xmlStrdup(text: *const XmlChar) -> *mut XmlChar;
    fn xmlIsID(doc: *mut XmlDoc, element: *mut XmlNode, attribute: *mut XmlAttr) -> c_int;
    fn xmlAddID(
        context: *mut c_void,
        doc: *mut XmlDoc,
        value: *const XmlChar,
        attribute: *mut XmlAttr,
    ) -> *mut c_void;
}

/// The layout record this crate's declarations stand for, in the order of
/// `layout.c`.
fn expected_layout() -> [usize; 52] {
    use std::mem::{offset_of, size_of};
    [
        offset_of!(XmlNode, kind),
        offset_of!(XmlNode, name),
        offset_of!(XmlNode, children),
        offset_of!(XmlNode, last),
        offset_of!(XmlNode, parent),
        offset_of!(XmlNode, next),
        offset_of!(XmlNode, prev),
        offset_of!(XmlNode, doc),
        offset_of!(XmlNode, ns),
        offset_of!(XmlNode, content),
        offset_of!(XmlNode, properties),
        offset_of!(XmlNode, ns_def),
        offset_of!(XmlAttr, kind),
        offset_of!(XmlAttr, name),
        offset_of!(XmlAttr, children),
        offset_of!(XmlAttr, parent),
        offset_of!(XmlAttr, next),
        offset_of!(XmlAttr, ns),
        offset_of!(XmlAttr, atype),
        offset_of!(XmlNs, next),
        offset_of!(XmlNs, kind),
        offset_of!(XmlNs, href),
        offset_of!(XmlNs, prefix),
        offset_of!(XmlDoc, kind),
        offset_of!(XmlDoc, children),
        offset_of!(XmlDoc, last),
        offset_of!(XmlDoc, int_subset),
        offset_of!(XmlDoc, standalone),
        offset_of!(XmlDoc, version),
        offset_of!(XmlDoc, encoding),
        offset_of!(XmlEntity, children),
        offset_of!(XmlEntity, content),
        offset_of!(XmlEntity, length),
        offset_of!(XmlEntity, etype),
        size_of::<c_int>(),
        XML_ELEMENT_NODE as usize,
        XML_TEXT_NODE as usize,
        XML_CDATA_SECTION_NODE as usize,
        XML_ENTITY_REF_NODE as usize,
        XML_PI_NODE as usize,
        XML_COMMENT_NODE as usize,
        XML_DOCUMENT_NODE as usize,
        XML_DTD_NODE as usize,
        XML_XINCLUDE_START as usize,
        XML_XINCLUDE_END as usize,
        XML_ATTRIBUTE_ID as usize,
        XML_INTERNAL_PREDEFINED_ENTITY as usize,
        XML_ATTRIBUTE_NODE as usize,
        XML_NAMESPACE_DECL as usize,
        offset_of!(XmlNodeSet, node_nr),
        offset_of!(XmlNodeSet, node_max),
        offset_of!(XmlNodeSet, node_tab),
    ]
}

/// The layout record of the linked headers.
fn linked_layout() -> &'static [usize] {
    // SAFETY: `layout.c` defines `xs_libxml2_layout` as an array of
    // `xs_libxml2_layout_len` initialized `size_t` values with static
    // storage, and `size_t` is `usize` on every target Rust supports.
    unsafe {
        std::slice::from_raw_parts(
            (&raw const xs_libxml2_layout).cast::<usize>(),
            xs_libxml2_layout_len,
        )
    }
}

/// Whether the linked libxml2 lays its structures out as declared here;
/// computed once, and every entry point, here and in crates reading trees
/// through these declarations, refuses to touch a tree otherwise.
#[must_use]
pub fn layout_matches() -> bool {
    static MATCHES: OnceLock<bool> = OnceLock::new();
    *MATCHES.get_or_init(|| linked_layout() == expected_layout())
}

fn backend_error(message: &str) -> ParseError {
    ParseError::Backend {
        backend: "libxml2",
        message: message.into(),
    }
}

fn edit_error(message: &str) -> TreeEditError {
    TreeEditError(message.into())
}

fn reference(node: *mut XmlNode) -> ExternalNode {
    ExternalNode(node.expose_provenance() as u64)
}

fn node_of(node: ExternalNode) -> *mut XmlNode {
    // The value came from `reference` of a node of this tree.
    std::ptr::with_exposed_provenance_mut(usize::try_from(node.0).unwrap_or(0))
}

/// A NUL-terminated libxml2 string as UTF-8, or `None` for null.
///
/// # Safety
/// `text` is null or points to a NUL-terminated string that outlives `'a`.
unsafe fn string<'a>(text: *const XmlChar) -> Result<Option<&'a str>, ParseError> {
    if text.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null and NUL-terminated by the caller's contract.
    let bytes = unsafe { CStr::from_ptr(text.cast::<c_char>()) }.to_bytes();
    // libxml2 holds every tree string as UTF-8.
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| backend_error("a tree string is not UTF-8"))
}

/// What an entity reference stands for in the tree.
enum Replacement<'a> {
    /// The declaration's parsed replacement, from this node on.
    Nodes(*mut XmlNode),
    /// Character data: a predefined entity's character (XML 1.0 section
    /// 4.6), or nothing for an empty replacement (section 2.3, production 9).
    Text(&'a str),
}

/// The replacement of the entity reference `reference`. A declaration whose
/// replacement libxml2 holds only as unparsed text that is not a predefined
/// character is refused: reading it would mean parsing its markup here,
/// which the tree's own parser has not done.
///
/// # Safety
/// `reference` is a live entity-reference node of a live tree.
unsafe fn replacement<'a>(reference: &XmlNode) -> Result<Replacement<'a>, ParseError> {
    let entity = reference.children.cast::<XmlEntity>();
    if entity.is_null() {
        return Err(backend_error("an entity reference without its declaration"));
    }
    // SAFETY: a reference's `children` is its live declaration.
    let entity = unsafe { &*entity };
    if !entity.children.is_null() {
        return Ok(Replacement::Nodes(entity.children));
    }
    if entity.length == 0 {
        return Ok(Replacement::Text(""));
    }
    if entity.etype == XML_INTERNAL_PREDEFINED_ENTITY {
        // SAFETY: a predefined declaration's content is its NUL-terminated
        // character, static in libxml2.
        return Ok(Replacement::Text(
            unsafe { string(entity.content) }?.unwrap_or_default(),
        ));
    }
    Err(backend_error(
        "an entity reference whose replacement the tree has not parsed",
    ))
}

/// One undo step of an edit.
enum Undo {
    /// The edit created and linked `node`; undoing it unlinks and frees it.
    Linked(*mut XmlNode),
    /// The edit unlinked `node` from `parent`, where it preceded `next`.
    Unlinked {
        node: *mut XmlNode,
        parent: *mut XmlNode,
        next: *mut XmlNode,
    },
}

/// A caller's libxml2 document as the core's external tree.
pub struct LibxmlTree {
    doc: *mut XmlDoc,
    journal: Vec<Undo>,
}

// SAFETY: the tree is reached only through the document handle that owns
// it, which one call at a time uses under its lock; the caller does not
// use or free the `xmlDoc` from another thread while a call runs (header
// contract), and libxml2 tree functions keep no thread-confined state.
unsafe impl Send for LibxmlTree {}
// SAFETY: shared references read the tree only, under the same contract.
unsafe impl Sync for LibxmlTree {}

impl LibxmlTree {
    fn document_node(&self) -> *mut XmlNode {
        self.doc.cast::<XmlNode>()
    }

    /// Report the nodes from `first` on, with their descendants.
    ///
    /// # Safety
    /// `first` is null or a node of this tree, valid with all its siblings
    /// and descendants for the walk.
    unsafe fn walk(first: *mut XmlNode, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        enum Frame {
            Element(*mut XmlNode),
            Entity(*mut XmlNode),
        }
        let mut stack = Vec::new();
        let mut current = first;
        loop {
            if current.is_null() {
                match stack.pop() {
                    None => return Ok(()),
                    Some(Frame::Element(element)) => {
                        sink.end_element()?;
                        // SAFETY: `element` is a node of the walked tree.
                        current = unsafe { (*element).next };
                    }
                    Some(Frame::Entity(reference)) => {
                        sink.leave_entity()?;
                        // SAFETY: as above.
                        current = unsafe { (*reference).next };
                    }
                }
                continue;
            }
            // SAFETY: `current` is a live node of the tree by the walk's
            // contract; every pointer read below is one of its members.
            let node = unsafe { &*current };
            let next = node.next;
            match node.kind {
                XML_ELEMENT_NODE => {
                    // SAFETY: an element's name, namespace, declarations and
                    // attributes belong to the same live tree.
                    unsafe { Self::start_element(node, sink) }?;
                    stack.push(Frame::Element(current));
                    current = node.children;
                    continue;
                }
                XML_TEXT_NODE | XML_CDATA_SECTION_NODE => {
                    // SAFETY: content is null or a NUL-terminated tree string.
                    let text = unsafe { string(node.content) }?.unwrap_or_default();
                    sink.text(reference(current), text)?;
                }
                XML_COMMENT_NODE => {
                    // SAFETY: as above.
                    let text = unsafe { string(node.content) }?.unwrap_or_default();
                    sink.comment(reference(current), text)?;
                }
                XML_PI_NODE => {
                    // SAFETY: a PI's name is its target; content its value.
                    let (target, value) = unsafe { (string(node.name)?, string(node.content)?) };
                    sink.processing_instruction(
                        reference(current),
                        target.unwrap_or_default(),
                        value,
                    )?;
                }
                XML_ENTITY_REF_NODE => {
                    // The replacement is included in the content (XML 1.0
                    // section 4.4.2).
                    // SAFETY: a live entity reference of the walked tree.
                    match unsafe { replacement(node) }? {
                        Replacement::Nodes(first) => {
                            sink.enter_entity()?;
                            stack.push(Frame::Entity(current));
                            current = first;
                            continue;
                        }
                        Replacement::Text(text) => {
                            sink.enter_entity()?;
                            if !text.is_empty() {
                                sink.text(reference(current), text)?;
                            }
                            sink.leave_entity()?;
                        }
                    }
                }
                // The document type was reported before the walk; XInclude
                // markers carry no content.
                XML_DTD_NODE | XML_XINCLUDE_START | XML_XINCLUDE_END => {}
                _ => return Err(backend_error("a node type the tree may not hold")),
            }
            current = next;
        }
    }

    /// Report the start tag of `element`.
    ///
    /// # Safety
    /// `element` is a live element of this tree.
    unsafe fn start_element(element: &XmlNode, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        // SAFETY: the element's members belong to the live tree.
        let (name, prefix, namespace) = unsafe {
            let ns = element.ns;
            let (prefix, namespace) = if ns.is_null() {
                (None, None)
            } else {
                (string((*ns).prefix)?, string((*ns).href)?)
            };
            (string(element.name)?.unwrap_or_default(), prefix, namespace)
        };
        let node = std::ptr::from_ref(element).cast_mut();
        sink.begin_element(reference(node), name, prefix, namespace)?;
        let mut declaration = element.ns_def;
        while !declaration.is_null() {
            // SAFETY: the declaration list of a live element.
            let declared = unsafe { &*declaration };
            // SAFETY: its strings are NUL-terminated tree strings.
            let (prefix, uri) = unsafe { (string(declared.prefix)?, string(declared.href)?) };
            sink.declare_namespace(prefix, uri.unwrap_or_default())?;
            declaration = declared.next;
        }
        let mut attribute = element.properties;
        while !attribute.is_null() {
            // SAFETY: the attribute list of a live element.
            let attr = unsafe { &*attribute };
            // SAFETY: the attribute's members belong to the live tree.
            let (name, prefix, namespace, value) = unsafe {
                let (prefix, namespace) = if attr.ns.is_null() {
                    (None, None)
                } else {
                    (string((*attr.ns).prefix)?, string((*attr.ns).href)?)
                };
                (
                    string(attr.name)?.unwrap_or_default(),
                    prefix,
                    namespace,
                    attribute_value(attr, sink)?,
                )
            };
            sink.attribute(
                name,
                prefix,
                namespace,
                &value,
                attr.atype == XML_ATTRIBUTE_ID,
            )?;
            attribute = attr.next;
        }
        sink.open_element()
    }

    /// The nodes of `fragment`, created in this document as detached
    /// sibling subtrees; `context` is the element whose scope they join.
    ///
    /// # Safety
    /// `context` is null or a live element of this tree.
    unsafe fn build(
        &self,
        fragment: &Fragment<'_>,
        context: *mut XmlNode,
    ) -> Result<Vec<*mut XmlNode>, TreeEditError> {
        let mut builder = Builder {
            doc: self.doc,
            context,
            top: Vec::new(),
            open: Vec::new(),
        };
        match fragment.walk(&mut |event| builder.event(event)) {
            Ok(()) => Ok(builder.top),
            Err(error) => {
                builder.discard();
                Err(error)
            }
        }
    }

    /// Unlink `node`, remembering where it stood.
    ///
    /// # Safety
    /// `node` is a live, linked node of this tree.
    unsafe fn unlink(&mut self, node: *mut XmlNode) {
        // SAFETY: a live linked node.
        let (parent, next) = unsafe { ((*node).parent, (*node).next) };
        // SAFETY: as above; libxml2 fixes the parent's and siblings' links.
        unsafe { xmlUnlinkNode(node) };
        self.journal.push(Undo::Unlinked { node, parent, next });
    }
}

/// Builds a fragment's nodes in one document: elements stay open until their
/// end tag, then join their parent or the top-level sequence.
struct Builder {
    doc: *mut XmlDoc,
    context: *mut XmlNode,
    top: Vec<*mut XmlNode>,
    open: Vec<Open>,
}

impl Builder {
    fn event(&mut self, event: FragmentEvent<'_>) -> Result<(), TreeEditError> {
        match event {
            FragmentEvent::StartElement {
                local_name,
                prefix,
                namespace,
            } => self.start(local_name, prefix, namespace),
            FragmentEvent::Namespace { prefix, uri } => self.declare(prefix, uri),
            FragmentEvent::Attribute {
                local_name,
                prefix,
                namespace,
                value,
            } => {
                let element = self
                    .open
                    .last_mut()
                    .ok_or_else(|| edit_error("a stray attribute"))?;
                element.attributes.push((
                    local_name.into(),
                    prefix.map(c_string).transpose()?,
                    namespace.map(String::from),
                    value.into(),
                ));
                Ok(())
            }
            FragmentEvent::OpenElement => self.open_element(),
            FragmentEvent::EndElement => {
                let element = self
                    .open
                    .pop()
                    .ok_or_else(|| edit_error("a stray end tag"))?;
                self.place(element.node);
                Ok(())
            }
            // White space at the document level is not content (XML 1.0
            // section 2.8, production 27) and a libxml2 document holds no
            // text children; the core admits only white space there.
            FragmentEvent::Text(_) if self.context.is_null() && self.open.is_empty() => Ok(()),
            FragmentEvent::Text(text) => {
                let text = c_string(text)?;
                // SAFETY: `doc` is live; libxml2 copies the content, unescaped.
                let node = unsafe { xmlNewDocText(self.doc, text.as_ptr().cast()) };
                self.leaf(node)
            }
            FragmentEvent::Comment(text) => {
                let text = c_string(text)?;
                // SAFETY: as above.
                let node = unsafe { xmlNewDocComment(self.doc, text.as_ptr().cast()) };
                self.leaf(node)
            }
            FragmentEvent::ProcessingInstruction { target, value } => {
                let (target, value) = (c_string(target)?, value.map(c_string).transpose()?);
                // SAFETY: as above.
                let node = unsafe {
                    xmlNewDocPI(
                        self.doc,
                        target.as_ptr().cast(),
                        value
                            .as_ref()
                            .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
                    )
                };
                self.leaf(node)
            }
        }
    }

    fn start(
        &mut self,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<(), TreeEditError> {
        let name = c_string(local_name)?;
        // SAFETY: `doc` is live; libxml2 copies the name. The namespace is
        // set once the element's own declarations are known.
        let node = unsafe {
            xmlNewDocNode(
                self.doc,
                std::ptr::null_mut(),
                name.as_ptr().cast(),
                std::ptr::null(),
            )
        };
        if node.is_null() {
            return Err(edit_error("libxml2 could not create an element"));
        }
        self.open.push(Open {
            node,
            prefix: prefix.map(c_string).transpose()?,
            namespace: namespace.map(String::from),
            attributes: Vec::new(),
        });
        Ok(())
    }

    fn declare(&mut self, prefix: Option<&str>, uri: &str) -> Result<(), TreeEditError> {
        let node = self
            .open
            .last()
            .ok_or_else(|| edit_error("a stray declaration"))?
            .node;
        let (uri, prefix) = (c_string(uri)?, prefix.map(c_string).transpose()?);
        // SAFETY: `node` was created by this build; libxml2 copies both strings.
        let declared = unsafe {
            xmlNewNs(
                node,
                uri.as_ptr().cast(),
                prefix
                    .as_ref()
                    .map_or(std::ptr::null(), |prefix| prefix.as_ptr().cast()),
            )
        };
        if declared.is_null() {
            return Err(edit_error("libxml2 could not declare a namespace"));
        }
        Ok(())
    }

    /// The start tag ended: the element's namespace and attributes, which may
    /// use its own declarations, are created now.
    fn open_element(&mut self) -> Result<(), TreeEditError> {
        let element = self
            .open
            .last()
            .ok_or_else(|| edit_error("a stray start tag end"))?;
        let ns = self.namespace(element.prefix.as_ref(), element.namespace.as_deref())?;
        // SAFETY: the element was created by this build.
        unsafe { (*element.node).ns = ns };
        for (name, prefix, namespace, value) in &element.attributes {
            let ns = self.namespace(prefix.as_ref(), namespace.as_deref())?;
            let (name, value) = (c_string(name)?, c_string(value)?);
            // SAFETY: libxml2 copies both strings; the value is taken as
            // given, without entity processing.
            let attribute = unsafe {
                xmlNewNsProp(
                    element.node,
                    ns,
                    name.as_ptr().cast(),
                    value.as_ptr().cast(),
                )
            };
            if attribute.is_null() {
                return Err(edit_error("libxml2 could not create an attribute"));
            }
        }
        Ok(())
    }

    fn leaf(&mut self, node: *mut XmlNode) -> Result<(), TreeEditError> {
        if node.is_null() {
            return Err(edit_error("libxml2 could not create a node"));
        }
        self.place(node);
        Ok(())
    }

    /// `node` joins the innermost open element, or the top-level sequence.
    fn place(&mut self, node: *mut XmlNode) {
        match self.open.last() {
            // SAFETY: both nodes were created by this build and `node` is
            // detached.
            Some(parent) => unsafe { link(parent.node, std::ptr::null_mut(), node) },
            None => self.top.push(node),
        }
    }

    /// Free everything a failed build created; none of it is in the tree.
    fn discard(self) {
        for node in self.open.into_iter().map(|open| open.node).chain(self.top) {
            // SAFETY: created by this build and linked nowhere in the tree;
            // an open element is not linked into its parent yet.
            unsafe { xmlFreeNode(node) };
        }
    }

    /// The declaration binding `prefix` to `namespace` for an element being
    /// built: the nearest one on the new elements, else the context's scope.
    fn namespace(
        &self,
        prefix: Option<&CString>,
        namespace: Option<&str>,
    ) -> Result<*mut XmlNs, TreeEditError> {
        let Some(namespace) = namespace else {
            return Ok(std::ptr::null_mut());
        };
        let wanted = prefix.map(CString::as_bytes);
        for element in self.open.iter().rev() {
            // SAFETY: the element and its declarations are live.
            let mut declaration = unsafe { (*element.node).ns_def };
            while !declaration.is_null() {
                // SAFETY: a live declaration.
                let declared = unsafe { &*declaration };
                // SAFETY: its strings are NUL-terminated.
                let found = unsafe { c_bytes(declared.prefix) };
                if found == wanted {
                    // SAFETY: as above.
                    return if unsafe { c_bytes(declared.href) } == Some(namespace.as_bytes()) {
                        Ok(declaration)
                    } else {
                        Err(edit_error("a fragment prefix bound to another namespace"))
                    };
                }
                declaration = declared.next;
            }
        }
        let prefix = prefix.map_or(std::ptr::null(), |prefix| prefix.as_ptr().cast());
        // Without a context element (the document element is being replaced)
        // search from the element being built: xmlSearchNs returns nothing for
        // a null node, not even the implicit `xml` binding every element has
        // (Namespaces in XML 1.0 section 3). The built element's own
        // declarations were checked above and it has no ancestors yet.
        let from = if self.context.is_null() {
            self.open
                .last()
                .map_or(std::ptr::null_mut(), |element| element.node)
        } else {
            self.context
        };
        // SAFETY: `doc` is live and `from` null or live; the result is a
        // declaration of the document or of `from` or an ancestor of it.
        let found = unsafe { xmlSearchNs(self.doc, from, prefix) };
        // SAFETY: a declaration libxml2 returned is live.
        if found.is_null() || unsafe { c_bytes((*found).href) } != Some(namespace.as_bytes()) {
            return Err(edit_error("a fragment namespace its context does not bind"));
        }
        Ok(found)
    }
}

impl LibxmlTree {
    /// Link the nodes `built` created under `parent` before `next` (null:
    /// as its last children), remembering each.
    ///
    /// # Safety
    /// `parent` is live and `next` is null or one of its children; every
    /// node of `built` is detached and was created in this document.
    unsafe fn attach(
        &mut self,
        parent: *mut XmlNode,
        next: *mut XmlNode,
        built: Vec<*mut XmlNode>,
    ) {
        for node in built {
            // SAFETY: the caller's contract.
            unsafe { link(parent, next, node) };
            self.journal.push(Undo::Linked(node));
        }
    }

    /// Unlink every child of `element`.
    ///
    /// # Safety
    /// `element` is a live element of this tree.
    unsafe fn clear(&mut self, element: *mut XmlNode) {
        // SAFETY: a live element.
        let mut child = unsafe { (*element).children };
        while !child.is_null() {
            // SAFETY: a live child, read before it is unlinked.
            let next = unsafe { (*child).next };
            // SAFETY: as above.
            unsafe { self.unlink(child) };
            child = next;
        }
    }

    /// Apply one edit.
    ///
    /// # Safety
    /// The edit's target is a live node of this tree.
    unsafe fn apply_one(&mut self, edit: &TreeEdit<'_>) -> Result<(), TreeEditError> {
        match *edit {
            TreeEdit::SetText { target, text } => {
                let target = node_of(target);
                // SAFETY: the target is live by the caller's contract.
                unsafe { self.clear(target) };
                if !text.is_empty() {
                    let text = c_string(text)?;
                    // SAFETY: libxml2 copies the content, unescaped.
                    let node = unsafe { xmlNewDocText(self.doc, text.as_ptr().cast()) };
                    if node.is_null() {
                        return Err(edit_error("libxml2 could not create a text node"));
                    }
                    // SAFETY: the new node is detached; the target is live.
                    unsafe { self.attach(target, std::ptr::null_mut(), vec![node]) };
                }
            }
            TreeEdit::ReplaceContent { target, fragment } => {
                let target = node_of(target);
                // SAFETY: the target is a live element.
                let built = unsafe { self.build(&fragment, target) }?;
                // SAFETY: as above; the built nodes are detached.
                unsafe {
                    self.clear(target);
                    self.attach(target, std::ptr::null_mut(), built);
                }
            }
            TreeEdit::AppendChild { target, fragment } => {
                let target = node_of(target);
                // SAFETY: as above.
                let built = unsafe { self.build(&fragment, target) }?;
                // SAFETY: as above.
                unsafe { self.attach(target, std::ptr::null_mut(), built) };
            }
            TreeEdit::InsertBefore { target, fragment }
            | TreeEdit::ReplaceNode { target, fragment } => {
                let target = node_of(target);
                // SAFETY: the target is live; its parent is an element or
                // the document.
                let parent = unsafe { (*target).parent };
                if parent.is_null() {
                    return Err(edit_error("the target has no parent"));
                }
                let context = if parent == self.document_node() {
                    std::ptr::null_mut()
                } else {
                    parent
                };
                // SAFETY: `context` is null or the live parent element.
                let built = unsafe { self.build(&fragment, context) }?;
                // SAFETY: `target` is a child of `parent`; the built nodes
                // are detached.
                unsafe { self.attach(parent, target, built) };
                if matches!(edit, TreeEdit::ReplaceNode { .. }) {
                    // SAFETY: `target` is still linked under `parent`.
                    unsafe { self.unlink(target) };
                }
            }
        }
        Ok(())
    }
}

/// A new libxml2 document holding `document`, which the core parsed under
/// its policy: the nodes are created with libxml2's constructors from the
/// core's tree, so libxml2 parses nothing, and the declaration's version,
/// encoding name and standalone value are carried as libxml2's parser would
/// record them. The caller owns the result and frees it with `xmlFreeDoc`.
///
/// # Errors
/// A document with a document type declaration, whose declarations a
/// libxml2 tree would have to carry as a DTD this build does not create, a
/// linked libxml2 laid out differently, or a node libxml2 cannot create.
pub fn new_document(document: &XmlDocument) -> Result<*mut XmlDoc, TreeEditError> {
    if !layout_matches() {
        return Err(edit_error(
            "the linked libxml2 lays out its tree differently",
        ));
    }
    if document.declares_dtd() {
        return Err(edit_error("a document type declaration is not built"));
    }
    let declaration = document.declaration();
    let version = c_string(declaration.map_or("1.0", |declaration| declaration.version))?;
    let encoding = declaration
        .and_then(|declaration| declaration.encoding)
        .map(c_string)
        .transpose()?;
    // SAFETY: libxml2 copies the version.
    let doc = unsafe { xmlNewDoc(version.as_ptr().cast()) };
    if doc.is_null() {
        return Err(edit_error("libxml2 could not create a document"));
    }
    // The document owns everything built from here on, so freeing it is the
    // whole cleanup of a failed build.
    let free = move |error| {
        // SAFETY: `doc` was created above and nothing else refers to it.
        unsafe { xmlFreeDoc(doc) };
        Err(error)
    };
    if let Some(encoding) = encoding {
        // SAFETY: libxml2 frees the copy with the document.
        let copy = unsafe { xmlStrdup(encoding.as_ptr().cast()) };
        if copy.is_null() {
            return free(edit_error("libxml2 could not copy the encoding name"));
        }
        // SAFETY: a fresh document has no encoding yet.
        unsafe { (*doc).encoding = copy };
    }
    // libxml2's parser records -1 without a declaration and -2 for one
    // without a standalone value.
    let standalone = match declaration.map(|declaration| declaration.standalone) {
        None => -1,
        Some(None) => -2,
        Some(Some(standalone)) => c_int::from(standalone),
    };
    // SAFETY: a live document.
    unsafe { (*doc).standalone = standalone };
    let mut builder = Builder {
        doc,
        context: std::ptr::null_mut(),
        top: Vec::new(),
        open: Vec::new(),
    };
    let built = document.with_view(|view| view.content().walk(&mut |event| builder.event(event)));
    if let Err(error) = built {
        builder.discard();
        return free(error);
    }
    for node in builder.top {
        // SAFETY: built detached in `doc`, whose node part is its common part.
        unsafe { link(doc.cast(), std::ptr::null_mut(), node) };
    }
    Ok(doc)
}

/// An element a fragment build created whose end tag has not come yet.
struct Open {
    node: *mut XmlNode,
    prefix: Option<CString>,
    namespace: Option<String>,
    /// Name, prefix, namespace and value; created once the element's own
    /// declarations are known.
    attributes: Vec<(String, Option<CString>, Option<String>, String)>,
}

fn c_string(value: &str) -> Result<CString, TreeEditError> {
    // XML 1.0 section 2.2 admits no NUL character.
    CString::new(value).map_err(|_| edit_error("a fragment string holds NUL"))
}

/// The bytes of a NUL-terminated string, or `None` for null.
///
/// # Safety
/// `text` is null or NUL-terminated and live.
unsafe fn c_bytes<'a>(text: *const XmlChar) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    (!text.is_null()).then(|| unsafe { CStr::from_ptr(text.cast::<c_char>()) }.to_bytes())
}

/// An attribute's value: its children's character data, entity references
/// expanded. Every expansion counts toward the projection's entity ceiling
/// and every piece is admitted against its byte limit before it is copied,
/// so nested references cannot grow a value past what the policy allows.
/// The walk keeps its pending siblings on the heap, as the content walk
/// does, so nesting depth costs no stack and needs no ceiling of its own:
/// the expansion ceiling bounds it.
///
/// # Safety
/// `attr` is a live attribute of a live tree.
unsafe fn attribute_value(attr: &XmlAttr, sink: &mut TreeSink<'_>) -> Result<String, ParseError> {
    let mut value = String::new();
    // The next sibling to read at each enclosing reference level.
    let mut resume = Vec::new();
    let mut current = attr.children;
    loop {
        if current.is_null() {
            match resume.pop() {
                Some(next) => {
                    current = next;
                    continue;
                }
                None => return Ok(value),
            }
        }
        // SAFETY: a live node of the attribute's value or of a declaration's
        // replacement, which belong to the same live tree.
        let node = unsafe { &*current };
        match node.kind {
            XML_TEXT_NODE => {
                // SAFETY: content is null or a NUL-terminated tree string.
                let text = unsafe { string(node.content) }?.unwrap_or_default();
                sink.admit_attribute_bytes(value.len() + text.len())?;
                value.push_str(text);
                current = node.next;
            }
            XML_ENTITY_REF_NODE => {
                sink.expand_attribute_entity()?;
                // SAFETY: a live entity reference of the attribute's tree.
                match unsafe { replacement(node) }? {
                    Replacement::Nodes(first) => {
                        resume.push(node.next);
                        current = first;
                    }
                    Replacement::Text(text) => {
                        sink.admit_attribute_bytes(value.len() + text.len())?;
                        value.push_str(text);
                        current = node.next;
                    }
                }
            }
            _ => return Err(backend_error("an attribute value the tree cannot report")),
        }
    }
}

/// Link the detached `node` under `parent` before `next`, or last.
///
/// # Safety
/// `parent` is a live element or document, `next` null or a child of it,
/// and `node` a detached node of the same document.
unsafe fn link(parent: *mut XmlNode, next: *mut XmlNode, node: *mut XmlNode) {
    // SAFETY: the caller's contract; the document shares the common part.
    unsafe {
        (*node).parent = parent;
        let prev = if next.is_null() {
            (*parent).last
        } else {
            (*next).prev
        };
        (*node).prev = prev;
        (*node).next = next;
        if prev.is_null() {
            (*parent).children = node;
        } else {
            (*prev).next = node;
        }
        if next.is_null() {
            (*parent).last = node;
        } else {
            (*next).prev = node;
        }
    }
}

impl ExternalTree for LibxmlTree {
    fn document(&self) -> ExternalNode {
        reference(self.document_node())
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        if !layout_matches() {
            return Err(backend_error(
                "the linked libxml2 lays out its tree differently",
            ));
        }
        // SAFETY: `doc` is the caller's live document for the whole call.
        let (has_dtd, first) = unsafe { (!(*self.doc).int_subset.is_null(), (*self.doc).children) };
        if has_dtd {
            sink.document_type()?;
        }
        // SAFETY: the document's nodes are live for the call.
        unsafe { Self::walk(first, sink) }
    }

    fn apply(&mut self, edits: &[TreeEdit<'_>]) -> Result<(), TreeEditError> {
        for edit in edits {
            // SAFETY: every target is a node the last projection reported,
            // and the tree changed since only through these edits.
            unsafe { self.apply_one(edit) }?;
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> usize {
        self.journal.len()
    }

    fn rollback(&mut self, mark: usize) {
        while self.journal.len() > mark {
            match self.journal.pop() {
                Some(Undo::Linked(node)) => {
                    // SAFETY: the node was created and linked by an edit not
                    // yet undone, so it is live and linked.
                    unsafe {
                        xmlUnlinkNode(node);
                        xmlFreeNode(node);
                    }
                }
                Some(Undo::Unlinked { node, parent, next }) => {
                    // SAFETY: undoing newest first restores the state in
                    // which `next` followed `node` under `parent`.
                    unsafe { link(parent, next, node) };
                }
                None => break,
            }
        }
    }

    fn release(&mut self, mark: usize) {
        // The caller's ID table names attribute nodes. xmlFreeProp removes
        // the entry of an ID attribute it frees, and xmlNewNsProp registers
        // an ID it creates unless the value is already taken, which it is
        // when a replacement keeps the ID of the element it replaces. So the
        // built nodes the committed tree still holds are found first, the
        // removed ones are freed, and the built ones register what they now
        // hold alone. A rollback needs none of this: the restored nodes were
        // never unregistered, and freeing built ones removes only their own.
        let doc = self.document_node();
        let kept: Vec<*mut XmlNode> = self.journal[mark..]
            .iter()
            .filter_map(|undo| match *undo {
                // SAFETY: every node of the journal is still allocated; the
                // walk reads parent links only.
                Undo::Linked(node) if unsafe { attached(doc, node) } => Some(node),
                _ => None,
            })
            .collect();
        for undo in self.journal.drain(mark..) {
            if let Undo::Unlinked { node, .. } = undo {
                // SAFETY: an unlinked node no later edit relinked; nothing
                // in the tree points to it any more.
                unsafe { xmlFreeNode(node) };
            }
        }
        for node in kept {
            // SAFETY: the node is in the committed tree, which the freed
            // subtrees were not part of.
            unsafe { register_ids(self.doc, node) };
        }
    }
}

/// Whether `node` hangs under the document `doc`, through its parent links.
///
/// # Safety
/// `node` and its ancestors are allocated nodes.
unsafe fn attached(doc: *mut XmlNode, node: *mut XmlNode) -> bool {
    let mut current = node;
    while !current.is_null() {
        if current == doc {
            return true;
        }
        // SAFETY: the caller's contract.
        current = unsafe { (*current).parent };
    }
    false
}

/// Register every ID attribute in the subtree of `node` that the table does
/// not name yet, as libxml2's parser and xmlNewNsProp would (`xmlIsID`).
///
/// # Safety
/// `node` is a live node of the live document `doc`.
unsafe fn register_ids(doc: *mut XmlDoc, node: *mut XmlNode) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        // SAFETY: a live node of the subtree.
        let element = unsafe { &*current };
        if element.kind != XML_ELEMENT_NODE {
            continue;
        }
        let mut attribute = element.properties;
        while !attribute.is_null() {
            // SAFETY: the attribute list of a live element.
            let attr = unsafe { &*attribute };
            // SAFETY: live element and attribute of `doc`.
            if attr.atype != XML_ATTRIBUTE_ID && unsafe { xmlIsID(doc, current, attribute) } == 1 {
                // A built attribute holds one text node, its value as given.
                let text = attr.children;
                let value = if text.is_null() {
                    std::ptr::null()
                } else {
                    // SAFETY: a live text child of the attribute.
                    unsafe { (*text).content }
                };
                if !value.is_null() {
                    // SAFETY: the value is a NUL-terminated tree string that
                    // libxml2 copies into the table entry.
                    unsafe { xmlAddID(std::ptr::null_mut(), doc, value, attribute) };
                }
            }
            attribute = attr.next;
        }
        let mut child = element.children;
        while !child.is_null() {
            stack.push(child);
            // SAFETY: a live child.
            child = unsafe { (*child).next };
        }
    }
}

impl Drop for LibxmlTree {
    fn drop(&mut self) {
        // Committed edits only remain if a transaction never finished.
        self.release(0);
    }
}

impl LibxmlTree {
    /// The caller's document `doc` as an external tree, for crates that
    /// project it themselves; `None` for a null or non-document pointer or a
    /// libxml2 whose layout differs from the declarations here.
    ///
    /// # Safety
    /// `doc` is null or a live `xmlDocPtr` that outlives the tree, and nothing
    /// else changes it while the tree is projected or edited.
    #[must_use]
    pub unsafe fn new(doc: *mut XmlDoc) -> Option<Self> {
        if doc.is_null() || !doc.is_aligned() || !layout_matches() {
            return None;
        }
        // SAFETY: a live document by the caller's contract.
        if unsafe { (*doc).kind } != XML_DOCUMENT_NODE {
            return None;
        }
        Some(Self {
            doc,
            journal: Vec::new(),
        })
    }
}

/// Create a document handle over the caller's libxml2 document `doc`, read
/// under the compiled policy of `operation` (`XS_OPERATION_*`) in `policy`.
///
/// Every operation on the handle reads `doc` as it is when the operation
/// starts and changes it in place. Destroying the handle leaves `doc` to the
/// caller.
///
/// # Safety
/// `doc` is a valid `xmlDocPtr` that outlives the handle; while a call on
/// the handle runs, nothing else uses or changes `doc`. `out` is valid for
/// writes of one `XsDocument`; `error` is null or valid for writes of one
/// `XsError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_libxml2_document(
    policy: XsPolicy,
    operation: u32,
    doc: *mut XmlDoc,
    out: *mut XsDocument,
    error: *mut XsError,
) -> XsStatus {
    let refuse = |status: XsStatus| {
        if !error.is_null() && error.is_aligned() {
            // SAFETY: non-null, aligned and writable by the caller's contract.
            unsafe { error.write(XsError::default()) };
        }
        status
    };
    if doc.is_null() || !doc.is_aligned() {
        return refuse(XS_INVALID_ARGUMENT);
    }
    // SAFETY: a valid document by the caller's contract.
    if unsafe { (*doc).kind } != XML_DOCUMENT_NODE {
        return refuse(XS_INVALID_ARGUMENT);
    }
    if !layout_matches() {
        return refuse(XS_INTERNAL);
    }
    // SAFETY: a live document that outlives the handle by the contract.
    let Some(tree) = (unsafe { LibxmlTree::new(doc) }) else {
        return refuse(XS_INVALID_ARGUMENT);
    };
    let tree = Box::new(tree);
    // SAFETY: forwarded contract for `out` and `error`.
    unsafe { xml_sec_capi::ffi::document_from_tree(policy, operation, tree, out, error) }
}
