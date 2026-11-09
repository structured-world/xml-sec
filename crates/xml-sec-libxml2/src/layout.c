/* The layout of the libxml2 structure members and constants the bridge reads
 * and writes, as the headers being linked define them. The Rust side
 * compares this record with its own declarations before touching any tree.
 * Structure sizes are not part of it: the bridge never allocates a libxml2
 * structure itself, and later releases append members. */

#include <stddef.h>
#include <libxml/entities.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

const size_t xs_libxml2_layout[] = {
    offsetof(xmlNode, type),
    offsetof(xmlNode, name),
    offsetof(xmlNode, children),
    offsetof(xmlNode, last),
    offsetof(xmlNode, parent),
    offsetof(xmlNode, next),
    offsetof(xmlNode, prev),
    offsetof(xmlNode, doc),
    offsetof(xmlNode, ns),
    offsetof(xmlNode, content),
    offsetof(xmlNode, properties),
    offsetof(xmlNode, nsDef),
    offsetof(xmlAttr, type),
    offsetof(xmlAttr, name),
    offsetof(xmlAttr, children),
    offsetof(xmlAttr, parent),
    offsetof(xmlAttr, next),
    offsetof(xmlAttr, ns),
    offsetof(xmlAttr, atype),
    offsetof(xmlNs, next),
    offsetof(xmlNs, type),
    offsetof(xmlNs, href),
    offsetof(xmlNs, prefix),
    offsetof(xmlDoc, type),
    offsetof(xmlDoc, children),
    offsetof(xmlDoc, last),
    offsetof(xmlDoc, intSubset),
    offsetof(xmlEntity, children),
    offsetof(xmlEntity, content),
    offsetof(xmlEntity, length),
    offsetof(xmlEntity, etype),
    sizeof(xmlElementType),
    XML_ELEMENT_NODE,
    XML_TEXT_NODE,
    XML_CDATA_SECTION_NODE,
    XML_ENTITY_REF_NODE,
    XML_PI_NODE,
    XML_COMMENT_NODE,
    XML_DOCUMENT_NODE,
    XML_DTD_NODE,
    XML_XINCLUDE_START,
    XML_XINCLUDE_END,
    XML_ATTRIBUTE_ID,
    XML_INTERNAL_PREDEFINED_ENTITY,
    XML_ATTRIBUTE_NODE,
    XML_NAMESPACE_DECL,
    offsetof(xmlNodeSet, nodeNr),
    offsetof(xmlNodeSet, nodeMax),
    offsetof(xmlNodeSet, nodeTab),
};

const size_t xs_libxml2_layout_len = sizeof(xs_libxml2_layout) / sizeof(xs_libxml2_layout[0]);
