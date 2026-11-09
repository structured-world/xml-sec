/* The layout of the xmlsec1 structures this crate creates or reads, as its
 * own headers define them. The Rust declarations are compared with this
 * record in the crate's tests; the headers themselves are compared with the
 * pinned libxmlsec1 by the header check and with its binary baseline by the
 * C layout test. */

#include <stddef.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/nodeset.h>

const size_t xs_xmlsec1_layout[] = {
    sizeof(xmlSecBuffer),
    offsetof(xmlSecBuffer, data),
    offsetof(xmlSecBuffer, size),
    offsetof(xmlSecBuffer, maxSize),
    offsetof(xmlSecBuffer, allocMode),
    sizeof(xmlSecAllocMode),
    xmlSecAllocModeExact,
    xmlSecAllocModeDouble,
    sizeof(xmlSecPtrList),
    offsetof(xmlSecPtrList, id),
    offsetof(xmlSecPtrList, data),
    offsetof(xmlSecPtrList, use),
    offsetof(xmlSecPtrList, max),
    offsetof(xmlSecPtrList, allocMode),
    sizeof(struct _xmlSecPtrListKlass),
    offsetof(struct _xmlSecPtrListKlass, name),
    offsetof(struct _xmlSecPtrListKlass, duplicateItem),
    offsetof(struct _xmlSecPtrListKlass, destroyItem),
    offsetof(struct _xmlSecPtrListKlass, debugDumpItem),
    offsetof(struct _xmlSecPtrListKlass, debugXmlDumpItem),
    sizeof(xmlSecNodeSet),
    offsetof(xmlSecNodeSet, nodes),
    offsetof(xmlSecNodeSet, doc),
    offsetof(xmlSecNodeSet, destroyDoc),
    offsetof(xmlSecNodeSet, type),
    offsetof(xmlSecNodeSet, op),
    offsetof(xmlSecNodeSet, next),
    offsetof(xmlSecNodeSet, prev),
    offsetof(xmlSecNodeSet, reserved),
    xmlSecNodeSetTreeWithoutCommentsInvert,
    xmlSecNodeSetList,
    xmlSecNodeSetUnion,
};

const size_t xs_xmlsec1_layout_len = sizeof(xs_xmlsec1_layout) / sizeof(xs_xmlsec1_layout[0]);
