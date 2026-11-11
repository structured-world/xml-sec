/* The document tree the test programs use: our tree functions, or, when the
 * program is built against the libxmlsec1 oracle (XS_ORACLE), the libxml2
 * functions and fields each of them is shaped like. The programs are the
 * same source either way, so the comparison covers the tree functions too. */
#ifndef XS_TEST_TREE_H
#define XS_TEST_TREE_H

#ifdef XS_ORACLE

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlIO.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <libxml/xmlerror.h>

#define xsSetGenericErrorFunc xmlSetGenericErrorFunc
#define xsFree(mem) xmlFree(mem)
#define xsStrdup xmlStrdup
#define xsReadMemory xmlReadMemory
#define xsFreeDoc xmlFreeDoc
#define xsDocGetRootElement xmlDocGetRootElement
#define xsDocDumpMemory xmlDocDumpMemory
#define xsNewDocNode xmlNewDocNode
#define xsNodeGetContent xmlNodeGetContent
#define xsFreeNode xmlFreeNode
#define xsSearchNs xmlSearchNs
#define xsXPathNodeSetCreate xmlXPathNodeSetCreate
#define xsXPathNodeSetAdd xmlXPathNodeSetAdd
#define xsXPathNodeSetAddNs xmlXPathNodeSetAddNs
#define xsAllocOutputBuffer xmlAllocOutputBuffer
#define xsOutputBufferFlush xmlOutputBufferFlush
#define xsOutputBufferGetSize xmlOutputBufferGetSize
#define xsOutputBufferGetContent xmlOutputBufferGetContent
#define xsOutputBufferClose xmlOutputBufferClose

static inline xmlNodePtr xsNodeGetChildren(const xmlNode *node) {
    return node != NULL ? node->children : NULL;
}
static inline xmlNodePtr xsNodeGetNext(const xmlNode *node) {
    return node != NULL ? node->next : NULL;
}
static inline xmlNodePtr xsNodeGetParent(const xmlNode *node) {
    return node != NULL ? node->parent : NULL;
}
static inline int xsNodeGetType(const xmlNode *node) {
    return node != NULL ? (int)node->type : 0;
}
static inline xmlChar *xsNodeGetName(const xmlNode *node) {
    return node != NULL && node->name != NULL ? xmlStrdup(node->name) : NULL;
}
static inline xmlAttrPtr xsNodeGetProperties(const xmlNode *node) {
    return node != NULL && node->type == XML_ELEMENT_NODE ? node->properties : NULL;
}
static inline xmlAttrPtr xsAttrGetNext(const xmlAttr *attr) {
    return attr != NULL ? attr->next : NULL;
}
static inline xmlNsPtr xsNodeGetNsDef(const xmlNode *node) {
    return node != NULL && node->type == XML_ELEMENT_NODE ? node->nsDef : NULL;
}
static inline xmlNsPtr xsNsGetNext(const xmlNs *ns) {
    return ns != NULL ? ns->next : NULL;
}
static inline xmlChar *xsNsGetPrefix(const xmlNs *ns) {
    return ns != NULL && ns->prefix != NULL ? xmlStrdup(ns->prefix) : NULL;
}

#else /* XS_ORACLE */

#include <xs_tree.h>

#endif /* XS_ORACLE */

#endif /* XS_TEST_TREE_H */
