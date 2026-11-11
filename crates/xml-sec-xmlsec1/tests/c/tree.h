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
#include <libxml/valid.h>

#define xsSetGenericErrorFunc xmlSetGenericErrorFunc
#define xsFree(mem) xmlFree(mem)
#define xsStrdup xmlStrdup
#define xsReadMemory xmlReadMemory
#define xsNewDoc xmlNewDoc
#define xsFreeDoc xmlFreeDoc
#define xsDocGetRootElement xmlDocGetRootElement
#define xsDocSetRootElement xmlDocSetRootElement
#define xsAddChild xmlAddChild
#define xsGetProp xmlGetProp
#define xsDocDumpMemory xmlDocDumpMemory
#define xsNewDocNode xmlNewDocNode
#define xsNodeGetContent xmlNodeGetContent
#define xsFreeNode xmlFreeNode
#define xsFreeNodeList xmlFreeNodeList
#define xsNewDocText xmlNewDocText
#define xsSearchNs xmlSearchNs
/* libxml2's xmlNodeSetContent returns nothing before 2.13; the programs do
 * not read the result. */
#define xsNodeSetContent(node, content) (xmlNodeSetContent(node, content), 0)
/* Only compared with NULL by the programs: an attribute against an element. */
#define xsGetID(doc, value) ((void *)xmlGetID(doc, value))
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
static inline xmlNodePtr xsNodeGetPrev(const xmlNode *node) {
    return node != NULL ? node->prev : NULL;
}
static inline xmlNodePtr xsNodeGetLast(const xmlNode *node) {
    return node != NULL ? node->last : NULL;
}
static inline xmlChar *xsNodeGetNsPrefix(const xmlNode *node) {
    return node != NULL && node->ns != NULL && node->ns->prefix != NULL ? xmlStrdup(node->ns->prefix)
                                                                         : NULL;
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
