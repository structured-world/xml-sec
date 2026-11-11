/*
 * The document tree of the libxmlsec1 surface: our own types and functions
 * shaped like libxml2's tree interface, exported under the `xs` prefix where
 * libxml2 has `xml`.
 *
 * The tree types are incomplete: a pointer to one is a handle the library
 * validates on every call and C code cannot dereference. Strings and blocks
 * a function returns for the caller to own are released with xsFree. No
 * function reads a file or a URL; a program reads its document and passes
 * the bytes to xsReadMemory or xmlSecParseMemory.
 *
 * A program written against libxml2 ports by renaming its tree calls
 * (xmlFoo -> xsFoo) and reading node fields through the accessor functions
 * below instead of through the structure. A few results differ from
 * libxml2's and are marked where declared: check those calls after the
 * rename.
 */
#ifndef XS_TREE_H
#define XS_TREE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char xmlChar;
#define BAD_CAST (xmlChar *)

typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;
typedef struct _xmlNode xmlNode;
typedef xmlNode *xmlNodePtr;
typedef struct _xmlNs xmlNs;
typedef xmlNs *xmlNsPtr;
typedef struct _xmlAttr xmlAttr;
typedef xmlAttr *xmlAttrPtr;
typedef struct _xmlNodeSet xmlNodeSet;
typedef xmlNodeSet *xmlNodeSetPtr;
typedef struct _xmlOutputBuffer xmlOutputBuffer;
typedef xmlOutputBuffer *xmlOutputBufferPtr;
typedef struct _xmlParserInputBuffer xmlParserInputBuffer;
typedef xmlParserInputBuffer *xmlParserInputBufferPtr;

/* The node types xsNodeGetType returns, libxml2's xmlElementType values. */
typedef enum {
    XML_ELEMENT_NODE = 1,
    XML_ATTRIBUTE_NODE = 2,
    XML_TEXT_NODE = 3,
    XML_CDATA_SECTION_NODE = 4,
    XML_ENTITY_REF_NODE = 5,
    XML_PI_NODE = 7,
    XML_COMMENT_NODE = 8,
    XML_DOCUMENT_NODE = 9,
    XML_DTD_NODE = 14,
    XML_NAMESPACE_DECL = 18
} xmlElementType;

typedef int (*xmlInputMatchCallback)(const char *filename);
typedef void *(*xmlInputOpenCallback)(const char *filename);
typedef int (*xmlInputReadCallback)(void *context, char *buffer, int len);
typedef int (*xmlInputCloseCallback)(void *context);
typedef int (*xmlOutputWriteCallback)(void *context, const char *buffer, int len);
typedef int (*xmlOutputCloseCallback)(void *context);

/* The generic error channel the library's default error reports use. */
typedef void (*xmlGenericErrorFunc)(void *context, const char *msg, ...);
void xsSetGenericErrorFunc(void *context, xmlGenericErrorFunc handler);

/* Memory. */
void *xsMalloc(size_t size);
void *xsRealloc(void *mem, size_t size);
void xsFree(void *mem);
xmlChar *xsStrdup(const xmlChar *text);
int xsStrEqual(const xmlChar *left, const xmlChar *right);

/* Documents. */
xmlDocPtr xsReadMemory(const char *buffer, int size, const char *url, const char *encoding,
                       int options);
xmlDocPtr xsNewDoc(const xmlChar *version);
void xsFreeDoc(xmlDocPtr doc);
xmlNodePtr xsDocGetRootElement(const xmlDoc *doc);
xmlNodePtr xsDocSetRootElement(xmlDocPtr doc, xmlNodePtr root);
void xsDocDumpMemory(const xmlDoc *doc, xmlChar **mem, int *size);

/* Node fields, read through accessors. */
xmlDocPtr xsNodeGetDoc(const xmlNode *node);
xmlNodePtr xsNodeGetParent(const xmlNode *node);
xmlNodePtr xsNodeGetChildren(const xmlNode *node);
xmlNodePtr xsNodeGetLast(const xmlNode *node);
xmlNodePtr xsNodeGetNext(const xmlNode *node);
xmlNodePtr xsNodeGetPrev(const xmlNode *node);
int xsNodeGetType(const xmlNode *node);
/* The name as a copy the caller frees with xsFree. */
xmlChar *xsNodeGetName(const xmlNode *node);
/* The name as node->name reads it: not owned by the caller, valid until the
 * document is freed. */
const xmlChar *xsNodeName(const xmlNode *node);
xmlChar *xsNodeGetNsHref(const xmlNode *node);
xmlChar *xsNodeGetNsPrefix(const xmlNode *node);
xmlAttrPtr xsNodeGetProperties(const xmlNode *node);
xmlAttrPtr xsAttrGetNext(const xmlAttr *attr);
xmlNsPtr xsNodeGetNsDef(const xmlNode *node);
xmlNsPtr xsNsGetNext(const xmlNs *ns);
xmlChar *xsNsGetHref(const xmlNs *ns);
xmlChar *xsNsGetPrefix(const xmlNs *ns);

/* Building and linking. */
xmlNodePtr xsNewDocNode(xmlDocPtr doc, xmlNsPtr ns, const xmlChar *name, const xmlChar *content);
xmlNodePtr xsNewDocText(xmlDocPtr doc, const xmlChar *content);
xmlNodePtr xsNewDocComment(xmlDocPtr doc, const xmlChar *content);
xmlNodePtr xsAddChild(xmlNodePtr parent, xmlNodePtr child);
xmlNodePtr xsAddNextSibling(xmlNodePtr current, xmlNodePtr node);
xmlNodePtr xsAddPrevSibling(xmlNodePtr current, xmlNodePtr node);
void xsUnlinkNode(xmlNodePtr node);
void xsFreeNode(xmlNodePtr node);
xmlNodePtr xsReplaceNode(xmlNodePtr old, xmlNodePtr current);

/* Content and attributes. */
xmlChar *xsNodeGetContent(const xmlNode *node);
int xsNodeSetContent(xmlNodePtr node, const xmlChar *content);
/* Unlike libxml2's, which returns nothing: 0 on success, -1 when refused. */
int xsNodeAddContent(xmlNodePtr node, const xmlChar *content);
xmlChar *xsGetProp(const xmlNode *node, const xmlChar *name);
xmlChar *xsGetNsProp(const xmlNode *node, const xmlChar *name, const xmlChar *href);
xmlAttrPtr xsHasProp(const xmlNode *node, const xmlChar *name);
xmlAttrPtr xsHasNsProp(const xmlNode *node, const xmlChar *name, const xmlChar *href);
xmlAttrPtr xsSetProp(xmlNodePtr node, const xmlChar *name, const xmlChar *value);
xmlAttrPtr xsSetNsProp(xmlNodePtr node, xmlNsPtr ns, const xmlChar *name, const xmlChar *value);
int xsUnsetProp(xmlNodePtr node, const xmlChar *name);

/* Namespaces and IDs. */
xmlNsPtr xsNewNs(xmlNodePtr node, const xmlChar *href, const xmlChar *prefix);
xmlNsPtr xsSearchNs(xmlDocPtr doc, xmlNodePtr node, const xmlChar *prefix);
xmlNsPtr xsSearchNsByHref(xmlDocPtr doc, xmlNodePtr node, const xmlChar *href);
void xsSetNs(xmlNodePtr node, xmlNsPtr ns);
/* Unlike libxml2's: xsAddID returns 0 on success and -1 when refused (not an
 * xmlIDPtr, NULL on failure), and xsGetID returns the element carrying the
 * ID (not its attribute). */
int xsAddID(xmlDocPtr doc, const xmlChar *value, xmlAttrPtr attr);
xmlNodePtr xsGetID(xmlDocPtr doc, const xmlChar *value);

/* Node sets. */
xmlNodeSetPtr xsXPathNodeSetCreate(xmlNodePtr node);
int xsXPathNodeSetAdd(xmlNodeSetPtr set, xmlNodePtr node);
int xsXPathNodeSetAddNs(xmlNodeSetPtr set, xmlNodePtr element, xmlNsPtr ns);
int xsXPathNodeSetContains(const xmlNodeSet *set, const xmlNode *node);
int xsXPathNodeSetGetLength(const xmlNodeSet *set);
xmlNodePtr xsXPathNodeSetItem(const xmlNodeSet *set, int index);
void xsXPathFreeNodeSet(xmlNodeSetPtr set);
int xsXPathCmpNodes(const xmlNode *left, const xmlNode *right);

/* I/O buffers over the caller's callbacks or memory. */
xmlOutputBufferPtr xsOutputBufferCreateIO(xmlOutputWriteCallback write,
                                          xmlOutputCloseCallback close, void *context,
                                          void *encoder);
xmlOutputBufferPtr xsAllocOutputBuffer(void *encoder);
int xsOutputBufferWrite(xmlOutputBufferPtr out, int len, const char *buffer);
int xsOutputBufferWriteString(xmlOutputBufferPtr out, const char *text);
int xsOutputBufferFlush(xmlOutputBufferPtr out);
int xsOutputBufferClose(xmlOutputBufferPtr out);
const xmlChar *xsOutputBufferGetContent(xmlOutputBufferPtr out);
size_t xsOutputBufferGetSize(xmlOutputBufferPtr out);
xmlParserInputBufferPtr xsParserInputBufferCreateIO(xmlInputReadCallback read,
                                                    xmlInputCloseCallback close,
                                                    void *context, int encoding);
int xsParserInputBufferRead(xmlParserInputBufferPtr input, int len);
const xmlChar *xsParserInputBufferGetContent(xmlParserInputBufferPtr input);
size_t xsParserInputBufferGetSize(xmlParserInputBufferPtr input);
void xsFreeParserInputBuffer(xmlParserInputBufferPtr input);

#ifdef __cplusplus
}
#endif

#endif /* XS_TREE_H */
