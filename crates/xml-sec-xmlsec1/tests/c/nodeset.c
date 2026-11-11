/* Node sets over a document tree as a libxmlsec1 caller sees them. Built
 * against the pinned libxmlsec1 and against this crate, both must print the
 * same membership for every node, attribute and namespace node, under every
 * set type and operation, and the same walks and dumps. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/xmltree.h>

static const char document[] =
    "<root xmlns='urn:default' xmlns:a='urn:a' id='r'>"
    "<!--top-->"
    "<a:first attr='1'>text one<inner a:x='2'>deep</inner></a:first>"
    "<second xmlns:b='urn:b'><!--inside-->text two<b:leaf/></second>"
    "</root>";

/* Prints `text` and releases it. */
static const char *shown(xmlChar *text, char *out, size_t size) {
    snprintf(out, size, "%s", text != NULL ? (const char *)text : "");
    xsFree(text);
    return out;
}

/* A printable name for any node a walk or set can hold. */
static void describe(xmlNodePtr node, xmlNodePtr parent, char *out, size_t size) {
    char first[64];
    char second[64];
    int type = xsNodeGetType(node);
    if (type == XML_NAMESPACE_DECL) {
        snprintf(out, size, "ns:%s@%s", shown(xsNsGetPrefix((xmlNsPtr)node), first, sizeof(first)),
                 parent != NULL ? shown(xsNodeGetName(parent), second, sizeof(second)) : "?");
    } else if (type == XML_TEXT_NODE || type == XML_COMMENT_NODE) {
        snprintf(out, size, "%s:%s", type == XML_TEXT_NODE ? "text" : "comment",
                 shown(xsNodeGetContent(node), first, sizeof(first)));
    } else if (type == XML_ATTRIBUTE_NODE) {
        snprintf(out, size, "@%s", shown(xsNodeGetName(node), first, sizeof(first)));
    } else if (type == XML_DOCUMENT_NODE) {
        snprintf(out, size, "#document");
    } else {
        snprintf(out, size, "%s", shown(xsNodeGetName(node), first, sizeof(first)));
    }
}

static int print_member(xmlSecNodeSetPtr nset, xmlNodePtr cur, xmlNodePtr parent, void *data) {
    char name[128];
    (void)nset;
    (void)data;
    describe(cur, parent, name, sizeof(name));
    printf(" %s", name);
    return 0;
}

/* The members of `nset` in document order, by walking it. */
static void walk(const char *label, xmlSecNodeSetPtr nset) {
    printf("%s:", label);
    printf(" ret=%d", xmlSecNodeSetWalk(nset, print_member, NULL));
    printf("\n");
}

/* Membership of every node of the document, checked directly. */
static int check_member(xmlNodePtr cur, void *data) {
    xmlSecNodeSetPtr nset = (xmlSecNodeSetPtr)data;
    char name[128];
    xmlAttrPtr attr;
    xmlNsPtr ns;
    xmlNodePtr parent = xsNodeGetParent(cur);

    describe(cur, parent, name, sizeof(name));
    printf(" %s=%d", name, xmlSecNodeSetContains(nset, cur, parent));
    if (xsNodeGetType(cur) == XML_ELEMENT_NODE) {
        for (attr = xsNodeGetProperties(cur); attr != NULL; attr = xsAttrGetNext(attr)) {
            describe((xmlNodePtr)attr, cur, name, sizeof(name));
            printf(" %s=%d", name, xmlSecNodeSetContains(nset, (xmlNodePtr)attr, cur));
        }
        for (ns = xsNodeGetNsDef(cur); ns != NULL; ns = xsNsGetNext(ns)) {
            describe((xmlNodePtr)ns, cur, name, sizeof(name));
            printf(" %s=%d", name, xmlSecNodeSetContains(nset, (xmlNodePtr)ns, cur));
        }
    }
    return 1;
}

static void contains(const char *label, xmlDocPtr doc, xmlSecNodeSetPtr nset) {
    printf("%s:", label);
    printf(" ret=%d", xmlSecDepthFirstTreeWalk((xmlNodePtr)doc, check_member, nset));
    printf("\n");
}

static xmlNodePtr find(xmlDocPtr doc, const char *name, const char *ns) {
    return xmlSecFindNode(xsDocGetRootElement(doc), BAD_CAST name, BAD_CAST ns);
}

/* The first child of `node` of type `type`. */
static xmlNodePtr child_of_type(xmlNodePtr node, int type) {
    xmlNodePtr child;
    for (child = xsNodeGetChildren(node); child != NULL; child = xsNodeGetNext(child)) {
        if (xsNodeGetType(child) == type) {
            return child;
        }
    }
    return NULL;
}

/* Adds every text node the walk visits to the node set in `data`. */
static int add_text(xmlNodePtr cur, void *data) {
    if (xsNodeGetType(cur) == XML_TEXT_NODE) {
        xsXPathNodeSetAdd((xmlNodeSetPtr)data, cur);
    }
    return 1;
}

/* An element, an attribute, a namespace node and text, none inside
 * another's subtree, listed in document order as an XPath result is
 * (libxmlsec1 walks a list in its own order). */
static xmlNodeSetPtr mixed_nodes(xmlDocPtr doc) {
    xmlNodePtr first = find(doc, "first", "urn:a");
    xmlNodePtr second = find(doc, "second", "urn:default");
    xmlNodeSetPtr nodes = xsXPathNodeSetCreate((xmlNodePtr)xsNodeGetProperties(first));
    xsXPathNodeSetAdd(nodes, find(doc, "inner", "urn:default"));
    xsXPathNodeSetAddNs(nodes, second, xsSearchNs(doc, second, BAD_CAST "b"));
    xsXPathNodeSetAdd(nodes, child_of_type(second, XML_TEXT_NODE));
    return nodes;
}

int main(void) {
    static const char *types[] = {
        "normal", "invert", "tree", "tree-without-comments", "tree-invert",
        "tree-without-comments-invert",
    };
    xmlDocPtr doc = xsReadMemory(document, (int)strlen(document), "doc.xml", NULL, 0);
    xmlSecNodeSetPtr nset;
    xmlSecNodeSetPtr other;
    xmlOutputBufferPtr out;
    xmlNodeSetPtr nodes;
    xmlNodePtr second;
    int type;

    /* Every type over one node list holding an element, an attribute, a
     * namespace node and text, none inside another's subtree: where listed
     * subtrees nest, libxmlsec1 walks the nested nodes again, and this
     * library visits each node once as the walk's contract states. */
    for (type = xmlSecNodeSetNormal; type <= xmlSecNodeSetTreeWithoutCommentsInvert; ++type) {
        nset = xmlSecNodeSetCreate(doc, mixed_nodes(doc), (xmlSecNodeSetType)type);
        contains(types[type], doc, nset);
        walk(types[type], nset);
        xmlSecNodeSetDestroy(nset);
    }

    /* Subtrees from GetChildren with and without comments and inverted. */
    nset = xmlSecNodeSetGetChildren(doc, find(doc, "second", "urn:default"), 0, 0);
    contains("children of second", doc, nset);
    walk("children of second", nset);
    xmlSecNodeSetDestroy(nset);
    nset = xmlSecNodeSetGetChildren(doc, find(doc, "second", "urn:default"), 1, 1);
    contains("all but second", doc, nset);
    xmlSecNodeSetDestroy(nset);
    nset = xmlSecNodeSetGetChildren(doc, NULL, 0, 0);
    contains("document without comments", doc, nset);
    walk("document without comments", nset);

    /* Operations: the enveloped-signature shape and a union back. */
    other = xmlSecNodeSetGetChildren(doc, find(doc, "first", "urn:a"), 1, 1);
    printf("add: %s\n", xmlSecNodeSetAdd(nset, other, xmlSecNodeSetIntersection) == nset ? "same" : "other");
    contains("document minus first", doc, nset);
    other = xmlSecNodeSetCreate(doc, xsXPathNodeSetCreate(find(doc, "inner", "urn:default")),
                                xmlSecNodeSetTree);
    xmlSecNodeSetAdd(nset, other, xmlSecNodeSetUnion);
    contains("plus inner", doc, nset);
    nodes = xsXPathNodeSetCreate(NULL);
    xmlSecDepthFirstTreeWalk((xmlNodePtr)doc, add_text, nodes);
    other = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetNormal);
    xmlSecNodeSetAdd(nset, other, xmlSecNodeSetSubtraction);
    contains("minus text", doc, nset);
    walk("minus text", nset);

    out = xsAllocOutputBuffer(NULL);
    printf("dump text: %d", xmlSecNodeSetDumpTextNodes(nset, out));
    xsOutputBufferFlush(out);
    printf(" [%.*s]\n", (int)xsOutputBufferGetSize(out), (const char *)xsOutputBufferGetContent(out));
    xsOutputBufferClose(out);
    xmlSecNodeSetDestroy(nset);

    /* An element and the namespace nodes its own declarations make. */
    second = find(doc, "second", "urn:default");
    nodes = xsXPathNodeSetCreate(second);
    xsXPathNodeSetAddNs(nodes, second, xsSearchNs(doc, second, BAD_CAST "b"));
    xsXPathNodeSetAddNs(nodes, second, xsSearchNs(doc, second, BAD_CAST "a"));
    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetNormal);
    fflush(stdout);
    xmlSecNodeSetDebugDump(nset, stdout);
    fflush(stdout);
    xmlSecNodeSetDestroy(nset);

    /* A set told to destroy its document frees it with itself. */
    nset = xmlSecNodeSetGetChildren(doc, NULL, 1, 0);
    xmlSecNodeSetDocDestroy(nset);
    xmlSecNodeSetDestroy(nset);
    printf("done\n");
    return 0;
}
