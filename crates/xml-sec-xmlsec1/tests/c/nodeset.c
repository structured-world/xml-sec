/* Node sets over a libxml2 tree as a libxmlsec1 caller sees them. Built
 * unmodified against the pinned libxmlsec1 and against this crate, both must
 * print the same membership for every node, attribute and namespace node,
 * under every set type and operation, and the same walks and dumps. */

#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/xmltree.h>

static const char document[] =
    "<root xmlns='urn:default' xmlns:a='urn:a' id='r'>"
    "<!--top-->"
    "<a:first attr='1'>text one<inner a:x='2'>deep</inner></a:first>"
    "<second xmlns:b='urn:b'><!--inside-->text two<b:leaf/></second>"
    "</root>";

/* A printable name for any node a walk or set can hold. */
static void describe(xmlNodePtr node, xmlNodePtr parent, char *out, size_t size) {
    if (node->type == XML_NAMESPACE_DECL) {
        xmlNsPtr ns = (xmlNsPtr)node;
        snprintf(out, size, "ns:%s@%s", ns->prefix ? (const char *)ns->prefix : "",
                 parent && parent->name ? (const char *)parent->name : "?");
    } else if (node->type == XML_TEXT_NODE || node->type == XML_COMMENT_NODE) {
        snprintf(out, size, "%s:%s", node->type == XML_TEXT_NODE ? "text" : "comment",
                 node->content ? (const char *)node->content : "");
    } else if (node->type == XML_ATTRIBUTE_NODE) {
        snprintf(out, size, "@%s", (const char *)node->name);
    } else if (node->type == XML_DOCUMENT_NODE) {
        snprintf(out, size, "#document");
    } else {
        snprintf(out, size, "%s", (const char *)node->name);
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

    describe(cur, cur->parent, name, sizeof(name));
    printf(" %s=%d", name, xmlSecNodeSetContains(nset, cur, cur->parent));
    if (cur->type == XML_ELEMENT_NODE) {
        for (attr = cur->properties; attr != NULL; attr = attr->next) {
            describe((xmlNodePtr)attr, cur, name, sizeof(name));
            printf(" %s=%d", name, xmlSecNodeSetContains(nset, (xmlNodePtr)attr, cur));
        }
        for (ns = cur->nsDef; ns != NULL; ns = ns->next) {
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

/* An XPath result over `doc`, given up to the node set. */
static xmlNodeSetPtr select_nodes(xmlDocPtr doc, const char *expression) {
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodes;

    xmlXPathRegisterNs(ctx, BAD_CAST "d", BAD_CAST "urn:default");
    xmlXPathRegisterNs(ctx, BAD_CAST "a", BAD_CAST "urn:a");
    xmlXPathRegisterNs(ctx, BAD_CAST "b", BAD_CAST "urn:b");
    result = xmlXPathEvalExpression(BAD_CAST expression, ctx);
    nodes = result->nodesetval;
    result->nodesetval = NULL;
    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return nodes;
}

static xmlNodePtr find(xmlDocPtr doc, const char *name, const char *ns) {
    return xmlSecFindNode(xmlDocGetRootElement(doc), BAD_CAST name, BAD_CAST ns);
}

int main(void) {
    static const char *types[] = {
        "normal", "invert", "tree", "tree-without-comments", "tree-invert",
        "tree-without-comments-invert",
    };
    xmlDocPtr doc = xmlReadMemory(document, (int)strlen(document), "doc.xml", NULL, 0);
    xmlSecNodeSetPtr nset;
    xmlSecNodeSetPtr other;
    xmlOutputBufferPtr out;
    int type;

    /* Every type over one XPath result holding elements, an attribute, a
     * namespace node and text. */
    for (type = xmlSecNodeSetNormal; type <= xmlSecNodeSetTreeWithoutCommentsInvert; ++type) {
        nset = xmlSecNodeSetCreate(doc,
            select_nodes(doc, "//a:first | //@attr | //d:second/namespace::b | //d:inner/text()"),
            (xmlSecNodeSetType)type);
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
    other = xmlSecNodeSetCreate(doc, select_nodes(doc, "//d:inner"), xmlSecNodeSetTree);
    xmlSecNodeSetAdd(nset, other, xmlSecNodeSetUnion);
    contains("plus inner", doc, nset);
    other = xmlSecNodeSetCreate(doc, select_nodes(doc, "//text()"), xmlSecNodeSetNormal);
    xmlSecNodeSetAdd(nset, other, xmlSecNodeSetSubtraction);
    contains("minus text", doc, nset);
    walk("minus text", nset);

    out = xmlAllocOutputBuffer(NULL);
    printf("dump text: %d", xmlSecNodeSetDumpTextNodes(nset, out));
    xmlOutputBufferFlush(out);
    printf(" [%.*s]\n", (int)xmlOutputBufferGetSize(out), (const char *)xmlOutputBufferGetContent(out));
    xmlOutputBufferClose(out);
    xmlSecNodeSetDestroy(nset);

    nset = xmlSecNodeSetCreate(doc, select_nodes(doc, "//d:second | //d:second/namespace::*"), xmlSecNodeSetNormal);
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
