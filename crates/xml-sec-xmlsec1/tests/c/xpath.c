/* The XPath, XPath Filter 2.0, XPointer and Visa3D transforms as a
 * libxmlsec1 caller uses them: read from transform elements, and created by
 * a context for a same-document URI. Built against the pinned libxmlsec1
 * and against this crate, both must print the same canonical results and
 * statuses. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transforms.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/buffer.h>

#define DSIG "http://www.w3.org/2000/09/xmldsig#"
#define TRANSFORM(alg) "<ds:Transform Algorithm='" alg "'>"
#define XPATH_ALG "http://www.w3.org/TR/1999/REC-xpath-19991116"
#define XPATH2_ALG "http://www.w3.org/2002/06/xmldsig-filter2"
#define XPTR_ALG "http://www.w3.org/2001/04/xmldsig-more/xptr"
#define EXC_C14N "<ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>"

static const char document[] =
    "<root xmlns='urn:t' xmlns:t='urn:t' xmlns:a='urn:a'>"
    "<!--c-->"
    "<item xml:id='k' a:x='1'>keep<sub>me</sub></item>"
    "<other>drop</other>"
    "<ds:Signature xmlns:ds='" DSIG "'>"
    /* an XMLDSig XPath filter with a prefix bound on an ancestor */
    "<g1>" TRANSFORM(XPATH_ALG)
    "<ds:XPath xmlns:b='urn:a'>not(ancestor-or-self::ds:Signature) and (self::t:item or ancestor::t:item or self::b:*)</ds:XPath>"
    "</ds:Transform>" EXC_C14N "</g1>"
    /* Filter 2.0: intersect, subtract, union */
    "<g2>" TRANSFORM(XPATH2_ALG)
    "<f:XPath xmlns:f='" XPATH2_ALG "' Filter='intersect'>//t:item</f:XPath>"
    "<f:XPath xmlns:f='" XPATH2_ALG "' Filter='subtract'>//t:sub</f:XPath>"
    "<f:XPath xmlns:f='" XPATH2_ALG "' Filter='union'>//t:other</f:XPath>"
    "</ds:Transform>" EXC_C14N "</g2>"
    /* an unknown Filter operation */
    "<g3>" TRANSFORM(XPATH2_ALG)
    "<f:XPath xmlns:f='" XPATH2_ALG "' Filter='xor'>//t:item</f:XPath>"
    "</ds:Transform></g3>"
    /* an XPointer transform */
    "<g4>" TRANSFORM(XPTR_ALG)
    "<x:XPointer xmlns:x='" XPTR_ALG "'>xpointer(id('k'))</x:XPointer>"
    "</ds:Transform>" EXC_C14N "</g4>"
    /* here(): everything outside the Signature holding the expression */
    "<g5>" TRANSFORM(XPATH_ALG)
    "<ds:XPath>count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) &gt; count(ancestor-or-self::ds:Signature)</ds:XPath>"
    "</ds:Transform>" EXC_C14N "</g5>"
    /* an XPath transform without its XPath element */
    "<g6>" TRANSFORM(XPATH_ALG) "<ds:Other/></ds:Transform></g6>"
    "</ds:Signature>"
    "</root>";

static void result(const char *label, xmlSecTransformCtxPtr ctx, int ret) {
    printf("%s: ret=%d status=%d", label, ret, ctx->status);
    if (ctx->result != NULL) {
        printf(" [%.*s]", (int)xmlSecBufferGetSize(ctx->result), (const char *)xmlSecBufferGetData(ctx->result));
    }
    printf("\n");
}

/* Reads the transforms of group `name` and runs them over the document. */
static void group(xmlDocPtr doc, const char *name) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlNodePtr node = xmlSecFindNode(xsDocGetRootElement(doc), BAD_CAST name, BAD_CAST "urn:t");
    xmlSecNodeSetPtr nodes;
    int ret = xmlSecTransformCtxNodesListRead(ctx, node, xmlSecTransformUsageDSigTransform);
    printf("%s read: %d\n", name, ret);
    if (ret == 0) {
        nodes = xmlSecNodeSetGetChildren(doc, NULL, 1, 0);
        ret = xmlSecTransformCtxXmlExecute(ctx, nodes);
        result(name, ctx, ret);
        xmlSecNodeSetDestroy(nodes);
    }
    xmlSecTransformCtxDestroy(ctx);
}

/* Selects `uri` in the document, as a Reference does, and canonicalizes. */
static void uri(xmlDocPtr doc, const char *uri, unsigned int flags) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    int ret;
    ctx->flags = flags;
    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, xsDocGetRootElement(doc));
    printf("%s set: %d first=%s\n", uri, ret,
           ctx->first != NULL ? (const char *)xmlSecTransformGetName(ctx->first) : "none");
    if (ret == 0) {
        xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformExclC14NId);
        ret = xmlSecTransformCtxExecute(ctx, doc);
        result(uri, ctx, ret);
    }
    xmlSecTransformCtxDestroy(ctx);
}

int main(void) {
    xmlDocPtr doc = xsReadMemory(document, (int)strlen(document), "doc.xml", NULL, 0);
    xmlNodePtr root = xsDocGetRootElement(doc);
    xmlSecTransformPtr transform;

    printf("ids init: %d\n", xmlSecTransformIdsInit());
    group(doc, "g1");
    group(doc, "g2");
    group(doc, "g3");
    group(doc, "g4");
    group(doc, "g5");
    group(doc, "g6");

    uri(doc, "#xpointer(id('k'))", 0);
    uri(doc, "#k", 0);
    uri(doc, "#xmlns(p=urn:t)xpointer(//p:other)", 0);
    uri(doc, "#xpointer(//t:sub)", 0);
    uri(doc, "#xpointer(//t:nothing)", 0);
    uri(doc, "#absent", 0);
    uri(doc, "#k", XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK);
    uri(doc, "#missing", XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK);

    transform = xmlSecTransformCreate(xmlSecTransformXPathId);
    printf("set expr on xpath: %d\n",
           xmlSecTransformXPointerSetExpr(transform, BAD_CAST "xpointer(/)", xmlSecNodeSetTree,
                                          root));
    xmlSecTransformDestroy(transform);
    transform = xmlSecTransformCreate(xmlSecTransformXPointerId);
    printf("set expr: %d again: %d\n",
           xmlSecTransformXPointerSetExpr(transform, BAD_CAST "xpointer(/)", xmlSecNodeSetTree,
                                          root),
           xmlSecTransformXPointerSetExpr(transform, BAD_CAST "xpointer(/)", xmlSecNodeSetTree,
                                          root));
    xmlSecTransformDestroy(transform);
    transform = xmlSecTransformCreate(xmlSecTransformVisa3DHackId);
    printf("set id: %d again: %d\n", xmlSecTransformVisa3DHackSetID(transform, BAD_CAST "k"),
           xmlSecTransformVisa3DHackSetID(transform, BAD_CAST "k"));
    xmlSecTransformDestroy(transform);

    printf("object sizes: %d %d %d %d\n",
           xmlSecTransformXPathId->objSize > sizeof(xmlSecTransform),
           xmlSecTransformXPath2Id->objSize == xmlSecTransformXPathId->objSize,
           xmlSecTransformXPointerId->objSize == xmlSecTransformXPathId->objSize,
           xmlSecTransformVisa3DHackId->objSize == sizeof(xmlSecTransform) + sizeof(void *));

    xmlSecTransformIdsShutdown();
    xsFreeDoc(doc);
    printf("done\n");
    return 0;
}
