/* The parser functions, the XML parser transform in both directions, and
 * the OPC Relationship transform, as a libxmlsec1 caller uses them. Built
 * against the pinned libxmlsec1 and against this crate, both must print the
 * same documents, results and statuses. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/parser.h>
#include <xmlsec/transforms.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/buffer.h>

static void doc_line(const char *label, xmlDocPtr doc) {
    xmlChar *text = NULL;
    int size = 0;
    if (doc == NULL) {
        printf("%s: none\n", label);
        return;
    }
    xsDocDumpMemory(doc, &text, &size);
    printf("%s: %.*s", label, size, (const char *)text);
    xsFree(text);
    xsFreeDoc(doc);
}

static void result(const char *label, xmlSecTransformCtxPtr ctx, int ret) {
    printf("%s: ret=%d status=%d", label, ret, ctx->status);
    if (ctx->result != NULL) {
        printf(" [%.*s]", (int)xmlSecBufferGetSize(ctx->result), (const char *)xmlSecBufferGetData(ctx->result));
    }
    printf("\n");
}

static const char rels[] =
    "<?xml version='1.0'?>"
    "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>"
    "<Relationship Id='rId3' Type='urn:t:c' Target='c.xml'/>"
    "<Relationship Id='rId1' Type='urn:t:a' Target='a.xml' TargetMode='External'/>"
    "<Relationship Id='rId2' Type='urn:t:b' Target='b.xml'/>"
    "</Relationships>";

static const char transforms[] =
    "<t:Transforms xmlns:t='http://www.w3.org/2000/09/xmldsig#'>"
    "<t:Transform Algorithm='http://schemas.openxmlformats.org/package/2006/RelationshipTransform'>"
    "<r:RelationshipReference xmlns:r='http://schemas.openxmlformats.org/package/2006/digital-signature' SourceId='rId3'/>"
    "<r:RelationshipReference xmlns:r='http://schemas.openxmlformats.org/package/2006/digital-signature' SourceId='rId1'/>"
    "</t:Transform>"
    "<t:Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'/>"
    "</t:Transforms>";

int main(void) {
    const char *good = "<a x='1'><b>t</b></a>";
    const char *bad = "<a><b></a>";
    xmlSecTransformCtxPtr ctx;
    xmlSecTransformPtr left;
    xmlSecTransformPtr parser;
    xmlSecNodeSetPtr nodes = NULL;
    xmlDocPtr relsDoc;
    xmlDocPtr transformsDoc;
    xmlChar *name;
    int ret;
    int options = xmlSecParserGetDefaultOptions();

    printf("ids init: %d\n", xmlSecTransformIdsInit());
    /* libxml2's XML_PARSE_NONET, part of libxmlsec1's default options. */
    printf("options nonet: %d\n", (options & (1 << 11)) != 0);

    /* A malformed document parsed with recovery is left out: libxml2
     * recovers a tree, the core parser refuses the document. */
    doc_line("memory", xmlSecParseMemory(BAD_CAST good, strlen(good), 0));
    doc_line("malformed", xmlSecParseMemory(BAD_CAST bad, strlen(bad), 0));
    doc_line("three chunks", xmlSecParseMemoryExt(BAD_CAST "<a>", 3, BAD_CAST "<b/>", 4, BAD_CAST "</a>", 4));
    doc_line("three chunks malformed", xmlSecParseMemoryExt(BAD_CAST "<a>", 3, NULL, 0, BAD_CAST "</b>", 4));

    /* binary into a node-set transform: the parser adapter appears */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformBase64Id);
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformInclC14NId);
    ctx->binaryChunkSize = 5;
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "PGEgeD0nMSc+PGIvPjwvYT4=", 24);
    result("base64-parse-c14n", ctx, ret);
    printf("adapter: %s\n", ctx->first->next != NULL ? (const char *)xmlSecTransformGetName(ctx->first->next) : "none");
    xmlSecTransformCtxDestroy(ctx);

    /* malformed octets fail the parser */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformXmlParserId);
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformInclC14NId);
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST bad, strlen(bad));
    result("malformed parse", ctx, ret);
    xmlSecTransformCtxDestroy(ctx);

    /* the pop side: the parser reads everything its predecessor pops */
    {
        xmlSecTransformCtx popCtx;
        xmlSecTransformCtxInitialize(&popCtx);
        left = xmlSecTransformCreate(xmlSecTransformBase64Id);
        parser = xmlSecTransformCreate(xmlSecTransformXmlParserId);
        xmlSecBufferSetData(&(left->inBuf), BAD_CAST "PGEgeD0nMSc+PGIvPjwvYT4=", 24);
        left->next = parser;
        parser->prev = left;
        ret = xmlSecTransformPopXml(parser, &nodes, &popCtx);
        name = nodes != NULL && nodes->doc != NULL ? xsNodeGetName(xsDocGetRootElement(nodes->doc)) : NULL;
        printf("pop xml: %d status=%d root=%s\n", ret, parser->status,
               name != NULL ? (const char *)name : "none");
        xsFree(name);
        if (nodes != NULL) {
            xmlSecNodeSetDestroy(nodes);
        }
        nodes = NULL;
        ret = xmlSecTransformPopXml(parser, &nodes, &popCtx);
        printf("pop again: %d nodes=%s\n", ret, nodes == NULL ? "none" : "some");
        if (nodes != NULL) {
            xmlSecNodeSetDestroy(nodes);
        }
        left->next = NULL;
        parser->prev = NULL;
        xmlSecTransformDestroy(left);
        xmlSecTransformDestroy(parser);
        xmlSecTransformCtxFinalize(&popCtx);
    }

    /* the OPC relationship transform, read from its element */
    relsDoc = xsReadMemory(rels, (int)strlen(rels), "rels.xml", NULL, 0);
    transformsDoc = xsReadMemory(transforms, (int)strlen(transforms), "t.xml", NULL, 0);
    ctx = xmlSecTransformCtxCreate();
    ret = xmlSecTransformCtxNodesListRead(ctx, xsDocGetRootElement(transformsDoc), xmlSecTransformUsageDSigTransform);
    printf("relationship read: %d\n", ret);
    nodes = xmlSecNodeSetGetChildren(relsDoc, NULL, 1, 0);
    ret = xmlSecTransformCtxXmlExecute(ctx, nodes);
    result("relationship", ctx, ret);
    xmlSecNodeSetDestroy(nodes);
    xmlSecTransformCtxDestroy(ctx);

    printf("object sizes: %d %d\n",
           xmlSecTransformXmlParserId->objSize == sizeof(xmlSecTransform) + sizeof(void *),
           xmlSecTransformRelationshipId->objSize == sizeof(xmlSecTransform) + sizeof(void *));

    xsFreeDoc(relsDoc);
    xsFreeDoc(transformsDoc);
    xmlSecTransformIdsShutdown();
    printf("done\n");
    return 0;
}
