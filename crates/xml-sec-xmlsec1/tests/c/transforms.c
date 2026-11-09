/* Transform chains as a libxmlsec1 caller builds them, with representative
 * extension klasses: an octet transform written on the default push/pop
 * methods, one with its own push method, and a node-set transform. Built
 * unmodified against the pinned libxmlsec1 and against this crate, both must
 * print the same results, statuses, adapters and callback observations. */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transforms.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/buffer.h>
#include <xmlsec/membuf.h>

/* ---- an octet klass on the default methods: upper-cases ASCII ---- */
static int upper_execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr ctx) {
    xmlSecBufferPtr in = &(transform->inBuf);
    xmlSecBufferPtr out = &(transform->outBuf);
    xmlSecSize size = xmlSecBufferGetSize(in);
    xmlSecSize ii;
    (void)ctx;

    if (transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }
    if (size > 0) {
        if (xmlSecBufferAppend(out, xmlSecBufferGetData(in), size) < 0) {
            return -1;
        }
        for (ii = xmlSecBufferGetSize(out) - size; ii < xmlSecBufferGetSize(out); ++ii) {
            xmlSecBufferGetData(out)[ii] = (xmlSecByte)toupper(xmlSecBufferGetData(out)[ii]);
        }
        xmlSecBufferRemoveHead(in, size);
    }
    if (last) {
        transform->status = xmlSecTransformStatusFinished;
    }
    return 0;
}

static xmlSecTransformKlass upperKlass = {
    sizeof(xmlSecTransformKlass), sizeof(xmlSecTransform),
    BAD_CAST "upper", BAD_CAST "urn:test:upper", xmlSecTransformUsageDSigTransform,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    xmlSecTransformDefaultGetDataType,
    xmlSecTransformDefaultPushBin, xmlSecTransformDefaultPopBin, NULL, NULL,
    upper_execute, NULL, NULL,
};

/* ---- a klass with its own push: reverses all data at the final call ---- */
typedef struct { xmlSecTransform base; int pushes; } ReverseTransform;

static int reverse_push(xmlSecTransformPtr transform, const xmlSecByte *data, xmlSecSize size,
                        int final, xmlSecTransformCtxPtr ctx) {
    ReverseTransform *self = (ReverseTransform *)transform;
    ++self->pushes;
    if (size > 0 && xmlSecBufferAppend(&(transform->inBuf), data, size) < 0) {
        return -1;
    }
    if (!final) {
        return 0;
    }
    xmlSecBufferReverse(&(transform->inBuf));
    printf("reverse: %d pushes, " XMLSEC_SIZE_FMT " bytes\n", self->pushes, xmlSecBufferGetSize(&(transform->inBuf)));
    transform->status = xmlSecTransformStatusFinished;
    if (transform->next != NULL) {
        return xmlSecTransformPushBin(transform->next, xmlSecBufferGetData(&(transform->inBuf)),
                                      xmlSecBufferGetSize(&(transform->inBuf)), 1, ctx);
    }
    return 0;
}

static xmlSecTransformKlass reverseKlass = {
    sizeof(xmlSecTransformKlass), sizeof(ReverseTransform),
    BAD_CAST "reverse", NULL, xmlSecTransformUsageDSigTransform,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    xmlSecTransformDefaultGetDataType,
    reverse_push, xmlSecTransformDefaultPopBin, NULL, NULL, NULL, NULL, NULL,
};

/* ---- a node-set klass: keeps only elements named "keep" and their text ---- */
static int keep_execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr ctx) {
    xmlNodePtr root;
    xmlSecNodeSetPtr keep;
    (void)last;
    (void)ctx;

    if (transform->inNodes == NULL) {
        return -1;
    }
    root = xmlDocGetRootElement(transform->inNodes->doc);
    keep = xmlSecNodeSetGetChildren(transform->inNodes->doc,
                                    xmlSecFindNode(root, BAD_CAST "keep", BAD_CAST "urn:t"), 0, 0);
    transform->outNodes = xmlSecNodeSetAdd(transform->inNodes, keep, xmlSecNodeSetIntersection);
    return transform->outNodes != NULL ? 0 : -1;
}

static xmlSecTransformKlass keepKlass = {
    sizeof(xmlSecTransformKlass), sizeof(xmlSecTransform),
    BAD_CAST "keep", BAD_CAST "urn:test:keep", xmlSecTransformUsageDSigTransform,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    xmlSecTransformDefaultGetDataType,
    NULL, NULL, xmlSecTransformDefaultPushXml, xmlSecTransformDefaultPopXml,
    keep_execute, NULL, NULL,
};

static void chain(const char *label, xmlSecTransformCtxPtr ctx) {
    xmlSecTransformPtr transform;
    printf("%s chain:", label);
    for (transform = ctx->first; transform != NULL; transform = transform->next) {
        printf(" %s(%d)", xmlSecTransformGetName(transform), transform->status);
    }
    printf("\n");
}

static void result(const char *label, xmlSecTransformCtxPtr ctx, int ret) {
    printf("%s: ret=%d status=%d", label, ret, ctx->status);
    if (ctx->result != NULL) {
        printf(" [%.*s]", (int)xmlSecBufferGetSize(ctx->result), (const char *)xmlSecBufferGetData(ctx->result));
    }
    printf("\n");
    chain(label, ctx);
}

static int observed = 0;
static int pre_execute(xmlSecTransformCtxPtr ctx) {
    ++observed;
    chain("pre-execute", ctx);
    return ((int *)ctx->userData != NULL && *(int *)ctx->userData) ? -1 : 0;
}

/* A callback that reenters the library: it runs another context to the end,
 * then tries to execute the context that is running it. */
static int reentrant(xmlSecTransformCtxPtr ctx) {
    xmlSecTransformCtxPtr nested = xmlSecTransformCtxCreate();
    int ret;
    xmlSecTransformCtxCreateAndAppend(nested, &upperKlass);
    ret = xmlSecTransformCtxBinaryExecute(nested, BAD_CAST "in", 2);
    printf("nested: ret=%d [%.*s]\n", ret, (int)xmlSecBufferGetSize(nested->result),
           (const char *)xmlSecBufferGetData(nested->result));
    xmlSecTransformCtxDestroy(nested);
    printf("running again: %d\n", xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "x", 1));
    return 0;
}

static const char document[] =
    "<root xmlns='urn:t' xmlns:a='urn:a'>"
    "<!--c-->"
    "<keep a:x='1'>Zm9v<b>YmFy</b></keep>"
    "<drop>dropped</drop>"
    "<t:Transforms xmlns:t='http://www.w3.org/2000/09/xmldsig#'>"
    "<t:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'>"
    "<ec:InclusiveNamespaces xmlns:ec='http://www.w3.org/2001/10/xml-exc-c14n#' PrefixList='a #default'/>"
    "</t:Transform>"
    "<t:Transform Algorithm='urn:test:upper'/>"
    "</t:Transforms>"
    "</root>";

int main(void) {
    xmlDocPtr doc = xmlReadMemory(document, (int)strlen(document), "doc.xml", NULL, 0);
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlSecTransformCtxPtr ctx;
    xmlSecTransformPtr transform;
    xmlSecNodeSetPtr nodes;
    xmlSecTransformCtx local;
    int abort_run = 1;
    int ret;

    printf("ids init: %d\n", xmlSecTransformIdsInit());
    printf("register upper: %d keep: %d\n",
           xmlSecTransformIdsRegister(&upperKlass), xmlSecTransformIdsRegister(&keepKlass));
    printf("find upper: %s\n",
           xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), BAD_CAST "urn:test:upper",
                                           xmlSecTransformUsageDSigTransform) == &upperKlass ? "yes" : "no");
    printf("uri types: %d %d %d %d\n",
           xmlSecTransformUriTypeCheck(xmlSecTransformUriTypeEmpty, NULL),
           xmlSecTransformUriTypeCheck(xmlSecTransformUriTypeSameDocument, BAD_CAST "#x"),
           xmlSecTransformUriTypeCheck(xmlSecTransformUriTypeLocal, BAD_CAST "file:///x"),
           xmlSecTransformUriTypeCheck(xmlSecTransformUriTypeLocal, BAD_CAST "http://x"));

    /* binary: decode, upper-case, encode */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformBase64Id);
    xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass);
    transform = xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformBase64Id);
    transform->operation = xmlSecTransformOperationEncode;
    ctx->binaryChunkSize = 3;
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "Zm9vYmFy", 8);
    result("decode-upper-encode", ctx, ret);
    printf("executing again: %d\n", xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "Zg==", 4));
    xmlSecTransformCtxDestroy(ctx);

    /* binary through a klass with its own push */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, &reverseKlass);
    xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass);
    ctx->binaryChunkSize = 2;
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "abcdef", 6);
    result("reverse-upper", ctx, ret);
    xmlSecTransformCtxDestroy(ctx);

    /* a klass without binary output cannot precede a binary one */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, &keepKlass);
    printf("keep before upper: %s\n",
           xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass) != NULL ? "connected" : "refused");
    chain("keep before upper", ctx);
    xmlSecTransformCtxDestroy(ctx);

    /* pre-execute callback: observes the prepared chain, then aborts it */
    ctx = xmlSecTransformCtxCreate();
    ctx->preExecCallback = pre_execute;
    xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass);
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "ok", 2);
    result("callback", ctx, ret);
    xmlSecTransformCtxReset(ctx);
    ctx->userData = &abort_run;
    xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass);
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "no", 2);
    result("callback abort", ctx, ret);
    printf("callbacks: %d\n", observed);
    xmlSecTransformCtxDestroy(ctx);

    /* a callback that reenters the library */
    ctx = xmlSecTransformCtxCreate();
    ctx->preExecCallback = reentrant;
    xmlSecTransformCtxCreateAndAppend(ctx, &upperKlass);
    ret = xmlSecTransformCtxBinaryExecute(ctx, BAD_CAST "out", 3);
    result("reentrant", ctx, ret);
    xmlSecTransformCtxDestroy(ctx);

    /* XML input into a binary klass: inclusive C14N is prepended */
    xmlSecTransformCtxInitialize(&local);
    xmlSecTransformCtxCreateAndAppend(&local, &upperKlass);
    nodes = xmlSecNodeSetGetChildren(doc, xmlSecFindNode(root, BAD_CAST "keep", BAD_CAST "urn:t"), 1, 0);
    ret = xmlSecTransformCtxXmlExecute(&local, nodes);
    result("xml into binary", &local, ret);
    xmlSecNodeSetDestroy(nodes);
    xmlSecTransformCtxFinalize(&local);

    /* a node-set klass before Base64: the tag-removing adapter appears */
    ctx = xmlSecTransformCtxCreate();
    xmlSecTransformCtxCreateAndAppend(ctx, &keepKlass);
    xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformBase64Id);
    ret = xmlSecTransformCtxExecute(ctx, doc);
    result("keep-base64", ctx, ret);
    xmlSecTransformCtxDestroy(ctx);

    /* each canonicalization over the whole document */
    {
        xmlSecTransformId ids[6];
        int ii;
        ids[0] = xmlSecTransformInclC14NId;
        ids[1] = xmlSecTransformInclC14NWithCommentsId;
        ids[2] = xmlSecTransformInclC14N11Id;
        ids[3] = xmlSecTransformInclC14N11WithCommentsId;
        ids[4] = xmlSecTransformExclC14NId;
        ids[5] = xmlSecTransformExclC14NWithCommentsId;
        for (ii = 0; ii < 6; ++ii) {
            ctx = xmlSecTransformCtxCreate();
            xmlSecTransformCtxCreateAndAppend(ctx, ids[ii]);
            nodes = xmlSecNodeSetGetChildren(doc, NULL, 1, 0);
            ret = xmlSecTransformCtxXmlExecute(ctx, nodes);
            result((const char *)xmlSecTransformKlassGetName(ids[ii]), ctx, ret);
            xmlSecNodeSetDestroy(nodes);
            xmlSecTransformCtxDestroy(ctx);
        }
    }

    /* transforms read from the document, with a prefix list and a
     * registered extension; the subtree of keep only */
    ctx = xmlSecTransformCtxCreate();
    ret = xmlSecTransformCtxNodesListRead(ctx,
        xmlSecFindNode(root, BAD_CAST "Transforms", BAD_CAST "http://www.w3.org/2000/09/xmldsig#"),
        xmlSecTransformUsageDSigTransform);
    printf("nodes list read: %d flags=%d\n", ret, ctx->first != NULL ? (int)ctx->first->flags : -1);
    nodes = xmlSecNodeSetGetChildren(doc, xmlSecFindNode(root, BAD_CAST "keep", BAD_CAST "urn:t"), 0, 0);
    ret = xmlSecTransformCtxXmlExecute(ctx, nodes);
    result("read exc-c14n-upper", ctx, ret);
    xmlSecNodeSetDestroy(nodes);
    xmlSecTransformCtxDestroy(ctx);

    /* a disabled transform cannot be read */
    ctx = xmlSecTransformCtxCreate();
    xmlSecPtrListAdd(&(ctx->enabledTransforms), (void *)xmlSecTransformBase64Id);
    ret = xmlSecTransformCtxNodesListRead(ctx,
        xmlSecFindNode(root, BAD_CAST "Transforms", BAD_CAST "http://www.w3.org/2000/09/xmldsig#"),
        xmlSecTransformUsageDSigTransform);
    printf("disabled read: %d\n", ret);
    xmlSecTransformCtxDestroy(ctx);

    /* the pump between two transforms, outside a context's execute */
    {
        xmlSecTransformCtx pumpCtx;
        xmlSecTransformPtr left;
        xmlSecTransformPtr right;
        xmlSecTransformCtxInitialize(&pumpCtx);
        left = xmlSecTransformCreate(xmlSecTransformBase64Id);
        right = xmlSecTransformCreate(xmlSecTransformMemBufId);
        xmlSecBufferSetData(&(left->inBuf), BAD_CAST "Zm9vYmFy", 8);
        left->status = xmlSecTransformStatusNone;
        printf("pump: %d", xmlSecTransformPump(left, right, &pumpCtx));
        printf(" [%.*s]\n", (int)xmlSecBufferGetSize(xmlSecTransformMemBufGetBuffer(right)),
               (const char *)xmlSecBufferGetData(xmlSecTransformMemBufGetBuffer(right)));
        xmlSecTransformDestroy(left);
        xmlSecTransformDestroy(right);
        xmlSecTransformCtxFinalize(&pumpCtx);
    }

    printf("connect mismatch: %d\n", xmlSecTransformConnect(NULL, NULL, NULL));
    printf("object sizes: %d %d\n",
           xmlSecTransformBase64Id->objSize > sizeof(xmlSecTransform),
           xmlSecTransformEnvelopedId->objSize == sizeof(xmlSecTransform));

    xmlSecTransformIdsShutdown();
    xmlFreeDoc(doc);
    printf("done\n");
    return 0;
}
