/* Error reporting as a libxmlsec1 caller sees it. The program is built
 * unmodified against the pinned libxmlsec1 and against this crate, and both
 * must print the same: the reason table, the fields and formatted message a
 * callback receives, the callback priority, the default callback's line
 * (after its location fields, which name each library's own code), and the
 * reports of failing library calls: the reason of the first report (the
 * cause) and of the last (the entry point), and how many there were. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <libxml/xmlerror.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
/* The system callback is the crypto layer's, declared privately. */
#define XMLSEC_PRIVATE 1
#include <xmlsec/private.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/base64.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/xmltree.h>
#include <libxml/parser.h>

static int reports;
static int first_reason;
static int last_reason;
static int printing;

static const char *safe(const char *text) {
    return text != NULL ? text : "(null)";
}

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    (void)func;
    if (reports == 0) {
        first_reason = reason;
    }
    last_reason = reason;
    ++reports;
    if (printing == 1) {
        printf("  report: obj=%s subj=%s reason=%d msg=[%s]\n", safe(object), safe(subject),
               reason, safe(msg));
    } else if (printing == 2) {
        /* The message names the evaluator's own cause. */
        printf("  report: obj=%s subj=%s reason=%d\n", safe(object), safe(subject), reason);
    }
}

static void other(const char *file, int line, const char *func, const char *object,
                  const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    (void)func;
    (void)object;
    (void)subject;
    (void)msg;
    printf("  system callback: reason=%d\n", reason);
}

/* libxml2's generic error handler, through which the default callback
 * writes: the part from "obj=" on is the same for both libraries. */
static void generic(void *ctx, const char *msg, ...) {
    va_list args;
    char line[2048];
    const char *tail;

    (void)ctx;
    va_start(args, msg);
    vsnprintf(line, sizeof(line), msg, args);
    va_end(args);
    tail = strstr(line, ":obj=");
    printf("  default: %s", tail != NULL ? tail + 1 : line);
}

static void begin(const char *label) {
    reports = 0;
    first_reason = 0;
    last_reason = 0;
    printf("%s\n", label);
}

static void end(int ret) {
    printf("  ret=%d reports=%d first=%d last=%d\n", ret, reports > 0 ? 1 : 0, first_reason,
           last_reason);
}

static void table(void) {
    xmlSecSize pos;

    for (pos = 0; xmlSecErrorsGetMsg(pos) != NULL; ++pos) {
        printf("table %d: %d %s\n", (int)pos, xmlSecErrorsGetCode(pos), xmlSecErrorsGetMsg(pos));
    }
    printf("table end at %d: code=%d\n", (int)pos, xmlSecErrorsGetCode(pos));
    printf("table far: code=%d msg=%s\n", xmlSecErrorsGetCode(1000),
           safe(xmlSecErrorsGetMsg(1000)));
}

static void formatting(void) {
    char long_text[3000];

    printing = 1;
    xmlSecErrorsSetCallback(record);
    begin("xmlSecError formats");
    xmlSecError(XMLSEC_ERRORS_HERE, "object", "subject", XMLSEC_ERRORS_R_INVALID_DATA,
                "size=%d;name=%s;hex=%x", 42, "x", 255);
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, NULL, XMLSEC_ERRORS_R_ASSERTION, NULL);
    memset(long_text, 'y', sizeof(long_text) - 1);
    long_text[sizeof(long_text) - 1] = '\0';
    printing = 0;
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, NULL, 1, "%s", long_text);
    printf("  reports=%d\n", reports);
}

static void truncation(void) {
    char long_text[3000];

    memset(long_text, 'z', sizeof(long_text) - 1);
    long_text[sizeof(long_text) - 1] = '\0';
    xmlSetGenericErrorFunc(NULL, generic);
    xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);
    printf("default callback\n");
    xmlSecError(XMLSEC_ERRORS_HERE, "obj", NULL, XMLSEC_ERRORS_R_INVALID_SIZE, "n=%d", 3);
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, "subj", 999, NULL);
    xmlSecErrorsDefaultCallbackEnableOutput(0);
    xmlSecError(XMLSEC_ERRORS_HERE, "silent", NULL, 1, "hidden");
    xmlSecErrorsDefaultCallbackEnableOutput(1);
    printf("  output enabled again\n");
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, NULL, 1, "%s", long_text);
}

static void priority(void) {
    printing = 0;
    printf("priority\n");
    xmlSecErrorsSetCallback(record);
    xmlSecErrorsSetSystemCallback(other);
    reports = 0;
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, NULL, 7, "user first");
    printf("  user reports=%d\n", reports);
    xmlSecErrorsSetCallback(NULL);
    reports = 0;
    xmlSecError(XMLSEC_ERRORS_HERE, NULL, NULL, 7, "disabled");
    printf("  after null user reports=%d\n", reports);
    xmlSecErrorsSetCallback(record);
}

static void library(void) {
    xmlSecBufferPtr buf;
    xmlSecByte out[16];
    xmlSecSize written = 0;
    int ret;

    printing = 1;
    xmlSecErrorsSetCallback(record);
    begin("buffer initialize null");
    end(xmlSecBufferInitialize(NULL, 1));
    begin("list add to null");
    end(xmlSecPtrListAdd(NULL, NULL));
    begin("base64 decode invalid");
    ret = xmlSecBase64Decode_ex(BAD_CAST "A!A=", out, sizeof(out), &written);
    end(ret);
    begin("base64 decode misplaced padding");
    end(xmlSecBase64Decode_ex(BAD_CAST "A===", out, sizeof(out), &written));
    begin("base64 decode after the end");
    end(xmlSecBase64Decode_ex(BAD_CAST "AA==AA", out, sizeof(out), &written));
    begin("base64 decode unfinished group");
    end(xmlSecBase64Decode_ex(BAD_CAST "AAA", out, sizeof(out), &written));
    begin("base64 decode into too little room");
    end(xmlSecBase64Decode_ex(BAD_CAST "AAAAAAAA", out, 2, &written));
    begin("buffer base64 read invalid");
    buf = xmlSecBufferCreate(0);
    end(xmlSecBufferBase64NodeContentRead(buf, NULL));
    xmlSecBufferDestroy(buf);
}

/* Transform-chain failures, every report printed: the precondition, the
 * cause and the chain of callers above it. */
static void transform_context(void) {
    static const char document[] =
        "<T xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<Transform/>"
        "<Transform Algorithm='urn:unknown'/>"
        "<Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'/>"
        "<L><Transform Algorithm='http://www.w3.org/2002/06/xmldsig-filter2'>"
        "<XPath xmlns='http://www.w3.org/2002/06/xmldsig-filter2'>/</XPath>"
        "</Transform></L>"
        "<L><Transform Algorithm='http://www.w3.org/TR/1999/REC-xpath-19991116'>"
        "<Other/></Transform></L>"
        "<Other/>"
        "</T>";
    xmlDocPtr doc = xmlReadMemory(document, (int)strlen(document), "doc.xml", NULL, 0);
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr bare = xmlSecGetNextElementNode(root->children);
    xmlNodePtr unknown = xmlSecGetNextElementNode(bare->next);
    xmlNodePtr enveloped = xmlSecGetNextElementNode(unknown->next);
    xmlNodePtr xpath2 = xmlSecGetNextElementNode(enveloped->next);
    xmlNodePtr xpath = xmlSecGetNextElementNode(xpath2->next);
    xmlSecTransformCtx ctx;

    printing = 1;
    xmlSecErrorsSetCallback(record);
    printf("transform ids init: %d\n", xmlSecTransformIdsInit());

    begin("ctx append null");
    end(xmlSecTransformCtxAppend(NULL, NULL));
    begin("ctx execute without document");
    xmlSecTransformCtxInitialize(&ctx);
    end(xmlSecTransformCtxExecute(&ctx, NULL));
    begin("node read without algorithm");
    end(xmlSecTransformCtxNodeRead(&ctx, bare, xmlSecTransformUsageAny) == NULL ? -1 : 0);
    begin("node read unknown algorithm");
    end(xmlSecTransformCtxNodeRead(&ctx, unknown, xmlSecTransformUsageAny) == NULL ? -1 : 0);
    begin("node read disabled algorithm");
    xmlSecPtrListAdd(&ctx.enabledTransforms, (void *)xmlSecTransformBase64Id);
    end(xmlSecTransformCtxNodeRead(&ctx, enveloped, xmlSecTransformUsageAny) == NULL ? -1 : 0);
    begin("nodes list with a foreign node");
    xmlSecTransformCtxFinalize(&ctx);
    xmlSecTransformCtxInitialize(&ctx);
    end(xmlSecTransformCtxNodesListRead(&ctx, root, xmlSecTransformUsageAny));
    xmlSecTransformCtxFinalize(&ctx);

    begin("set uri of a disabled type");
    xmlSecTransformCtxInitialize(&ctx);
    ctx.enabledUris = xmlSecTransformUriTypeSameDocument;
    end(xmlSecTransformCtxSetUri(&ctx, BAD_CAST "http://example.org/a", root));
    begin("set uri twice");
    end(xmlSecTransformCtxSetUri(&ctx, BAD_CAST "#a", root));
    end(xmlSecTransformCtxSetUri(&ctx, BAD_CAST "#b", root));
    xmlSecTransformCtxFinalize(&ctx);

    begin("prepare twice");
    xmlSecTransformCtxInitialize(&ctx);
    end(xmlSecTransformCtxPrepare(&ctx, xmlSecTransformDataTypeBin));
    end(xmlSecTransformCtxPrepare(&ctx, xmlSecTransformDataTypeBin));
    xmlSecTransformCtxFinalize(&ctx);

    begin("base64 transform on invalid input");
    xmlSecTransformCtxInitialize(&ctx);
    xmlSecTransformCtxCreateAndAppend(&ctx, xmlSecTransformBase64Id);
    end(xmlSecTransformCtxBinaryExecute(&ctx, BAD_CAST "A!A=", 4));
    xmlSecTransformCtxFinalize(&ctx);

    begin("enveloped transform outside a signature");
    xmlSecTransformCtxInitialize(&ctx);
    xmlSecTransformCtxNodeRead(&ctx, enveloped, xmlSecTransformUsageAny);
    end(xmlSecTransformCtxExecute(&ctx, doc));
    xmlSecTransformCtxFinalize(&ctx);

    printing = 2;
    begin("xpointer selecting a missing id");
    xmlSecTransformCtxInitialize(&ctx);
    xmlSecTransformCtxSetUri(&ctx, BAD_CAST "#absent", root);
    end(xmlSecTransformCtxExecute(&ctx, doc));
    xmlSecTransformCtxFinalize(&ctx);

    begin("visa3d selecting a missing id");
    xmlSecTransformCtxInitialize(&ctx);
    ctx.flags |= XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK;
    xmlSecTransformCtxSetUri(&ctx, BAD_CAST "#absent", root);
    end(xmlSecTransformCtxExecute(&ctx, doc));
    xmlSecTransformCtxFinalize(&ctx);
    printing = 1;

    begin("xpath2 transform without a filter");
    xmlSecTransformCtxInitialize(&ctx);
    end(xmlSecTransformCtxNodesListRead(&ctx, xpath2, xmlSecTransformUsageAny));
    xmlSecTransformCtxFinalize(&ctx);

    begin("xpath transform without an expression");
    xmlSecTransformCtxInitialize(&ctx);
    end(xmlSecTransformCtxNodesListRead(&ctx, xpath, xmlSecTransformUsageAny));
    xmlSecTransformCtxFinalize(&ctx);

    printing = 0;
    xmlSecTransformIdsShutdown();
    xmlFreeDoc(doc);
}

/* Key-data failures: preconditions, a klass method missing and a lookup in
 * a list of the wrong kind. */
static void key_data(void) {
    xmlSecKeyDataPtr name;
    xmlSecPtrListPtr list;

    printing = 1;
    xmlSecErrorsSetCallback(record);
    printf("key data ids init: %d\n", xmlSecKeyDataIdsInit());
    name = xmlSecKeyDataCreate(xmlSecKeyDataNameId);

    begin("key data create without klass");
    end(xmlSecKeyDataCreate(NULL) == NULL ? -1 : 0);
    begin("key data duplicate without method");
    end(xmlSecKeyDataDuplicate(name) == NULL ? -1 : 0);
    begin("binary value of a plain key data");
    end(xmlSecKeyDataBinaryValueGetBuffer(name) == NULL ? -1 : 0);
    begin("generate without method");
    end(xmlSecKeyDataGenerate(name, 128, xmlSecKeyDataTypeAny));
    begin("find in a list of another kind");
    list = xmlSecPtrListCreate(xmlSecStringListId);
    end(xmlSecKeyDataIdListFindByName(list, BAD_CAST "x", xmlSecKeyDataUsageAny) == NULL
            ? -1
            : 0);
    begin("find by a null href");
    end(xmlSecKeyDataIdListFindByHref(xmlSecKeyDataIdsGet(), NULL, xmlSecKeyDataUsageAny) ==
                NULL
            ? -1
            : 0);
    begin("store create without klass");
    end(xmlSecKeyDataStoreCreate(NULL) == NULL ? -1 : 0);

    printing = 0;
    xmlSecPtrListDestroy(list);
    xmlSecKeyDataDestroy(name);
    xmlSecKeyDataIdsShutdown();
}

int main(void) {
    table();
    formatting();
    truncation();
    priority();
    library();
    transform_context();
    key_data();
    return 0;
}
