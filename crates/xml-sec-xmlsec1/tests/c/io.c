/* Input callbacks as a libxmlsec1 caller sees them. The program is built
 * unmodified against the pinned libxmlsec1 and against this crate, and both
 * must print the same: which registered set reads a URI, the URI each
 * callback receives, the bytes a chain reads through them, and the outcome
 * and reports of a set that cannot open or read. Each library's own default
 * callbacks are removed first; this program registers its own. */

#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/io.h>
#include <xmlsec/transforms.h>
#include <xmlsec/buffer.h>

static const char content[] = "Resource content read in small pieces.";

struct resource {
    size_t position;
    int fail_read;
};

static struct resource opened;
static int closes;

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    (void)func;
    printf("  report: obj=%s subj=%s reason=%d msg=[%s]\n", object != NULL ? object : "(null)",
           subject != NULL ? subject : "(null)", reason, msg != NULL ? msg : "(null)");
}

static int match_any(const char *uri) {
    printf("  match any: %s\n", uri);
    return 1;
}

static int match_example(const char *uri) {
    printf("  match example: %s\n", uri);
    return strncmp(uri, "example:", 8) == 0;
}

static void *open_resource(const char *uri) {
    printf("  open: %s\n", uri);
    if (strstr(uri, "missing") != NULL) {
        return NULL;
    }
    opened.position = 0;
    opened.fail_read = strstr(uri, "broken") != NULL;
    return &opened;
}

/* Returns at most 7 bytes per call, so a chain reads in several calls. */
static int read_resource(void *context, char *buffer, int len) {
    struct resource *resource = context;
    size_t left = sizeof(content) - 1 - resource->position;
    size_t count = left < 7 ? left : 7;

    if (resource->fail_read) {
        return -1;
    }
    if ((size_t)len < count) {
        count = (size_t)len;
    }
    memcpy(buffer, content + resource->position, count);
    resource->position += count;
    return (int)count;
}

static int close_resource(void *context) {
    (void)context;
    ++closes;
    return 0;
}

static void execute(const char *label, const char *uri) {
    xmlSecTransformCtx ctx;
    int ret;

    printf("%s\n", label);
    closes = 0;
    xmlSecTransformCtxInitialize(&ctx);
    ret = xmlSecTransformCtxUriExecute(&ctx, BAD_CAST uri);
    printf("  ret=%d status=%d closes=%d\n", ret, (int)ctx.status, closes);
    if (ret == 0 && ctx.result != NULL) {
        printf("  result=[%.*s]\n", (int)xmlSecBufferGetSize(ctx.result),
               (const char *)xmlSecBufferGetData(ctx.result));
    }
    xmlSecTransformCtxFinalize(&ctx);
    printf("  closes after finalize=%d\n", closes);
}

int main(void) {
    xmlSecTransformPtr transform;
    int closed;

    /* A libxmlsec1 caller works with libxml2, which provides the allocator;
     * initializing it also keeps the linker from dropping it. */
    xmlInitParser();
    xmlSecErrorsSetCallback(record);
    printf("io init: %d\n", xmlSecIOInit());
    xmlSecIOCleanupCallbacks();

    execute("no callbacks", "example:thing");

    printf("register: %d\n", xmlSecIORegisterCallbacks(match_example, open_resource,
                                                        read_resource, close_resource));
    execute("one set", "example:thing");
    execute("one set, unescaped first", "example:with%20space");
    execute("one set, no match", "other:thing");

    printf("register: %d\n",
           xmlSecIORegisterCallbacks(match_any, open_resource, read_resource, close_resource));
    execute("later set first", "example:thing");
    execute("open fails", "example:missing");
    execute("read fails", "example:broken");

    printf("open and close directly\n");
    transform = xmlSecTransformCreate(xmlSecTransformInputURIId);
    closes = 0;
    printf("  open=%d\n", xmlSecTransformInputURIOpen(transform, BAD_CAST "example:x"));
    /* The call runs before `closes` is read: argument evaluation order is
     * unspecified, so the result is taken in its own statement. */
    closed = xmlSecTransformInputURIClose(transform);
    printf("  close=%d closes=%d\n", closed, closes);
    closed = xmlSecTransformInputURIClose(transform);
    printf("  close again=%d closes=%d\n", closed, closes);
    xmlSecTransformDestroy(transform);

    printf("register without match: %d\n",
           xmlSecIORegisterCallbacks(NULL, open_resource, read_resource, close_resource));

    xmlSecIOShutdown();
    return 0;
}
