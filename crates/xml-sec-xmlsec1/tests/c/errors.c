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
    if (printing) {
        printf("  report: obj=%s subj=%s reason=%d msg=[%s]\n", safe(object), safe(subject),
               reason, safe(msg));
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

    printing = 0;
    xmlSecErrorsSetCallback(record);
    begin("buffer initialize null");
    end(xmlSecBufferInitialize(NULL, 1));
    begin("list add to null");
    end(xmlSecPtrListAdd(NULL, NULL));
    begin("base64 decode invalid");
    ret = xmlSecBase64Decode_ex(BAD_CAST "A!A=", out, sizeof(out), &written);
    end(ret);
    begin("buffer base64 read invalid");
    buf = xmlSecBufferCreate(0);
    end(xmlSecBufferBase64NodeContentRead(buf, NULL));
    xmlSecBufferDestroy(buf);
}

int main(void) {
    table();
    formatting();
    truncation();
    priority();
    library();
    return 0;
}
