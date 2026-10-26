/* In-process libxmlsec1 harness for the competitor comparison. Test-only;
 * never linked into a product binary. It follows the request protocol of
 * benchmarks/competitors/src/lib.rs:
 *
 *   HARNESS SCENARIO OPERATION BOUNDARY CORPUS INPUT OUTPUT SAMPLES
 *
 * and configures each workload as the xmlsec1 command line does. Built with
 * -DLIBRARY_PROFILE on glibc, it counts the operation's heap work; that
 * build's timings are never reported. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
/* CLOCK_MONOTONIC has microsecond granularity on macOS; the raw clock matches
 * the nanosecond source of Rust's Instant. */
#define _DARWIN_C_SOURCE
#define BENCHMARK_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCHMARK_CLOCK CLOCK_MONOTONIC
#endif
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/parser.h>
#include <xmlsec/crypto.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { EXIT_USAGE = 2, EXIT_UNSUPPORTED = 3, EXIT_FAILURE_OPERATION = 4 };
enum { WARMUPS = 3 };

static const xmlChar SAML_ASSERTION[] = "urn:oasis:names:tc:SAML:2.0:assertion";

#ifdef LIBRARY_PROFILE
/* Every heap allocation in the process is counted, as the Rust harnesses'
 * global allocator does: libxml2, libxslt, xmlsec and the OpenSSL linked into
 * xmlsec all allocate through malloc. The glibc manual's "Replacing malloc"
 * contract: define the malloc family here and forward to glibc's own. */
#if !defined(__GLIBC__)
#error "allocation profiling replaces glibc's malloc family"
#endif
#include <malloc.h>
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);
static size_t allocation_calls, allocated_bytes;
static long long live_bytes, peak_bytes;
static int counting;
/* Live bytes are usable block sizes, as the Rust harnesses' profile counts them,
 * so every engine's peak includes allocator rounding. */
static void observe(void *block, size_t requested, size_t released) {
    if (!counting || block == NULL) return;
    ++allocation_calls; allocated_bytes += requested;
    live_bytes += (long long)malloc_usable_size(block) - (long long)released;
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
}
void *malloc(size_t bytes) { void *block = __libc_malloc(bytes); observe(block, bytes, 0); return block; }
void *calloc(size_t count, size_t size) {
    void *block = __libc_calloc(count, size);
    /* A non-NULL result means count * size did not overflow. */
    observe(block, count * size, 0);
    return block;
}
void *realloc(void *pointer, size_t bytes) {
    size_t released = pointer != NULL && counting ? malloc_usable_size(pointer) : 0;
    void *block = __libc_realloc(pointer, bytes);
    if (block != NULL) observe(block, bytes, released);
    else if (bytes == 0 && counting) live_bytes -= (long long)released;
    return block;
}
void free(void *pointer) {
    if (pointer != NULL && counting) live_bytes -= (long long)malloc_usable_size(pointer);
    __libc_free(pointer);
}
void *memalign(size_t alignment, size_t bytes) { void *block = __libc_memalign(alignment, bytes); observe(block, bytes, 0); return block; }
void *aligned_alloc(size_t alignment, size_t bytes) { return memalign(alignment, bytes); }
int posix_memalign(void **result, size_t alignment, size_t bytes) {
    void *block = memalign(alignment, bytes);
    if (block == NULL) return bytes == 0 ? 0 : 12; /* ENOMEM */
    *result = block;
    return 0;
}
#endif

static void fail(int status, const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(status);
}

static char *read_bytes(const char *path, int *length) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) { fprintf(stderr, "%s: cannot open\n", path); exit(EXIT_FAILURE_OPERATION); }
    if (fseek(file, 0, SEEK_END) != 0) fail(EXIT_FAILURE_OPERATION, "seek input");
    long size = ftell(file);
    if (size < 0 || size >= INT_MAX) fail(EXIT_FAILURE_OPERATION, "input size");
    rewind(file);
    char *bytes = malloc((size_t)size + 1);
    if (bytes == NULL) fail(EXIT_FAILURE_OPERATION, "input allocation");
    if (fread(bytes, 1, (size_t)size, file) != (size_t)size) fail(EXIT_FAILURE_OPERATION, "read input");
    if (fclose(file) != 0) fail(EXIT_FAILURE_OPERATION, "close input");
    bytes[size] = 0;
    *length = (int)size;
    return bytes;
}

static unsigned long long now_ns(void) {
    struct timespec time;
    if (clock_gettime(BENCHMARK_CLOCK, &time) != 0) fail(EXIT_FAILURE_OPERATION, "monotonic clock");
    return (unsigned long long)time.tv_sec * 1000000000ULL + (unsigned long long)time.tv_nsec;
}

/* The ID spellings each workload declares, as `--id-attr` does: a repeated ID
 * is refused, so a signature-wrapping forgery cannot shadow the signed node. */
static const xmlChar *id_attribute(xmlNodePtr node) {
    if (xmlStrEqual(node->name, BAD_CAST "Assertion") && node->ns != NULL && xmlStrEqual(node->ns->href, SAML_ASSERTION))
        return BAD_CAST "ID";
    if (node->ns == NULL && (xmlStrEqual(node->name, BAD_CAST "List") || xmlStrEqual(node->name, BAD_CAST "Payment")))
        return BAD_CAST "Id";
    return NULL;
}

static int register_ids(xmlDocPtr doc) {
    xmlNodePtr node = xmlDocGetRootElement(doc);
    while (node != NULL) {
        if (node->type == XML_ELEMENT_NODE) {
            const xmlChar *name = id_attribute(node);
            xmlAttrPtr attribute = name != NULL ? xmlHasProp(node, name) : NULL;
            if (attribute != NULL) {
                xmlChar *value = xmlNodeListGetString(doc, attribute->children, 1);
                if (value == NULL) return -1;
                int duplicate = xmlGetID(doc, value) != NULL;
                if (!duplicate && xmlAddID(NULL, doc, value, attribute) == NULL) duplicate = 1;
                xmlFree(value);
                if (duplicate) return -1;
            }
        }
        if (node->type == XML_ELEMENT_NODE && node->children != NULL) { node = node->children; continue; }
        while (node != NULL && node->next == NULL) {
            node = node->parent;
            if (node == NULL || node->type == XML_DOCUMENT_NODE) return 0;
        }
        if (node != NULL) node = node->next;
    }
    return 0;
}

/* The parser options of the xmlsec1 command line. They include XML_PARSE_NODICT:
 * encryption moves the template node into the data document, and a name interned
 * in the template's dictionary would be freed as heap memory with the data
 * document (glibc aborts on it with libxml2 2.9). */
static xmlDocPtr parse_document(const char *bytes, int length) {
    xmlDocPtr doc = xmlReadMemory(bytes, length, "urn:benchmark:input", NULL, xmlSecParserGetDefaultOptions());
    if (doc == NULL) return NULL;
    if (register_ids(doc) != 0) { xmlFreeDoc(doc); return NULL; }
    return doc;
}

typedef struct {
    const char *scenario, *operation, *corpus, *input_path, *output_path;
    int prepared, rejecting;
    long samples;
    char *input, *template_bytes;
    int input_length, template_length;
    xmlSecKeysMngrPtr keys;
} Request;

static int is(const char *value, const char *expected) { return strcmp(value, expected) == 0; }

static char *corpus_path(const Request *request, const char *name) {
    size_t size = strlen(request->corpus) + strlen(name) + 2;
    char *path = malloc(size);
    if (path == NULL) fail(EXIT_FAILURE_OPERATION, "path allocation");
    snprintf(path, size, "%s/%s", request->corpus, name);
    return path;
}

static void adopt_key(const Request *request, const char *file, xmlSecKeyDataType type, xmlSecKeyDataFormat format, const char *certificate, const char *name) {
    char *path = corpus_path(request, file);
    xmlSecKeyPtr key = xmlSecCryptoAppKeyLoadEx(path, type, format, NULL, NULL, NULL);
    free(path);
    if (key == NULL) fail(EXIT_FAILURE_OPERATION, "key load");
    if (certificate != NULL) {
        char *certificate_path = corpus_path(request, certificate);
        int loaded = xmlSecCryptoAppKeyCertLoad(key, certificate_path, xmlSecKeyDataFormatPem);
        free(certificate_path);
        if (loaded < 0) fail(EXIT_FAILURE_OPERATION, "certificate load");
    }
    if (xmlSecKeySetName(key, BAD_CAST name) < 0) fail(EXIT_FAILURE_OPERATION, "key name");
    if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(request->keys, key) < 0) fail(EXIT_FAILURE_OPERATION, "adopt key");
}

static void load_certificate(const Request *request, const char *file, xmlSecKeyDataType type) {
    char *path = corpus_path(request, file);
    int loaded = xmlSecCryptoAppKeysMngrCertLoad(request->keys, path, xmlSecKeyDataFormatPem, type);
    free(path);
    if (loaded < 0) fail(EXIT_FAILURE_OPERATION, "certificate store");
}

/* Keys and trust exactly as the xmlsec1 commands of the CLI comparison pass them. */
static void configure_keys(Request *request) {
    request->keys = xmlSecKeysMngrCreate();
    if (request->keys == NULL || xmlSecCryptoAppDefaultKeysMngrInit(request->keys) < 0) fail(EXIT_FAILURE_OPERATION, "keys manager");
    int assertion = is(request->scenario, "assertion");
    if (is(request->operation, "sign")) {
        adopt_key(request, "private.pem", xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, assertion ? "leaf.pem" : NULL, "bench");
    } else if (is(request->operation, "verify") || request->rejecting) {
        if (assertion) {
            load_certificate(request, "root.pem", xmlSecKeyDataTypeTrusted);
            load_certificate(request, "intermediate.pem", xmlSecKeyDataTypeNone);
        } else {
            adopt_key(request, "public.pem", xmlSecKeyDataTypePublic, xmlSecKeyDataFormatPem, NULL, "bench");
        }
    } else if (is(request->operation, "encrypt")) {
        adopt_key(request, "leaf.pem", xmlSecKeyDataTypePublic, xmlSecKeyDataFormatCertPem, NULL, "recipient");
        char *path = corpus_path(request, "element.template.xml");
        request->template_bytes = read_bytes(path, &request->template_length);
        free(path);
    } else {
        adopt_key(request, "private.pem", xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, "recipient");
    }
}

/* 0 success; 1 verification refused the document; -1 processing failure. */
static int sign(const Request *request, xmlDocPtr doc) {
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    xmlSecDSigCtxPtr context = xmlSecDSigCtxCreate(request->keys);
    if (node == NULL || context == NULL) { if (context) xmlSecDSigCtxDestroy(context); return -1; }
    int status = xmlSecDSigCtxSign(context, node) < 0 ? -1 : 0;
    xmlSecDSigCtxDestroy(context);
    return status;
}

static int verify(const Request *request, xmlDocPtr doc) {
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    xmlSecDSigCtxPtr context = xmlSecDSigCtxCreate(request->keys);
    if (node == NULL || context == NULL) { if (context) xmlSecDSigCtxDestroy(context); return 1; }
    int verified = xmlSecDSigCtxVerify(context, node);
    int status = verified >= 0 && context->status == xmlSecDSigStatusSucceeded ? 0 : 1;
    xmlSecDSigCtxDestroy(context);
    return status;
}

/* `encrypt --session-key aes-256 [--node-id payment]`: the template replaces the target. */
static int encrypt(const Request *request, xmlDocPtr doc, xmlDocPtr template_doc) {
    xmlNodePtr target = xmlDocGetRootElement(doc);
    if (is(request->scenario, "element_in_place")) {
        xmlAttrPtr id = xmlGetID(doc, BAD_CAST "payment");
        target = id != NULL ? id->parent : NULL;
    }
    xmlSecEncCtxPtr context = xmlSecEncCtxCreate(request->keys);
    if (target == NULL || context == NULL) { if (context) xmlSecEncCtxDestroy(context); return -1; }
    context->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 256, xmlSecKeyDataTypeSession);
    int status = context->encKey == NULL || xmlSecEncCtxXmlEncrypt(context, xmlDocGetRootElement(template_doc), target) < 0 ? -1 : 0;
    xmlSecEncCtxDestroy(context);
    return status;
}

static int decrypt(const Request *request, xmlDocPtr doc) {
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    xmlSecEncCtxPtr context = xmlSecEncCtxCreate(request->keys);
    if (node == NULL || context == NULL) { if (context) xmlSecEncCtxDestroy(context); return -1; }
    int status = xmlSecEncCtxDecrypt(context, node) < 0 || context->resultReplaced == 0 ? -1 : 0;
    xmlSecEncCtxDestroy(context);
    return status;
}

static int run_operation(const Request *request, xmlDocPtr doc, xmlDocPtr template_doc) {
    if (is(request->operation, "sign")) return sign(request, doc);
    if (is(request->operation, "encrypt")) return encrypt(request, doc, template_doc);
    if (is(request->operation, "decrypt")) return decrypt(request, doc);
    return verify(request, doc);
}

typedef struct {
    xmlDocPtr doc, template_doc;
    xmlChar *output;
    int output_length;
} Run;

/* One operation; returns 0, 1 (verification refused) or -1 (failure). With
 * `parse`, parsing and result serialization are inside the timed region; with
 * `prepared`, documents are parsed before it (once for verification, freshly
 * for a mutating operation) and nothing is serialized. A non-NULL
 * `output_length` requests the validation result after the timed region. */
static int run_once(const Request *request, xmlDocPtr shared, int *output_length, unsigned long long *elapsed, int count) {
    Run run = { NULL, NULL, NULL, 0 };
    int mutating = !is(request->operation, "verify");
    int has_template = request->template_bytes != NULL;
    if (request->prepared && mutating) {
        run.doc = parse_document(request->input, request->input_length);
        if (has_template) run.template_doc = parse_document(request->template_bytes, request->template_length);
        if (run.doc == NULL || (has_template && run.template_doc == NULL)) {
            if (run.doc != NULL) xmlFreeDoc(run.doc);
            if (run.template_doc != NULL) xmlFreeDoc(run.template_doc);
            return -1;
        }
    }
#ifdef LIBRARY_PROFILE
    if (count) { allocation_calls = 0; allocated_bytes = 0; live_bytes = 0; peak_bytes = 0; counting = 1; }
#else
    (void)count;
#endif
    unsigned long long start = now_ns();
    int status = 0;
    if (!request->prepared) {
        run.doc = parse_document(request->input, request->input_length);
        if (has_template) run.template_doc = parse_document(request->template_bytes, request->template_length);
        if (run.doc == NULL || (has_template && run.template_doc == NULL)) status = mutating ? -1 : 1;
    }
    xmlDocPtr doc = request->prepared && !mutating ? shared : run.doc;
    if (status == 0) status = run_operation(request, doc, run.template_doc);
    if (status == 0 && mutating && !request->prepared) xmlDocDumpMemory(doc, &run.output, &run.output_length);
    unsigned long long finished = now_ns();
#ifdef LIBRARY_PROFILE
    counting = 0;
#endif
    if (elapsed != NULL) *elapsed = finished - start;
    if (status == 0 && output_length != NULL && mutating) {
        if (run.output == NULL) xmlDocDumpMemory(doc, &run.output, &run.output_length);
        FILE *file = is(request->output_path, "-") ? NULL : fopen(request->output_path, "wb");
        if (run.output == NULL ||
            (file != NULL && (fwrite(run.output, 1, (size_t)run.output_length, file) != (size_t)run.output_length || fclose(file) != 0)) ||
            (file == NULL && !is(request->output_path, "-")))
            status = -1;
        *output_length = run.output_length;
    }
    xmlFree(run.output);
    if (run.doc != NULL) xmlFreeDoc(run.doc);
    if (run.template_doc != NULL) xmlFreeDoc(run.template_doc);
    return status;
}

int main(int argc, char **argv) {
    if (argc != 8) fail(EXIT_USAGE, "usage: HARNESS SCENARIO OPERATION BOUNDARY CORPUS INPUT OUTPUT SAMPLES");
    Request request = { argv[1], argv[2], argv[4], argv[5], argv[6], 0, 0, 0, NULL, NULL, 0, 0, NULL };
    if (!is(argv[3], "parse") && !is(argv[3], "prepared")) fail(EXIT_USAGE, "unknown boundary");
    request.prepared = is(argv[3], "prepared");
    request.rejecting = is(request.operation, "reject");
    if (!is(request.operation, "sign") && !is(request.operation, "verify") && !is(request.operation, "encrypt") &&
        !is(request.operation, "decrypt") && !request.rejecting) fail(EXIT_USAGE, "unknown operation");
    int signing = is(request.scenario, "assertion") || is(request.scenario, "xslt");
    int encrypting = is(request.scenario, "element") || is(request.scenario, "element_in_place");
    int signature_operation = is(request.operation, "sign") || is(request.operation, "verify") || request.rejecting;
    if (!(signing && signature_operation) && !(encrypting && !signature_operation)) fail(EXIT_UNSUPPORTED, "unsupported: no such workload operation");
    char *end = NULL;
    request.samples = strtol(argv[7], &end, 10);
    if (end == argv[7] || *end != 0 || request.samples < 1 || request.samples > 100000) fail(EXIT_USAGE, "SAMPLES must be 1..=100000");
    request.input = read_bytes(request.input_path, &request.input_length);

    xmlInitParser();
    LIBXML_TEST_VERSION
    if (xmlSecInit() < 0 || xmlSecCheckVersion() != 1 || xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0)
        fail(EXIT_FAILURE_OPERATION, "xmlsec initialization");
    configure_keys(&request);

    int exit_status = 0;
    if (request.rejecting) {
        xmlDocPtr doc = parse_document(request.input, request.input_length);
        int refused = doc == NULL || verify(&request, doc) != 0;
        if (doc != NULL) xmlFreeDoc(doc);
        if (!refused) fail(EXIT_FAILURE_OPERATION, "verification accepted an input it must refuse");
        printf("{\"engine\":\"libxmlsec1\",\"rejected\":true}\n");
    } else {
        xmlDocPtr shared = NULL;
        if (request.prepared && !strcmp(request.operation, "verify")) {
            shared = parse_document(request.input, request.input_length);
            if (shared == NULL) fail(EXIT_FAILURE_OPERATION, "prepare: document");
        }
        int output_length = 0;
        int validated = run_once(&request, shared, &output_length, NULL, 0);
        if (validated == 1) fail(EXIT_FAILURE_OPERATION, "verification refused a valid input");
        if (validated != 0) fail(EXIT_FAILURE_OPERATION, "operation: validation run failed");
        for (int i = 0; i < WARMUPS; ++i)
            if (run_once(&request, shared, NULL, NULL, 0) != 0) fail(EXIT_FAILURE_OPERATION, "operation: warmup failed");
        unsigned long long *times = malloc((size_t)request.samples * sizeof(*times));
        if (times == NULL) fail(EXIT_FAILURE_OPERATION, "sample allocation");
        for (long i = 0; i < request.samples; ++i)
            if (run_once(&request, shared, NULL, &times[i], 0) != 0) fail(EXIT_FAILURE_OPERATION, "operation: sample failed");
#ifdef LIBRARY_PROFILE
        /* One further counted run; this build's timings are not reported. */
        if (run_once(&request, shared, NULL, NULL, 1) != 0) fail(EXIT_FAILURE_OPERATION, "operation: counted run failed");
#endif
        printf("{\"engine\":\"libxmlsec1\",\"scenario\":\"%s\",\"operation\":\"%s\",\"boundary\":\"%s\",\"samples_ns\":[",
               request.scenario, request.operation, request.prepared ? "prepared" : "parse");
        for (long i = 0; i < request.samples; ++i) printf("%s%llu", i ? "," : "", times[i]);
#ifdef LIBRARY_PROFILE
        printf("],\"allocations\":{\"calls\":%zu,\"bytes\":%zu,\"peak_bytes\":%lld}", allocation_calls, allocated_bytes, peak_bytes > 0 ? peak_bytes : 0);
#else
        printf("],\"allocations\":null");
#endif
        printf(",\"input_bytes\":%d,\"output_bytes\":", request.input_length);
        if (!strcmp(request.operation, "verify")) printf("null}\n"); else printf("%d}\n", output_length);
        free(times);
        if (shared != NULL) xmlFreeDoc(shared);
    }
    xmlSecKeysMngrDestroy(request.keys);
    free(request.template_bytes);
    free(request.input);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
    return exit_status;
}
