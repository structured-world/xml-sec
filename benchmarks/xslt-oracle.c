/* Test-only libxslt oracle. Never linked into a product binary. */
#define _POSIX_C_SOURCE 200809L
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <libxslt/security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>

#ifdef XSLT_PROFILE
/* Separate instrumented executable: only libxml/libxslt allocator hooks are
 * counted, never libc startup or the runner's own sample buffers. */
typedef union { max_align_t alignment; size_t size; } Header;
static size_t live_bytes, peak_bytes, allocation_calls, allocated_bytes, baseline_bytes;
static int measuring;
static void observe(size_t bytes) {
    if (measuring) { ++allocation_calls; allocated_bytes += bytes; }
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
}
static void *tracked_malloc(size_t bytes) {
    if (bytes > SIZE_MAX - sizeof(Header)) return NULL;
    Header *block = malloc(sizeof(Header) + bytes);
    if (block == NULL) return NULL;
    block->size = bytes; live_bytes += bytes; observe(bytes);
    return block + 1;
}
static void tracked_free(void *pointer) {
    if (pointer == NULL) return;
    Header *block = (Header *)pointer - 1;
    live_bytes -= block->size; free(block);
}
static void *tracked_realloc(void *pointer, size_t bytes) {
    if (pointer == NULL) return tracked_malloc(bytes);
    if (bytes > SIZE_MAX - sizeof(Header)) return NULL;
    Header *old = (Header *)pointer - 1;
    size_t old_size = old->size;
    Header *block = realloc(old, sizeof(Header) + bytes);
    if (block == NULL) return NULL;
    block->size = bytes; live_bytes = live_bytes - old_size + bytes; observe(bytes);
    return block + 1;
}
static char *tracked_strdup(const char *text) {
    size_t size = strlen(text) + 1;
    char *copy = tracked_malloc(size);
    if (copy != NULL) memcpy(copy, text, size);
    return copy;
}
#endif

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(1); }
}

static char *read_bytes(const char *path, int *length) {
    FILE *file = fopen(path, "rb");
    require(file != NULL, "open fixture");
    require(fseek(file, 0, SEEK_END) == 0, "seek fixture");
    long size = ftell(file);
    require(size >= 0 && size < INT_MAX, "fixture size");
    rewind(file);
    char *bytes = malloc((size_t)size + 1);
    require(bytes != NULL, "fixture allocation");
    require(fread(bytes, 1, (size_t)size, file) == (size_t)size, "read fixture");
    require(fclose(file) == 0, "close fixture");
    bytes[size] = 0;
    *length = (int)size;
    return bytes;
}

static unsigned long long now_ns(void) {
    struct timespec time;
    require(clock_gettime(CLOCK_MONOTONIC, &time) == 0, "monotonic clock");
    return (unsigned long long)time.tv_sec * 1000000000ULL + (unsigned long long)time.tv_nsec;
}

static xsltStylesheetPtr compile(const char *bytes, int length) {
    xmlDocPtr doc = xmlReadMemory(bytes, length, "urn:benchmark:stylesheet", NULL, XML_PARSE_NONET);
    require(doc != NULL, "stylesheet XML");
    xsltStylesheetPtr sheet = xsltParseStylesheetDoc(doc);
    require(sheet != NULL, "stylesheet compilation");
    return sheet;
}

static xmlDocPtr apply(xsltStylesheetPtr sheet, xmlDocPtr source, xsltSecurityPrefsPtr security) {
    xsltTransformContextPtr context = xsltNewTransformContext(sheet, source);
    require(context != NULL, "transform context");
    require(xsltSetCtxtSecurityPrefs(security, context) == 0, "security preferences");
    xmlDocPtr result = xsltApplyStylesheetUser(sheet, source, NULL, NULL, NULL, context);
    require(result != NULL && context->state == XSLT_STATE_OK, "transformation");
    xsltFreeTransformContext(context);
    return result;
}

int main(int argc, char **argv) {
    require(argc == 6, "usage: xslt-oracle PHASE STYLESHEET SOURCE EXPECTED SAMPLES");
    const char *phase = argv[1];
    require(!strcmp(phase, "compile") || !strcmp(phase, "tree") || !strcmp(phase, "serialize") ||
            !strcmp(phase, "retained") || !strcmp(phase, "end_to_end"), "unknown phase");
    char *end = NULL;
    long samples = strtol(argv[5], &end, 10);
    require(end != argv[5] && *end == 0 && samples >= 1 && samples <= 100000, "sample count");
    int style_length, source_length, expected_length;
    char *style_bytes = read_bytes(argv[2], &style_length);
    char *source_bytes = read_bytes(argv[3], &source_length);
    char *expected = read_bytes(argv[4], &expected_length);
#ifdef XSLT_PROFILE
    require(xmlMemSetup(tracked_free, tracked_malloc, tracked_realloc, tracked_strdup) == 0, "allocator hooks");
#endif
    xsltInit();
    xsltSecurityPrefsPtr security = xsltNewSecurityPrefs();
    require(security != NULL, "security allocation");
    for (int option = XSLT_SECPREF_READ_FILE; option <= XSLT_SECPREF_WRITE_NETWORK; ++option)
        require(xsltSetSecurityPrefs(security, (xsltSecurityOption)option, xsltSecurityForbid) == 0, "deny I/O");
    xsltStylesheetPtr sheet = compile(style_bytes, style_length);
    xmlDocPtr source = xmlReadMemory(source_bytes, source_length, "urn:benchmark:source", NULL, XML_PARSE_NONET);
    require(source != NULL, "source XML");
    xmlDocPtr initial = apply(sheet, source, security);
    xmlChar *check = NULL;
    int check_length = 0;
    require(xsltSaveResultToString(&check, &check_length, initial, sheet) >= 0, "check serialization");
    require(check_length == expected_length && !memcmp(check, expected, (size_t)expected_length), "oracle output differs");
    xmlFree(check);
    xmlFreeDoc(initial);
    /* Reporting and file I/O are outside individual samples. Warmups match Rust. */
    unsigned long long *times = malloc((size_t)samples * sizeof(*times));
    require(times != NULL, "sample allocation");
    for (long i = -3; i < samples; ++i) {
        xmlDocPtr result = !strcmp(phase, "serialize") ? apply(sheet, source, security) : NULL;
        xmlChar *output = NULL;
        int length = 0;
#ifdef XSLT_PROFILE
        allocation_calls = 0; allocated_bytes = 0; baseline_bytes = live_bytes;
        peak_bytes = live_bytes; measuring = 1;
#endif
        unsigned long long start = now_ns();
        if (!strcmp(phase, "compile")) {
            xsltStylesheetPtr temporary = compile(style_bytes, style_length);
            xsltFreeStylesheet(temporary);
        } else {
            xsltStylesheetPtr active = sheet;
            xmlDocPtr input = source;
            if (!strcmp(phase, "end_to_end")) {
                active = compile(style_bytes, style_length);
                input = xmlReadMemory(source_bytes, source_length, "urn:benchmark:source", NULL, XML_PARSE_NONET);
                require(input != NULL, "source parse");
            }
            if (result == NULL) result = apply(active, input, security);
            if (strcmp(phase, "tree"))
                require(xsltSaveResultToString(&output, &length, result, active) >= 0, "serialization");
            xmlFreeDoc(result);
            if (active != sheet) { xmlFreeDoc(input); xsltFreeStylesheet(active); }
        }
        unsigned long long elapsed = now_ns() - start;
#ifdef XSLT_PROFILE
        measuring = 0;
#endif
        if (output != NULL) {
            require(length == expected_length && !memcmp(output, expected, (size_t)length), "sample output differs");
            xmlFree(output);
        }
        if (i >= 0) times[i] = elapsed;
    }
    printf("{\"engine\":\"libxslt\",\"libxslt_version\":\"%s\",\"libxml_version\":\"%s\",\"phase\":\"%s\",\"samples_ns\":[", xsltEngineVersion, xmlParserVersion, phase);
    for (long i = 0; i < samples; ++i) printf("%s%llu", i ? "," : "", times[i]);
    printf("],\"source_bytes\":%d,\"stylesheet_bytes\":%d,\"output_bytes\":%d", source_length, style_length, expected_length);
#ifdef XSLT_PROFILE
    printf(",\"allocation_calls\":%zu,\"allocated_bytes\":%zu,\"peak_live_xml_bytes\":%zu,\"baseline_live_xml_bytes\":%zu,\"extra_peak_xml_bytes\":%zu", allocation_calls, allocated_bytes, peak_bytes, baseline_bytes, peak_bytes - baseline_bytes);
#endif
    printf("}\n");
    free(times); free(expected); free(source_bytes); free(style_bytes);
    xmlFreeDoc(source); xsltFreeStylesheet(sheet); xsltFreeSecurityPrefs(security);
    xsltCleanupGlobals(); xmlCleanupParser();
    return 0;
}
