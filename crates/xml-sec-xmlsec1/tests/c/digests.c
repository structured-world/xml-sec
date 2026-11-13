/* The digest transform klasses of the default crypto library as a libxmlsec1
 * caller uses them: their identities, computing a digest through a transform
 * context in one chunk and in many, and verifying a digest that matches, has
 * the wrong size or the wrong value. Built against the pinned libxmlsec1
 * with its default crypto library and against this crate, both must print
 * the same. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/buffer.h>
#include <xmlsec/dl.h>
#include <xmlsec/transforms.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

static const xmlSecByte input[] = "The quick brown fox jumps over the lazy dog";

static void describe(xmlSecTransformId id) {
    printf("%s: href=%s usage=0x%x methods=%d%d%d%d%d%d%d%d\n", id->name, id->href, id->usage,
           id->initialize != NULL, id->finalize != NULL, id->readNode != NULL,
           id->verify != NULL, id->pushBin != NULL, id->popBin != NULL, id->pushXml != NULL,
           id->execute != NULL);
}

/* The largest digest the klasses produce, SHA-512's. */
#define DIGEST_CAPACITY 64

/* The digest of `input` by `id`, written into `out` of DIGEST_CAPACITY
 * bytes; returns its size, zero when none was produced or it does not fit. */
static xmlSecSize digest(xmlSecTransformId id, xmlSecSize chunk, xmlSecByte *out) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    xmlSecSize size = 0;
    int ret;
    transform->operation = xmlSecTransformOperationSign;
    if (chunk > 0) {
        ctx->binaryChunkSize = chunk;
    }
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    if (ret == 0 && ctx->result != NULL && xmlSecBufferGetSize(ctx->result) <= DIGEST_CAPACITY) {
        size = xmlSecBufferGetSize(ctx->result);
        memcpy(out, xmlSecBufferGetData(ctx->result), size);
    }
    printf("  %s sign: ret=%d status=%d size=%d\n", id->name, ret, transform->status, (int)size);
    xmlSecTransformCtxDestroy(ctx);
    return size;
}

static void print_hex(const xmlSecByte *data, xmlSecSize size) {
    xmlSecSize i;
    printf("  ");
    for (i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Verifies `expected` (`size` bytes) as the digest of `input` by `id`. */
static void verify(const char *label, xmlSecTransformId id, const xmlSecByte *expected,
                   xmlSecSize size) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    int ret;
    transform->operation = xmlSecTransformOperationVerify;
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    printf("  %s execute: ret=%d status=%d\n", label, ret, transform->status);
    ret = xmlSecTransformVerify(transform, expected, size, ctx);
    printf("  %s verify: ret=%d status=%d\n", label, ret, transform->status);
    xmlSecTransformCtxDestroy(ctx);
}

/* Runs the checks of `id`; nonzero when a digest was not produced, since
 * the comparisons below need one of a known size. */
static int check(xmlSecTransformId id) {
    xmlSecByte one[DIGEST_CAPACITY];
    xmlSecByte many[DIGEST_CAPACITY];
    xmlSecSize size;
    describe(id);
    size = digest(id, 0, one);
    if (size == 0 || digest(id, 5, many) != size) {
        printf("  %s: no digest\n", id->name);
        return 1;
    }
    print_hex(one, size);
    printf("  chunked equal: %d\n", memcmp(one, many, size) == 0);
    verify("match", id, one, size);
    verify("short", id, one, size - 1);
    one[0] ^= 0x01;
    verify("mismatch", id, one, size);
    return 0;
}

int main(void) {
    int failed = 0;
    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    failed |= check(xmlSecTransformMd5Id);
    failed |= check(xmlSecTransformRipemd160Id);
    failed |= check(xmlSecTransformSha1Id);
    failed |= check(xmlSecTransformSha224Id);
    failed |= check(xmlSecTransformSha256Id);
    failed |= check(xmlSecTransformSha384Id);
    failed |= check(xmlSecTransformSha512Id);
    failed |= check(xmlSecTransformSha3_224Id);
    failed |= check(xmlSecTransformSha3_256Id);
    failed |= check(xmlSecTransformSha3_384Id);
    failed |= check(xmlSecTransformSha3_512Id);

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return failed;
}
