/* The HMAC transform klasses of the default crypto library as a libxmlsec1
 * caller uses them: their identities, the key requirements, signing with an
 * HMAC key in full and truncated by HMACOutputLength (whole and partial last
 * byte), verifying a match, a wrong size and a wrong value, and the library's
 * minimum output length. Built against the pinned libxmlsec1 with its
 * default crypto library and against this crate, both must print the same.
 * Refusals whose reports name the implementation's own checks print their
 * result only. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/buffer.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

static int quiet;

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    if (quiet) {
        return;
    }
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

static const xmlSecByte input[] = "The quick brown fox jumps over the lazy dog";
static const xmlSecByte secret[] = "key-of-the-hmac-test";

static void print_hex(const char *label, const xmlSecByte *data, xmlSecSize size) {
    xmlSecSize i;
    printf("  %s:", label);
    for (i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static xmlSecKeyPtr hmac_key(void) {
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, secret, sizeof(secret) - 1, ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    return key;
}

/* A SignatureMethod element holding `length` as its HMACOutputLength, or no
 * child for NULL. */
static xmlDocPtr method(const char *length) {
    char xml[256];
    if (length != NULL) {
        snprintf(xml, sizeof(xml),
                 "<SignatureMethod xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                 "<HMACOutputLength>%s</HMACOutputLength></SignatureMethod>",
                 length);
    } else {
        snprintf(xml, sizeof(xml),
                 "<SignatureMethod xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>");
    }
    return xsReadMemory(xml, (int)strlen(xml), "method.xml", NULL, 0);
}

/* Runs `id` over `input` in `operation` with the HMACOutputLength `length`;
 * returns the transform's context, or NULL when reading the method fails. */
static xmlSecTransformCtxPtr run(xmlSecTransformId id, xmlSecTransformOperation operation,
                                 const char *length, int quietly) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    xmlSecKeyPtr key = hmac_key();
    xmlDocPtr doc = method(length);
    int ret;
    transform->operation = operation;
    quiet = quietly;
    ret = id->readNode(transform, xsDocGetRootElement(doc), ctx);
    quiet = 0;
    xsFreeDoc(doc);
    if (ret < 0) {
        printf("  length %s: refused\n", length);
        xmlSecKeyDestroy(key);
        xmlSecTransformCtxDestroy(ctx);
        return NULL;
    }
    printf("  set key: %d\n", xmlSecTransformSetKey(transform, key));
    xmlSecKeyDestroy(key);
    /* C leaves the order of argument evaluation unspecified, so a call and
     * the status it sets are never printed in one statement. */
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    printf("  execute: %d status=%d\n", ret, transform->status);
    return ctx;
}

/* Verifies `mac` with the first transform of `ctx`, prints the result as
 * `label` and releases the context. */
static void verify(const char *label, xmlSecTransformCtxPtr ctx, const xmlSecByte *mac, xmlSecSize size) {
    int ret = xmlSecTransformVerify(ctx->first, mac, size, ctx);
    printf("  verify %s: %d status=%d\n", label, ret, ctx->first->status);
    xmlSecTransformCtxDestroy(ctx);
}

static void check(xmlSecTransformId id, const char *truncated, const char *partial) {
    xmlSecKeyReq req;
    xmlSecTransformCtxPtr ctx;
    xmlSecTransformPtr transform;
    xmlSecByte mac[64];
    xmlSecSize size;
    int ret;

    printf("%s: href=%s usage=0x%x methods=%d%d%d%d%d%d%d\n", id->name, id->href, id->usage,
           id->readNode != NULL, id->setKeyReq != NULL, id->setKey != NULL, id->verify != NULL,
           id->pushBin != NULL, id->popBin != NULL, id->execute != NULL);

    ctx = xmlSecTransformCtxCreate();
    transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    xmlSecKeyReqInitialize(&req);
    transform->operation = xmlSecTransformOperationSign;
    printf("  sign req: %d", xmlSecTransformSetKeyReq(transform, &req));
    printf(" klass=%s type=0x%x usage=0x%x\n", req.keyId->name, req.keyType, req.keyUsage);
    transform->operation = xmlSecTransformOperationVerify;
    ret = xmlSecTransformSetKeyReq(transform, &req);
    printf("  verify req: %d usage=0x%x\n", ret, req.keyUsage);
    xmlSecKeyReqFinalize(&req);
    xmlSecTransformCtxDestroy(ctx);

    /* the full MAC */
    ctx = run(id, xmlSecTransformOperationSign, NULL, 0);
    size = xmlSecBufferGetSize(ctx->result);
    memcpy(mac, xmlSecBufferGetData(ctx->result), size);
    print_hex("full", mac, size);
    xmlSecTransformCtxDestroy(ctx);

    verify("match", run(id, xmlSecTransformOperationVerify, NULL, 0), mac, size);
    verify("short", run(id, xmlSecTransformOperationVerify, NULL, 0), mac, size - 1);
    mac[0] ^= 0x01;
    verify("mismatch", run(id, xmlSecTransformOperationVerify, NULL, 0), mac, size);

    /* truncated to whole bytes and to a partial last byte */
    ctx = run(id, xmlSecTransformOperationSign, truncated, 0);
    print_hex("truncated", xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
    size = xmlSecBufferGetSize(ctx->result);
    memcpy(mac, xmlSecBufferGetData(ctx->result), size);
    xmlSecTransformCtxDestroy(ctx);
    verify("truncated", run(id, xmlSecTransformOperationVerify, truncated, 0), mac, size);

    ctx = run(id, xmlSecTransformOperationSign, partial, 0);
    print_hex("partial", xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
    size = xmlSecBufferGetSize(ctx->result);
    memcpy(mac, xmlSecBufferGetData(ctx->result), size);
    xmlSecTransformCtxDestroy(ctx);
    /* bits past the selected length do not take part */
    mac[size - 1] ^= 0x01;
    verify("partial", run(id, xmlSecTransformOperationVerify, partial, 0), mac, size);

    /* a length below the minimum */
    ctx = run(id, xmlSecTransformOperationSign, "40", 1);
    if (ctx != NULL) {
        xmlSecTransformCtxDestroy(ctx);
    }
}

int main(void) {
    xmlSecTransformCtxPtr ctx;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    printf("min output: %d\n", (int)xmlSecTransformHmacGetMinOutputBitsSize());

    check(xmlSecTransformHmacMd5Id, "96", "100");
    check(xmlSecTransformHmacRipemd160Id, "96", "100");
    check(xmlSecTransformHmacSha1Id, "96", "100");
    check(xmlSecTransformHmacSha224Id, "128", "132");
    check(xmlSecTransformHmacSha256Id, "128", "132");
    check(xmlSecTransformHmacSha384Id, "192", "196");
    check(xmlSecTransformHmacSha512Id, "256", "260");

    /* raising the minimum refuses a length the default admits */
    xmlSecTransformHmacSetMinOutputBitsSize(200);
    printf("min output: %d\n", (int)xmlSecTransformHmacGetMinOutputBitsSize());
    ctx = run(xmlSecTransformHmacSha256Id, xmlSecTransformOperationSign, "160", 1);
    if (ctx != NULL) {
        xmlSecTransformCtxDestroy(ctx);
    }
    xmlSecTransformHmacSetMinOutputBitsSize(80);
    printf("min output: %d\n", (int)xmlSecTransformHmacGetMinOutputBitsSize());
    ctx = run(xmlSecTransformHmacSha256Id, xmlSecTransformOperationSign, "160", 0);
    if (ctx != NULL) {
        print_hex("restored", xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
        xmlSecTransformCtxDestroy(ctx);
    }

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
