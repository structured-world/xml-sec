/* The block cipher transform klasses of the default crypto library as a
 * libxmlsec1 caller uses them: their identities and key requirements, a
 * value encrypted and decrypted again through a transform context, the
 * length of its frame (the IV or nonce, padding, the tag), a key of the
 * wrong size, and a tampered GCM value. A fresh IV makes each cipher value
 * differ, so only lengths and round trips are printed. Built against the
 * libxmlsec1 oracle with its default crypto library and against this
 * crate, both must print the same. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    fprintf(stderr, "ciphers: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
            object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
            msg != NULL ? msg : "(null)");
}

static const xmlSecByte plaintext[] = "The quick brown fox jumps over the lazy dog";

static xmlSecKeyPtr key_of(xmlSecKeyDataId id, xmlSecByte fill, xmlSecSize size) {
    xmlSecByte bytes[32];
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    memset(bytes, fill, sizeof(bytes));
    xmlSecKeyDataBinRead(id, key, bytes, size, ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    return key;
}

/* Runs `id` with `operation` and `key` over `size` bytes of `data` into
 * `out`; returns the output length or -1. */
static int run(xmlSecTransformId id, xmlSecTransformOperation operation, xmlSecKeyPtr key,
               const xmlSecByte *data, xmlSecSize size, xmlSecByte *out) {
    int result = -1;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    transform->operation = operation;
    if (xmlSecTransformSetKey(transform, key) == 0 &&
        xmlSecTransformCtxBinaryExecute(ctx, data, size) == 0) {
        result = (int)xmlSecBufferGetSize(ctx->result);
        if (result > 0) {
            memcpy(out, xmlSecBufferGetData(ctx->result), (size_t)result);
        }
    }
    xmlSecTransformCtxDestroy(ctx);
    return result;
}

static void check(xmlSecTransformId id, xmlSecKeyDataId keyId, xmlSecSize keySize) {
    xmlSecByte encrypted[256];
    xmlSecByte decrypted[256];
    xmlSecKeyReq req;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    xmlSecKeyPtr key = key_of(keyId, 0x11, keySize);
    xmlSecKeyPtr short_key = key_of(keyId, 0x22, 8);
    int encrypted_size;
    int decrypted_size;

    printf("%s: href=%s usage=0x%x\n", id->name, id->href, id->usage);
    xmlSecKeyReqInitialize(&req);
    transform->operation = xmlSecTransformOperationEncrypt;
    printf("  encrypt req: %d", xmlSecTransformSetKeyReq(transform, &req));
    printf(" klass=%s type=0x%x usage=0x%x bits=%d\n", req.keyId->name, req.keyType,
           req.keyUsage, (int)req.keyBitsSize);
    transform->operation = xmlSecTransformOperationDecrypt;
    printf("  decrypt req: %d", xmlSecTransformSetKeyReq(transform, &req));
    printf(" usage=0x%x\n", req.keyUsage);
    xmlSecKeyReqFinalize(&req);
    xmlSecTransformCtxDestroy(ctx);

    encrypted_size = run(id, xmlSecTransformOperationEncrypt, key, plaintext,
                         sizeof(plaintext) - 1, encrypted);
    printf("  encrypted: %d\n", encrypted_size);
    decrypted_size = run(id, xmlSecTransformOperationDecrypt, key, encrypted,
                         (xmlSecSize)encrypted_size, decrypted);
    printf("  decrypted: %d %.*s\n", decrypted_size, decrypted_size > 0 ? decrypted_size : 0,
           (const char *)decrypted);
    printf("  short key: %d\n", run(id, xmlSecTransformOperationEncrypt, short_key, plaintext,
                                    sizeof(plaintext) - 1, encrypted));
    xmlSecKeyDestroy(key);
    xmlSecKeyDestroy(short_key);
}

/* A key wrap is deterministic (RFC 3394): the wrapped key is printed, then
 * unwrapped again, and a tampered one is refused. */
static void wrap(xmlSecTransformId id, xmlSecKeyDataId keyId, xmlSecSize kekSize) {
    static const xmlSecByte content_key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    xmlSecByte wrapped[64];
    xmlSecByte unwrapped[64];
    xmlSecKeyPtr kek = key_of(keyId, 0x0f, kekSize);
    int size;
    int i;
    printf("%s: href=%s usage=0x%x\n", id->name, id->href, id->usage);
    size = run(id, xmlSecTransformOperationEncrypt, kek, content_key, sizeof(content_key), wrapped);
    printf("  wrapped: %d ", size);
    for (i = 0; i < size; ++i) {
        printf("%02x", wrapped[i]);
    }
    printf("\n");
    printf("  unwrapped: %d same=%d\n",
           run(id, xmlSecTransformOperationDecrypt, kek, wrapped, (xmlSecSize)size, unwrapped),
           memcmp(unwrapped, content_key, sizeof(content_key)) == 0);
    wrapped[0] ^= 0x01;
    printf("  tampered: %d\n",
           run(id, xmlSecTransformOperationDecrypt, kek, wrapped, (xmlSecSize)size, unwrapped));
    xmlSecKeyDestroy(kek);
}

int main(void) {
    xmlSecByte encrypted[256];
    xmlSecByte decrypted[256];
    xmlSecKeyPtr key;
    int size;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    check(xmlSecTransformAes128CbcId, xmlSecKeyDataAesId, 16);
    check(xmlSecTransformAes256CbcId, xmlSecKeyDataAesId, 32);
    check(xmlSecTransformAes128GcmId, xmlSecKeyDataAesId, 16);
    check(xmlSecTransformAes256GcmId, xmlSecKeyDataAesId, 32);
    check(xmlSecTransformCamellia128CbcId, xmlSecKeyDataCamelliaId, 16);
    wrap(xmlSecTransformKWAes128Id, xmlSecKeyDataAesId, 16);
    wrap(xmlSecTransformKWAes256Id, xmlSecKeyDataAesId, 32);
    wrap(xmlSecTransformKWCamellia128Id, xmlSecKeyDataCamelliaId, 16);

    /* An authenticated cipher refuses a value whose tag was changed. */
    key = key_of(xmlSecKeyDataAesId, 0x33, 16);
    size = run(xmlSecTransformAes128GcmId, xmlSecTransformOperationEncrypt, key, plaintext,
               sizeof(plaintext) - 1, encrypted);
    encrypted[size - 1] ^= 0x01;
    printf("gcm tampered: %d\n", run(xmlSecTransformAes128GcmId, xmlSecTransformOperationDecrypt,
                                     key, encrypted, (xmlSecSize)size, decrypted));
    xmlSecKeyDestroy(key);

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
