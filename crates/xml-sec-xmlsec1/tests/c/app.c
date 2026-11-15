/* The application key loading of the default crypto library as a libxmlsec1
 * caller uses it: private and public keys from PEM and DER in memory and
 * from encrypted PEM with an explicit password or a password callback, the
 * formats a key cannot be read in, and signing with a loaded private key
 * through a transform context, verified with the loaded public key. The
 * program reads the key files and passes their bytes. Built against the
 * pinned libxmlsec1 with its default crypto library and against this crate,
 * both must print the same; the reports of failures whose wording belongs
 * to each implementation are hidden. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/base64.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/transforms.h>

static int quiet = 0;

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

#define RSA_KEY "tests/fixtures/keys/rsa/rsa-2048-key.pem"
#define RSA_PUBLIC "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
#define RSA_ENCRYPTED "tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem"
#define EC_KEY "tests/fixtures/keys/ec/ec-prime256v1-key.pem"
#define EC_PUBLIC "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"

/* An OpenSSL pem_password_cb answering with the password in `context`. */
static int password(char *buf, int size, int rwflag, void *context) {
    const char *secret = context;
    int length = (int)strlen(secret);
    printf("  password callback: size>=1024=%d rwflag=%d\n", size >= 1024, rwflag);
    if (length > size) {
        return -1;
    }
    memcpy(buf, secret, (size_t)length);
    return length;
}

/* The key in the file `path`, which the program reads, loaded from memory. */
static xmlSecKeyPtr load(const char *path, xmlSecKeyDataFormat format, const char *pwd,
                         void *callback, void *context) {
    static xmlSecByte bytes[16384];
    size_t size;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    size = fread(bytes, 1, sizeof(bytes), file);
    fclose(file);
    return xmlSecCryptoAppKeyLoadMemory(bytes, (xmlSecSize)size, format, pwd, callback, context);
}

/* Prints what `key`, loaded as `label`, holds and returns it. */
static xmlSecKeyPtr show(const char *label, xmlSecKeyPtr key, int private_key) {
    xmlSecKeyDataPtr value;
    if (key == NULL) {
        printf("%s: no key\n", label);
        return NULL;
    }
    value = xmlSecKeyGetValue(key);
    printf("%s: klass=%s size=%u", label,
           value != NULL ? (const char *)value->id->name : "(none)",
           value != NULL ? (unsigned)xmlSecKeyDataGetSize(value) : 0u);
    /* A public key's type differs between backends; a private key holds
     * both halves in each. */
    if (private_key && value != NULL) {
        printf(" type=0x%x", xmlSecKeyDataGetType(value));
    }
    printf("\n");
    return key;
}

/* The DER body of the PEM file `path` in `out`; returns its size. */
static xmlSecSize der_of(const char *path, xmlSecByte *out, xmlSecSize capacity) {
    static char text[8192];
    char *body;
    char *end;
    size_t length;
    xmlSecSize written = 0;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    length = fread(text, 1, sizeof(text) - 1, file);
    fclose(file);
    text[length] = '\0';
    /* The body runs from the line after the BEGIN line to the END line, with
     * either line ending; the decoder skips the line breaks inside it. */
    body = strstr(text, "-----BEGIN");
    body = body != NULL ? strchr(body, '\n') : NULL;
    end = body != NULL ? strstr(body, "-----END") : NULL;
    if (body == NULL || end == NULL) {
        return 0;
    }
    *end = '\0';
    if (xmlSecBase64Decode_ex((const xmlChar *)(body + 1), out, capacity, &written) < 0) {
        return 0;
    }
    return written;
}

/* Signs `input` with `private_key` by `id`; prints the signature when
 * `print`, then verifies it with `public_key`. Returns 0 only when the key
 * was set, both runs executed and the verification reported success: a
 * failed status is not a nonzero return, so the status is checked too. */
static int sign(xmlSecTransformId id, xmlSecKeyPtr private_key, xmlSecKeyPtr public_key,
                int print) {
    xmlSecByte value[1024];
    xmlSecSize size = 0;
    xmlSecSize i;
    int ret;
    int set;
    int ok;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    transform->operation = xmlSecTransformOperationSign;
    set = xmlSecTransformSetKey(transform, private_key);
    printf("%s sign: set key=%d", id->name, set);
    /* C leaves the order of argument evaluation unspecified, so a call and
     * the status it sets are never printed in one statement. */
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    printf(" execute=%d status=%d", ret, transform->status);
    ok = set == 0 && ret == 0;
    if (ctx->result != NULL) {
        size = xmlSecBufferGetSize(ctx->result);
        if (size <= sizeof(value)) {
            memcpy(value, xmlSecBufferGetData(ctx->result), size);
        }
    }
    printf(" size=%u\n", (unsigned)size);
    ok = ok && size > 0 && size <= sizeof(value);
    if (print) {
        printf("  ");
        for (i = 0; i < size && i < sizeof(value); ++i) {
            printf("%02x", value[i]);
        }
        printf("\n");
    }
    xmlSecTransformCtxDestroy(ctx);

    ctx = xmlSecTransformCtxCreate();
    transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    transform->operation = xmlSecTransformOperationVerify;
    set = xmlSecTransformSetKey(transform, public_key);
    printf("  verify: set key=%d", set);
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    printf(" execute=%d", ret);
    ok = ok && set == 0 && ret == 0;
    ret = xmlSecTransformVerify(transform, value, size, ctx);
    printf(" verify=%d status=%d\n", ret, transform->status);
    ok = ok && ret == 0 && transform->status == xmlSecTransformStatusOk;
    xmlSecTransformCtxDestroy(ctx);
    return ok ? 0 : -1;
}

/* Signing with a key that holds no private half fails. */
static void sign_public(xmlSecTransformId id, xmlSecKeyPtr public_key) {
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    int set;
    int executed;
    transform->operation = xmlSecTransformOperationSign;
    quiet = 1;
    set = xmlSecTransformSetKey(transform, public_key);
    executed = set < 0 ? -1 : xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    quiet = 0;
    printf("%s sign with a public key fails: %d\n", id->name, set < 0 || executed < 0);
    xmlSecTransformCtxDestroy(ctx);
}

static void fails(const char *label, xmlSecKeyPtr key) {
    printf("%s fails: %d\n", label, key == NULL);
    if (key != NULL) {
        xmlSecKeyDestroy(key);
    }
}

int main(void) {
    static xmlSecByte der[8192];
    xmlSecSize size;
    xmlSecKeyPtr rsa;
    xmlSecKeyPtr rsa_public;
    xmlSecKeyPtr ec;
    xmlSecKeyPtr ec_public;
    xmlSecKeyPtr key;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    rsa = show("rsa pem", load(RSA_KEY, xmlSecKeyDataFormatPem, NULL, NULL, NULL), 1);
    rsa_public = show("rsa public pem", load(RSA_PUBLIC, xmlSecKeyDataFormatPem, NULL, NULL, NULL),
                      0);
    ec = show("ec pem", load(EC_KEY, xmlSecKeyDataFormatPem, NULL, NULL, NULL),
              1);
    ec_public = show("ec public pem",
                     load(EC_PUBLIC, xmlSecKeyDataFormatPem, NULL, NULL, NULL),
                     0);
    key = show("rsa pkcs8 pem",
               load(RSA_KEY, xmlSecKeyDataFormatPkcs8Pem, NULL, NULL, NULL), 1);
    xmlSecKeyDestroy(key);

    /* Both DER keys must load: "no key" alone would let the comparison pass
     * without exercising the DER import. */
    size = der_of(RSA_KEY, der, sizeof(der));
    key = show("rsa der memory",
               xmlSecCryptoAppKeyLoadMemory(der, size, xmlSecKeyDataFormatDer, NULL, NULL, NULL),
               1);
    if (key == NULL) {
        printf("the DER private key did not load\n");
        return 1;
    }
    xmlSecKeyDestroy(key);
    size = der_of(RSA_PUBLIC, der, sizeof(der));
    key = show("rsa public der memory",
               xmlSecCryptoAppKeyLoadMemory(der, size, xmlSecKeyDataFormatDer, NULL, NULL, NULL),
               0);
    if (key == NULL) {
        printf("the DER public key did not load\n");
        return 1;
    }
    xmlSecKeyDestroy(key);

    /* The encrypted key must load both ways: printing "no key" alone would
     * let the run pass without exercising either. */
    key = show("rsa encrypted with password",
               load(RSA_ENCRYPTED, xmlSecKeyDataFormatPem,
                                      "legacy-rsa-password", NULL, NULL),
               1);
    if (key == NULL) {
        printf("the encrypted key did not load with its password\n");
        return 1;
    }
    xmlSecKeyDestroy(key);
    key = show("rsa encrypted with callback",
               load(RSA_ENCRYPTED, xmlSecKeyDataFormatPem, NULL,
                                      (void *)password, (void *)"legacy-rsa-password"),
               1);
    if (key == NULL) {
        printf("the encrypted key did not load through the callback\n");
        return 1;
    }
    xmlSecKeyDestroy(key);

    quiet = 1;
    key = load(RSA_ENCRYPTED, xmlSecKeyDataFormatPem, "wrong", NULL, NULL);
    quiet = 0;
    fails("rsa encrypted with a wrong password", key);
    quiet = 1;
    key = load(RSA_PUBLIC, xmlSecKeyDataFormatPkcs8Pem, NULL, NULL, NULL);
    quiet = 0;
    fails("public key as pkcs8", key);
    quiet = 1;
    key = load(RSA_KEY, xmlSecKeyDataFormatBinary, NULL, NULL, NULL);
    quiet = 0;
    fails("binary format", key);
    quiet = 1;
    key = xmlSecCryptoAppKeyLoadMemory((const xmlSecByte *)"garbage", 7, xmlSecKeyDataFormatDer,
                                       NULL, NULL, NULL);
    quiet = 0;
    fails("garbage der", key);

    /* The signing checks below need every key: a fixture that does not load
     * fails the run rather than skipping them. */
    if (rsa == NULL || rsa_public == NULL || ec == NULL || ec_public == NULL) {
        printf("a required key fixture did not load\n");
        return 1;
    }
    if (sign(xmlSecTransformRsaSha256Id, rsa, rsa_public, 1) < 0 ||
        sign(xmlSecTransformRsaPssSha256Id, rsa, rsa_public, 0) < 0) {
        printf("an RSA signature did not verify\n");
        return 1;
    }
    sign_public(xmlSecTransformRsaSha256Id, rsa_public);
    if (sign(xmlSecTransformEcdsaSha256Id, ec, ec_public, 0) < 0) {
        printf("an ECDSA signature did not verify\n");
        return 1;
    }

    xmlSecKeyDestroy(rsa);
    xmlSecKeyDestroy(rsa_public);
    xmlSecKeyDestroy(ec);
    xmlSecKeyDestroy(ec_public);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
