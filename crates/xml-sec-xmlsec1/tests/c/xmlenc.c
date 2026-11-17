/* The encryption context as a libxmlsec1 caller uses it to decrypt: an
 * Element EncryptedData replaced by its plaintext, the replaced node
 * returned on request, a Content one, one without a Type decrypted to a
 * buffer and left in place, a missing key, a wrong key, and a node that is
 * no EncryptedData. The cipher values are made with the AES-CBC transform
 * of the same library, so both libraries decrypt their own. Built against
 * the libxmlsec1 oracle with its default crypto library and against this
 * crate, both must print the same. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/base64.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>

/* Set while a report's reason depends on the random IV. */
static int quiet = 0;

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    fprintf(stderr, "xmlenc: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
            object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
            msg != NULL ? msg : "(null)");
    if (!quiet && reason != XMLSEC_ERRORS_R_XMLSEC_FAILED) {
        printf("  report: reason=%d\n", reason);
    }
}

static xmlSecKeyPtr aes_key(xmlSecByte fill) {
    xmlSecByte bytes[16];
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    memset(bytes, fill, sizeof(bytes));
    xmlSecKeyDataBinRead(xmlSecKeyDataAesId, key, bytes, sizeof(bytes), ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    return key;
}

/* The Base64 text of `plaintext` encrypted with AES-128-CBC under `key`. */
static xmlChar *cipher_value(const char *plaintext, xmlSecKeyPtr key) {
    xmlChar *encoded = NULL;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformAes128CbcId);
    transform->operation = xmlSecTransformOperationEncrypt;
    if (xmlSecTransformSetKey(transform, key) == 0 &&
        xmlSecTransformCtxBinaryExecute(ctx, (const xmlSecByte *)plaintext, strlen(plaintext)) == 0) {
        encoded = xmlSecBase64Encode(xmlSecBufferGetData(ctx->result),
                                     xmlSecBufferGetSize(ctx->result), 0);
    }
    xmlSecTransformCtxDestroy(ctx);
    return encoded;
}

/* A document whose `data` element holds an EncryptedData of `type` over
 * `plaintext`. */
static xmlDocPtr encrypted(const xmlChar *type, const char *plaintext, xmlSecKeyPtr key) {
    static const char xml[] = "<Envelope xmlns=\"urn:envelope\"><data/></Envelope>";
    xmlDocPtr doc = xsReadMemory(xml, (int)strlen(xml), "doc.xml", NULL, 0);
    xmlNodePtr data = xmlSecFindNode(xsDocGetRootElement(doc), BAD_CAST "data", BAD_CAST "urn:envelope");
    xmlNodePtr enc = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, type, NULL, NULL);
    xmlNodePtr value = xmlSecTmplEncDataEnsureCipherValue(enc);
    xmlChar *text = cipher_value(plaintext, key);
    xsNodeSetContent(value, text);
    xsFree(text);
    xmlSecAddChildNode(data, enc);
    return doc;
}

static xmlNodePtr enc_data(xmlDocPtr doc) {
    return xmlSecFindNode(xsDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
}

static void dump(const char *label, xmlDocPtr doc) {
    xmlChar *text = NULL;
    int size = 0;
    xsDocDumpMemory(doc, &text, &size);
    printf("%s: %.*s", label, size, (const char *)text);
    xsFree(text);
}

static void decrypt(const char *label, const xmlChar *type, const char *plaintext,
                    unsigned int flags) {
    xmlSecKeyPtr key = aes_key(0x11);
    xmlDocPtr doc = encrypted(type, plaintext, key);
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    int ret;
    xmlSecKeyDestroy(key);
    printf("%s\n", label);
    ctx->flags = flags;
    ctx->encKey = aes_key(0x11);
    ret = xmlSecEncCtxDecrypt(ctx, enc_data(doc));
    printf("  decrypt: %d replaced=%d failure=%s result=%.*s\n", ret, ctx->resultReplaced,
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason),
           ctx->result != NULL ? (int)xmlSecBufferGetSize(ctx->result) : 0,
           ctx->result != NULL ? (const char *)xmlSecBufferGetData(ctx->result) : "");
    printf("  returned node: %s\n", ctx->replacedNodeList != NULL ? "yes" : "no");
    /* A kept EncryptedData holds a cipher value of a fresh IV. */
    if (ctx->resultReplaced) {
        dump("  document", doc);
    } else {
        printf("  document: EncryptedData kept: %s\n", enc_data(doc) != NULL ? "yes" : "no");
    }
    xmlSecEncCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* Encrypts the `secret` element (or its content) of a document with a
 * template of `type`, then decrypts it again. */
static void round_trip(const char *label, const xmlChar *type) {
    static const char xml[] =
        "<Envelope xmlns=\"urn:envelope\"><secret Id=\"s\">pay<b>load</b></secret></Envelope>";
    xmlDocPtr doc = xsReadMemory(xml, (int)strlen(xml), "doc.xml", NULL, 0);
    xmlNodePtr secret = xmlSecFindNode(xsDocGetRootElement(doc), BAD_CAST "secret", BAD_CAST "urn:envelope");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, type, NULL, NULL);
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    printf("%s\n", label);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    ctx->encKey = aes_key(0x44);
    printf("  encrypt: %d", xmlSecEncCtxXmlEncrypt(ctx, tmpl, secret));
    printf(" replaced=%d base64=%d\n", ctx->resultReplaced, ctx->resultBase64Encoded);
    printf("  encrypted data in place: %s\n", enc_data(doc) != NULL ? "yes" : "no");
    xmlSecEncCtxDestroy(ctx);
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x44);
    printf("  decrypt: %d\n", xmlSecEncCtxDecrypt(ctx, enc_data(doc)));
    dump("  document", doc);
    xmlSecEncCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* Encrypts bytes into a standalone template and decrypts them to a buffer. */
static void binary_round_trip(void) {
    static const char bytes[] = "binary \x01\x02 bytes";
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes256GcmId, NULL, NULL, NULL, NULL);
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    xmlSecBufferPtr result;
    xmlSecKeyInfoCtxPtr key_ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecByte key_bytes[32];
    xmlSecKeyPtr key;
    memset(key_bytes, 0x55, sizeof(key_bytes));
    xsDocSetRootElement(doc, tmpl);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    printf("binary\n");
    key = xmlSecKeyCreate();
    xmlSecKeyDataBinRead(xmlSecKeyDataAesId, key, key_bytes, sizeof(key_bytes), key_ctx);
    ctx->encKey = key;
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, tmpl, (const xmlSecByte *)bytes, sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    ctx = xmlSecEncCtxCreate(NULL);
    key = xmlSecKeyCreate();
    xmlSecKeyDataBinRead(xmlSecKeyDataAesId, key, key_bytes, sizeof(key_bytes), key_ctx);
    ctx->encKey = key;
    result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
    printf("  decrypted: %d same=%d\n", result != NULL ? (int)xmlSecBufferGetSize(result) : -1,
           result != NULL && xmlSecBufferGetSize(result) == sizeof(bytes) - 1 &&
               memcmp(xmlSecBufferGetData(result), bytes, sizeof(bytes) - 1) == 0);
    xmlSecEncCtxDestroy(ctx);
    xmlSecKeyInfoCtxDestroy(key_ctx);
    xsFreeDoc(doc);
}

int main(void) {
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr mngr;
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

    decrypt("element", xmlSecTypeEncElement, "<secret xmlns=\"urn:envelope\">payload</secret>", 0);
    decrypt("element returning the node", xmlSecTypeEncElement,
            "<secret xmlns=\"urn:envelope\">payload</secret>", XMLSEC_ENC_FLAGS_RETURN_REPLACED_NODE);
    decrypt("content", xmlSecTypeEncContent, "text <b xmlns=\"urn:envelope\">bold</b>", 0);
    decrypt("no type", NULL, "raw bytes", 0);
    round_trip("encrypt element", xmlSecTypeEncElement);
    round_trip("encrypt content", xmlSecTypeEncContent);
    round_trip("encrypt without a type", NULL);
    binary_round_trip();

    /* No key: the keys manager has none. */
    key = aes_key(0x11);
    doc = encrypted(xmlSecTypeEncElement, "<secret/>", key);
    xmlSecKeyDestroy(key);
    mngr = xmlSecKeysMngrCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    ctx = xmlSecEncCtxCreate(mngr);
    printf("missing key\n");
    printf("  decrypt: %d", xmlSecEncCtxDecrypt(ctx, enc_data(doc)));
    printf(" failure=%s\n", xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    xmlSecEncCtxDestroy(ctx);

    /* A wrong key fails the padding or, rarely, the plaintext: which one
     * depends on the IV, so the reports are not compared. */
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x22);
    printf("wrong key\n");
    quiet = 1;
    printf("  decrypt: %d\n", xmlSecEncCtxDecrypt(ctx, enc_data(doc)) < 0 ? -1 : 0);
    quiet = 0;
    xmlSecEncCtxDestroy(ctx);

    /* A node that is no EncryptedData. */
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x11);
    printf("not encrypted data\n");
    printf("  decrypt: %d\n", xmlSecEncCtxDecrypt(ctx, xsDocGetRootElement(doc)));
    xmlSecEncCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
