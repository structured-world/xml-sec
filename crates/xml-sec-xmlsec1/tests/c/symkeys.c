/* The symmetric key-data klasses of the default crypto library and the
 * binary key-data value they are made of, as a libxmlsec1 caller uses them:
 * the klasses' identities, generating a key, reading and writing a KeyValue
 * child and raw bytes, the checks against a value the key already has and
 * against the key requirements, duplicating, and the debug dumps. Built
 * against the pinned libxmlsec1 with its default crypto library and against
 * this crate, both must print the same. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/buffer.h>
#define XMLSEC_PRIVATE 1
#include <xmlsec/private.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

static const char *text(const xmlChar *value) {
    return value != NULL ? (const char *)value : "(null)";
}

static void describe(const char *label, xmlSecKeyDataId id) {
    if (id == NULL) {
        printf("%s: none\n", label);
        return;
    }
    printf("%s: name=%s href=%s usage=0x%x node=%s ns=%s binary=%d methods=%d%d%d%d%d%d%d%d%d%d%d%d\n",
           label, text(id->name), text(id->href), id->usage, text(id->dataNodeName),
           text(id->dataNodeNs), id->objSize == sizeof(xmlSecKeyData) + sizeof(xmlSecBuffer),
           id->initialize != NULL, id->duplicate != NULL, id->finalize != NULL,
           id->generate != NULL, id->getType != NULL, id->getSize != NULL, id->xmlRead != NULL,
           id->xmlWrite != NULL, id->binRead != NULL, id->binWrite != NULL,
           id->debugDump != NULL, id->debugXmlDump != NULL);
}

static void show_key(const char *label, xmlSecKeyPtr key) {
    xmlSecKeyDataPtr value = xmlSecKeyGetValue(key);
    if (value == NULL) {
        printf("%s: no value\n", label);
        return;
    }
    printf("%s: klass=%s size=%d type=0x%x\n", label, text(value->id->name),
           (int)xmlSecKeyGetSize(key), xmlSecKeyGetType(key));
}

/* Reads `content` as a KeyValue child of klass `id` into `key`. */
static int read_value(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr ctx,
                      const char *content) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr node = xsNewDocNode(doc, NULL, id->dataNodeName, BAD_CAST content);
    int ret;
    xsDocSetRootElement(doc, node);
    ret = xmlSecKeyDataXmlRead(id, key, node, ctx);
    xsFreeDoc(doc);
    return ret;
}

/* Writes the value of `key` through klass `id` and prints the element. */
static void write_value(const char *label, xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlSecKeyInfoCtxPtr ctx) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr node = xsNewDocNode(doc, NULL, id->dataNodeName, NULL);
    xmlChar *content;
    int ret;
    xsDocSetRootElement(doc, node);
    ret = xmlSecKeyDataXmlWrite(id, key, node, ctx);
    content = xsNodeGetContent(node);
    printf("%s: %d [%s]\n", label, ret, text(content));
    xsFree(content);
    xsFreeDoc(doc);
}

static void bin_write(const char *label, xmlSecKeyDataId id, xmlSecKeyPtr key,
                      xmlSecKeyInfoCtxPtr ctx) {
    xmlSecByte *buf = NULL;
    xmlSecSize size = 0;
    xmlSecSize i;
    int ret = xmlSecKeyDataBinWrite(id, key, &buf, &size, ctx);
    printf("%s: %d size=%d bytes=", label, ret, (int)size);
    for (i = 0; buf != NULL && i < size; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    if (buf != NULL) {
        xsFree(buf);
    }
}

int main(void) {
    xmlSecCryptoDLFunctionsPtr table;
    xmlSecKeyInfoCtxPtr ctx;
    xmlSecKeyPtr key;
    xmlSecKeyPtr copy;
    xmlSecKeyDataPtr data;
    static const xmlSecByte raw[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }
    table = xmlSecCryptoDLGetFunctions();

    describe("aes", xmlSecKeyDataAesId);
    describe("des", xmlSecKeyDataDesId);
    describe("hmac", xmlSecKeyDataHmacId);
    describe("concatkdf", xmlSecKeyDataConcatKdfId);
    describe("pbkdf2", xmlSecKeyDataPbkdf2Id);
    describe("hkdf", xmlSecKeyDataHkdfId);
    describe("camellia",
             table->keyDataCamelliaGetKlass != NULL ? table->keyDataCamelliaGetKlass() : NULL);
    describe("chacha20",
             table->keyDataChaCha20GetKlass != NULL ? table->keyDataChaCha20GetKlass() : NULL);
    printf("registered aes: %d\n",
           xmlSecKeyDataIdListFind(xmlSecKeyDataIdsGet(), xmlSecKeyDataAesId));

    /* Generating: whole bytes of random data, a symmetric key. */
    key = xmlSecKeyGenerate(xmlSecKeyDataAesId, 128, xmlSecKeyDataTypeSymmetric);
    show_key("generate 128", key);
    xmlSecKeyDestroy(key);
    key = xmlSecKeyGenerate(xmlSecKeyDataHmacId, 12, xmlSecKeyDataTypeSymmetric);
    show_key("generate 12", key);
    xmlSecKeyDestroy(key);
    data = xmlSecKeyDataCreate(xmlSecKeyDataDesId);
    printf("empty: size=%d type=0x%x\n", (int)xmlSecKeyDataGetSize(data),
           xmlSecKeyDataGetType(data));
    printf("empty dump:\n");
    xmlSecKeyDataDebugDump(data, stdout);
    xmlSecKeyDataDebugXmlDump(data, stdout);
    xmlSecKeyDataDestroy(data);

    ctx = xmlSecKeyInfoCtxCreate(NULL);

    /* Reading a KeyValue child. */
    key = xmlSecKeyCreate();
    printf("read: %d\n", read_value(xmlSecKeyDataAesId, key, ctx, "  AAECAwQFBgcICQoLDA0ODw==\n"));
    show_key("read", key);
    printf("dump:\n");
    xmlSecKeyDataDebugDump(xmlSecKeyGetValue(key), stdout);
    xmlSecKeyDataDebugXmlDump(xmlSecKeyGetValue(key), stdout);
    printf("same again: %d\n", read_value(xmlSecKeyDataAesId, key, ctx, "AAECAwQFBgcICQoLDA0ODw=="));
    printf("other bytes: %d\n", read_value(xmlSecKeyDataAesId, key, ctx, "DwECAwQFBgcICQoLDA0ODw=="));
    printf("other size: %d\n", read_value(xmlSecKeyDataAesId, key, ctx, "AAECAw=="));
    printf("other klass: %d\n", read_value(xmlSecKeyDataDesId, key, ctx, "AAECAwQFBgcICQoLDA0ODw=="));

    /* Duplicating copies the value. */
    copy = xmlSecKeyDuplicate(key);
    show_key("duplicate", copy);
    xmlSecKeyDestroy(copy);

    /* Writing: only when the context asks for a symmetric key. */
    ctx->keyReq.keyType = xmlSecKeyDataTypePublic;
    write_value("write public", xmlSecKeyDataAesId, key, ctx);
    ctx->keyReq.keyType = xmlSecKeyDataTypeSymmetric;
    write_value("write symmetric", xmlSecKeyDataAesId, key, ctx);
    ctx->base64LineSize = 8;
    write_value("write lines", xmlSecKeyDataAesId, key, ctx);
    bin_write("bin write", xmlSecKeyDataAesId, key, ctx);
    ctx->keyReq.keyType = xmlSecKeyDataTypePrivate;
    bin_write("bin write private", xmlSecKeyDataAesId, key, ctx);
    xmlSecKeyDestroy(key);

    /* Contents that are not a value. */
    key = xmlSecKeyCreate();
    printf("empty node: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "   "));
    printf("bad base64: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "!!!!"));
    printf("decodes to nothing: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "===="));
    show_key("after bad", key);

    /* The key requirements decide what is accepted. */
    xmlSecKeyInfoCtxReset(ctx);
    ctx->keyReq.keyId = xmlSecKeyDataDesId;
    printf("wrong required klass: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "AAECAw=="));
    ctx->keyReq.keyId = xmlSecKeyDataHmacId;
    ctx->keyReq.keyBitsSize = 64;
    printf("too short: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "AAECAw=="));
    printf("long enough: %d\n", read_value(xmlSecKeyDataHmacId, key, ctx, "AAECAwQFBgc="));
    show_key("required", key);
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxReset(ctx);

    /* Raw bytes. */
    key = xmlSecKeyCreate();
    printf("bin read: %d\n", xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, raw, sizeof(raw), ctx));
    show_key("bin read", key);
    printf("bin read same: %d\n",
           xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, raw, sizeof(raw), ctx));
    printf("bin read shorter: %d\n", xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, raw, 4, ctx));
    printf("bin read empty: %d\n", xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, raw, 0, ctx));
    ctx->keyReq.keyType = xmlSecKeyDataTypeSymmetric;
    bin_write("bin write hmac", xmlSecKeyDataHmacId, key, ctx);
    xmlSecKeyDestroy(key);

    /* A derivation key has no element to dump. */
    key = xmlSecKeyCreate();
    printf("pbkdf2 bin read: %d\n",
           xmlSecKeyDataBinRead(xmlSecKeyDataPbkdf2Id, key, raw, sizeof(raw), ctx));
    show_key("pbkdf2", key);
    printf("pbkdf2 dump:\n");
    xmlSecKeyDataDebugDump(xmlSecKeyGetValue(key), stdout);
    xmlSecKeyDestroy(key);

    xmlSecKeyInfoCtxDestroy(ctx);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
