/* KeyInfo processing, keys managers and key stores as a libxmlsec1 caller
 * uses them: the KeyInfo context, reading a KeyInfo element through the
 * KeyName and KeyValue klasses and a key-data klass of the program's own,
 * writing a template, the keys manager with the simple keys store, a store
 * klass of the program's own and data stores. Built against the pinned
 * libxmlsec1 and against this crate, both must print the same keys, trees
 * and reports. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

typedef struct { xmlSecKeyData base; xmlSecBuffer value; } BinaryData;

static int secret_initialize(xmlSecKeyDataPtr data) {
    return xmlSecBufferInitialize(xmlSecKeyDataBinaryValueGetBuffer(data), 0);
}

static int secret_duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecBufferPtr from = xmlSecKeyDataBinaryValueGetBuffer(src);
    return xmlSecKeyDataBinaryValueSetBuffer(dst, xmlSecBufferGetData(from), xmlSecBufferGetSize(from));
}

static void secret_finalize(xmlSecKeyDataPtr data) {
    xmlSecBufferFinalize(xmlSecKeyDataBinaryValueGetBuffer(data));
}

static xmlSecKeyDataType secret_type(xmlSecKeyDataPtr data) {
    (void)data;
    return xmlSecKeyDataTypeSymmetric;
}

static int secret_xml_read(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr ctx) {
    xmlChar *content = xsNodeGetContent(node);
    xmlSecKeyDataPtr data = xmlSecKeyDataCreate(id);
    (void)ctx;
    xmlSecKeyDataBinaryValueSetBuffer(data, content, (xmlSecSize)strlen((const char *)content));
    xsFree(content);
    printf("  secret read: mode=%d\n", ctx->mode);
    return xmlSecKeySetValue(key, data);
}

static int secret_xml_write(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr ctx) {
    xmlSecBufferPtr buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlChar text[64];
    (void)id;
    (void)ctx;
    snprintf((char *)text, sizeof(text), "%.*s", (int)xmlSecBufferGetSize(buffer), (const char *)xmlSecBufferGetData(buffer));
    xsNodeSetContent(node, text);
    return 0;
}

static xmlSecKeyDataKlass secretKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-secret",
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    BAD_CAST "urn:test:secret", BAD_CAST "TestSecret", BAD_CAST "urn:test",
    secret_initialize, secret_duplicate, secret_finalize, NULL,
    secret_type, xmlSecKeyDataBinaryValueGetSize, NULL,
    secret_xml_read, secret_xml_write, NULL, NULL,
    NULL, NULL, NULL, NULL,
};

/* A store klass that finds one fixed key by name. */
typedef struct { xmlSecKeyStore base; xmlSecKeyPtr key; } FixedStore;

static int fixed_initialize(xmlSecKeyStorePtr store) {
    printf("  fixed store initialize\n");
    ((FixedStore *)store)->key = NULL;
    return 0;
}

static void fixed_finalize(xmlSecKeyStorePtr store) {
    printf("  fixed store finalize\n");
    if (((FixedStore *)store)->key != NULL) {
        xmlSecKeyDestroy(((FixedStore *)store)->key);
    }
}

static xmlSecKeyPtr fixed_find(xmlSecKeyStorePtr store, const xmlChar *name, xmlSecKeyInfoCtxPtr ctx) {
    xmlSecKeyPtr key = ((FixedStore *)store)->key;
    printf("  fixed store find: %s\n", name != NULL ? (const char *)name : "(null)");
    if (key == NULL || xmlSecKeyMatch(key, name, &ctx->keyReq) != 1) {
        return NULL;
    }
    return xmlSecKeyDuplicate(key);
}

static xmlSecKeyStoreKlass fixedKlass = {
    sizeof(xmlSecKeyStoreKlass), sizeof(FixedStore), BAD_CAST "fixed-store",
    fixed_initialize, fixed_finalize, fixed_find, NULL, NULL,
};

static xmlSecKeyDataStoreKlass dataStoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass), sizeof(xmlSecKeyDataStore), BAD_CAST "test-data-store",
    NULL, NULL, NULL, NULL,
};

static xmlSecKeyPtr secret_key(const char *name, const char *value) {
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecKeyDataPtr data = xmlSecKeyDataCreate(&secretKlass);
    xmlSecKeyDataBinaryValueSetBuffer(data, BAD_CAST value, (xmlSecSize)strlen(value));
    xmlSecKeySetValue(key, data);
    xmlSecKeySetName(key, BAD_CAST name);
    return key;
}

static void show_key(const char *label, xmlSecKeyPtr key) {
    if (key == NULL) {
        printf("%s: none\n", label);
        return;
    }
    printf("%s: name=%s value=%s size=%d\n", label, key->name != NULL ? (const char *)key->name : "(null)",
           key->value != NULL ? (const char *)key->value->id->name : "(null)", (int)xmlSecKeyGetSize(key));
}

static void context(void) {
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyInfoCtx copy;
    int ret;

    printf("context\n");
    printf("  defaults: mode=%d base64=%d retrieval=%d reference=%d enc=%d depth=%d usage=0x%08x\n", ctx->mode,
           ctx->base64LineSize, ctx->maxRetrievalMethodLevel, ctx->maxKeyInfoReferenceLevel, ctx->maxEncryptedKeyLevel,
           ctx->certsVerificationDepth, ctx->keyReq.keyUsage);
    ctx->flags = 3;
    ctx->flags2 = 4;
    ctx->base64LineSize = 33;
    ctx->maxRetrievalMethodLevel = 5;
    xmlSecPtrListAdd(&ctx->enabledKeyData, (xmlSecPtr)&secretKlass);
    xmlSecKeyInfoCtxDebugDump(ctx, stdout);
    xmlSecKeyInfoCtxInitialize(&copy, NULL);
    copy.mode = xmlSecKeyInfoModeWrite;
    /* C leaves the order of argument evaluation unspecified, so a call and
     * the fields it sets are never printed in one statement. */
    ret = xmlSecKeyInfoCtxCopyUserPref(&copy, ctx);
    printf("  copy: %d flags=%u base64=%d retrieval=%d enabled=%d\n", ret, copy.flags, copy.base64LineSize,
           copy.maxRetrievalMethodLevel, (int)xmlSecPtrListGetSize(&copy.enabledKeyData));
    xmlSecKeyInfoCtxDebugXmlDump(&copy, stdout);
    ctx->curRetrievalMethodLevel = 2;
    ctx->keyReq.keyType = 4;
    xmlSecKeyInfoCtxReset(ctx);
    printf("  reset: retrieval=%d type=%u flags=%u\n", ctx->curRetrievalMethodLevel, ctx->keyReq.keyType, ctx->flags);
    xmlSecKeyInfoCtxFinalize(&copy);
    xmlSecKeyInfoCtxDestroy(ctx);
    printf("  null: %d\n", xmlSecKeyInfoCtxInitialize(NULL, NULL));
}

static const char keyInfoText[] =
    "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#' xmlns:t='urn:test'>"
    "<KeyName> alpha </KeyName><Unknown/><KeyValue><t:TestSecret>s3cret</t:TestSecret></KeyValue>"
    "<KeyName>alpha</KeyName></KeyInfo>";

static const char conflictText[] =
    "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><KeyName>a</KeyName><KeyName>b</KeyName></KeyInfo>";

static const char valueText[] =
    "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#' xmlns:t='urn:test'>"
    "<KeyValue><t:TestSecret>one</t:TestSecret><t:TestSecret>two</t:TestSecret></KeyValue></KeyInfo>";

static xmlDocPtr parse(const char *text) {
    return xsReadMemory(text, (int)strlen(text), "k.xml", NULL, 0);
}

static void enable_values(xmlSecKeyInfoCtxPtr ctx) {
    xmlSecPtrListAdd(&ctx->enabledKeyData, (xmlSecPtr)xmlSecKeyDataNameId);
    xmlSecPtrListAdd(&ctx->enabledKeyData, (xmlSecPtr)xmlSecKeyDataValueId);
    xmlSecPtrListAdd(&ctx->enabledKeyData, (xmlSecPtr)&secretKlass);
}

static void reading(void) {
    xmlDocPtr doc = parse(keyInfoText);
    xmlDocPtr conflict = parse(conflictText);
    xmlDocPtr values = parse(valueText);
    xmlNodePtr keyInfo = xsDocGetRootElement(doc);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();

    printf("reading\n");
    printf("  wrong mode: %d\n", xmlSecKeyInfoNodeWrite(keyInfo, key, ctx));
    printf("  registry enabled: %d\n", xmlSecKeyInfoNodeRead(keyInfo, key, ctx));
    show_key("  key", key);
    xmlSecKeyEmpty(key);
    ctx->flags = XMLSEC_KEYINFO_FLAGS_STOP_ON_UNKNOWN_CHILD;
    printf("  stop on unknown: %d\n", xmlSecKeyInfoNodeRead(keyInfo, key, ctx));
    xmlSecKeyEmpty(key);
    ctx->flags = 0;
    printf("  names conflict: %d\n", xmlSecKeyInfoNodeRead(xsDocGetRootElement(conflict), key, ctx));
    xmlSecKeyEmpty(key);
    enable_values(ctx);
    printf("  values enabled: %d\n", xmlSecKeyInfoNodeRead(keyInfo, key, ctx));
    show_key("  key", key);
    xmlSecKeyEmpty(key);
    ctx->flags = XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND;
    printf("  read all: %d\n", xmlSecKeyInfoNodeRead(keyInfo, key, ctx));
    show_key("  key", key);
    xmlSecKeyEmpty(key);
    printf("  two values: %d\n", xmlSecKeyInfoNodeRead(xsDocGetRootElement(values), key, ctx));
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(values);
    xsFreeDoc(conflict);
    xsFreeDoc(doc);
}

static void writing(void) {
    xmlDocPtr doc = parse(keyInfoText);
    xmlNodePtr keyInfo = xsDocGetRootElement(doc);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = secret_key("written", "value");
    xmlChar *text = NULL;
    int size = 0;

    printf("writing\n");
    ctx->mode = xmlSecKeyInfoModeWrite;
    xsNodeSetContent(xsNodeGetChildren(keyInfo), NULL);
    printf("  registry enabled: %d\n", xmlSecKeyInfoNodeWrite(keyInfo, key, ctx));
    enable_values(ctx);
    ctx->keyReq.keyType = xmlSecKeyDataTypePublic;
    printf("  public only: %d\n", xmlSecKeyInfoNodeWrite(keyInfo, key, ctx));
    ctx->keyReq.keyType = xmlSecKeyDataTypeSymmetric;
    printf("  symmetric: %d\n", xmlSecKeyInfoNodeWrite(keyInfo, key, ctx));
    ctx->flags = XMLSEC_KEYINFO_FLAGS_STOP_ON_UNKNOWN_CHILD;
    printf("  stop on unknown: %d\n", xmlSecKeyInfoNodeWrite(keyInfo, key, ctx));
    xsDocDumpMemory(doc, &text, &size);
    printf("  tree: %.*s", size, (const char *)text);
    xsFree(text);
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

static const char referencesText[] =
    "<Root xmlns='http://www.w3.org/2000/09/xmldsig#' xmlns:t='urn:test'"
    " xmlns:dsig11='http://www.w3.org/2009/xmldsig11#'>"
    "<t:TestSecret xml:id='secret'>retrieved</t:TestSecret>"
    "<KeyInfo xml:id='shared'><KeyName>shared</KeyName></KeyInfo>"
    "<KeyInfo><RetrievalMethod URI='#secret' Type='urn:test:secret'/></KeyInfo>"
    "<KeyInfo><RetrievalMethod URI='#secret'/></KeyInfo>"
    "<KeyInfo><RetrievalMethod URI='#secret' Type='urn:test:unknown'/></KeyInfo>"
    "<KeyInfo><RetrievalMethod URI='#secret' Type='urn:test:secret'><Extra/></RetrievalMethod></KeyInfo>"
    "<KeyInfo><dsig11:KeyInfoReference URI='#shared'/></KeyInfo>"
    "<KeyInfo><dsig11:KeyInfoReference/></KeyInfo>"
    "<KeyInfo><dsig11:KeyInfoReference URI='#secret'/></KeyInfo>"
    "</Root>";

/* Reads the index-th KeyInfo child of the references document. */
static void read_reference(const char *label, xmlDocPtr doc, int index, xmlSecKeyInfoCtxPtr ctx) {
    xmlNodePtr cur = xmlSecGetNextElementNode(xsNodeGetChildren(xsDocGetRootElement(doc)));
    xmlSecKeyPtr key = xmlSecKeyCreate();
    int ii;
    for (ii = 0; ii < index; ++ii) {
        cur = xmlSecGetNextElementNode(xsNodeGetNext(cur));
    }
    printf("  %s: %d\n", label, xmlSecKeyInfoNodeRead(cur, key, ctx));
    show_key("    key", key);
    xmlSecKeyDestroy(key);
}

static void references(void) {
    xmlDocPtr doc = parse(referencesText);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);

    printf("references\n");
    read_reference("retrieval", doc, 2, ctx);
    read_reference("retrieval without type", doc, 3, ctx);
    read_reference("retrieval of unknown type", doc, 4, ctx);
    ctx->flags = XMLSEC_KEYINFO_FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF;
    read_reference("unknown type stops", doc, 4, ctx);
    ctx->flags = 0;
    read_reference("unexpected child", doc, 5, ctx);
    ctx->maxRetrievalMethodLevel = 0;
    read_reference("retrieval level", doc, 2, ctx);
    ctx->maxRetrievalMethodLevel = 1;
    read_reference("reference", doc, 6, ctx);
    read_reference("reference without uri", doc, 7, ctx);
    read_reference("reference to another element", doc, 8, ctx);
    ctx->maxKeyInfoReferenceLevel = 0;
    read_reference("reference level", doc, 6, ctx);
    printf("  levels after: %d %d\n", ctx->curRetrievalMethodLevel, ctx->curKeyInfoReferenceLevel);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

static void managers(void) {
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    xmlSecKeyStorePtr store = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    xmlSecKeyStorePtr fixed;
    xmlSecKeyDataStorePtr dataStore;
    xmlSecKeyInfoCtxPtr ctx;
    xmlSecKeyPtr key;
    xmlDocPtr doc;
    static char x509Value[64];
    int ret;

    printf("managers\n");
    ctx = xmlSecKeyInfoCtxCreate(mngr);
    printf("  no store: %p\n", (void *)xmlSecKeysMngrFindKey(mngr, BAD_CAST "a", ctx));
    xmlSecSimpleKeysStoreAdoptKey(store, secret_key("one", "1111"));
    xmlSecSimpleKeysStoreAdoptKey(store, secret_key("two", "22222222"));
    ret = xmlSecKeysMngrAdoptKeysStore(mngr, store);
    printf("  adopt store: %d same=%d\n", ret, xmlSecKeysMngrGetKeysStore(mngr) == store);
    printf("  keys: %d\n", (int)xmlSecPtrListGetSize(xmlSecSimpleKeysStoreGetKeys(store)));
    key = xmlSecKeysMngrFindKey(mngr, BAD_CAST "two", ctx);
    show_key("  find two", key);
    xmlSecKeyDestroy(key);
    ctx->keyReq.keyBitsSize = 48;
    key = xmlSecKeysMngrFindKey(mngr, NULL, ctx);
    show_key("  find large", key);
    xmlSecKeyDestroy(key);
    ctx->keyReq.keyBitsSize = 0;
    show_key("  find missing", xmlSecKeyStoreFindKey(store, BAD_CAST "three", ctx));

    doc = parse(keyInfoText);
    ctx->flags = 0;
    key = xmlSecKeysMngrGetKey(xsDocGetRootElement(doc), ctx);
    show_key("  get from node", key);
    enable_values(ctx);
    key = xmlSecKeysMngrGetKey(xsDocGetRootElement(doc), ctx);
    show_key("  get from node with values", key);
    if (key != NULL) {
        xmlSecKeyDestroy(key);
    }
    xsFreeDoc(doc);
    doc = parse("<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><KeyName>one</KeyName></KeyInfo>");
    key = xmlSecKeysMngrGetKey(xsDocGetRootElement(doc), ctx);
    show_key("  get by name", key);
    if (key != NULL) {
        xmlSecKeyDestroy(key);
    }
    xsFreeDoc(doc);
    key = xmlSecKeysMngrGetKey(NULL, ctx);
    show_key("  get without node", key);
    ctx->flags = XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
    key = xmlSecKeysMngrGetKey(NULL, ctx);
    show_key("  get lax", key);
    if (key != NULL) {
        xmlSecKeyDestroy(key);
    }

    fixed = xmlSecKeyStoreCreate(&fixedKlass);
    ((FixedStore *)fixed)->key = secret_key("fixed", "ffff");
    printf("  replace store: %d\n", xmlSecKeysMngrAdoptKeysStore(mngr, fixed));
    key = xmlSecKeysMngrFindKey(mngr, BAD_CAST "fixed", ctx);
    show_key("  find fixed", key);
    xmlSecKeyDestroy(key);
    /* the fixed store has no X.509 lookup, which never reads the value */
    printf("  x509 lookup: %p\n", (void *)xmlSecKeysMngrFindKeyFromX509Data(mngr, (xmlSecKeyX509DataValuePtr)x509Value, ctx));

    dataStore = xmlSecKeyDataStoreCreate(&dataStoreKlass);
    ret = xmlSecKeysMngrAdoptDataStore(mngr, dataStore);
    printf("  data store: %d get=%d\n", ret, xmlSecKeysMngrGetDataStore(mngr, &dataStoreKlass) == dataStore);
    ret = xmlSecKeysMngrAdoptDataStore(mngr, xmlSecKeyDataStoreCreate(&dataStoreKlass));
    printf("  data store again: %d size=%d\n", ret, (int)xmlSecPtrListGetSize(&mngr->storesList));
    printf("  no data store: %p\n", (void *)xmlSecKeysMngrGetDataStore(mngr, (xmlSecKeyDataStoreId)&fixedKlass));
    printf("  invalid store: %d\n", xmlSecKeysMngrAdoptKeysStore(mngr, NULL));
    xmlSecKeyInfoCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
}

/* The caller reads and writes keys files; the store adopts keys. */
static void stores(void) {
    printf("stores\n");
    printf("  wrong store: %d\n", xmlSecSimpleKeysStoreAdoptKey(NULL, NULL));
}

int main(void) {
    xmlSecErrorsSetCallback(record);
    xmlSecKeyDataIdsInit();
    xmlSecKeyDataIdsRegister(&secretKlass);
    context();
    reading();
    writing();
    references();
    managers();
    stores();
    xmlSecKeyDataIdsShutdown();
    printf("done\n");
    return 0;
}
