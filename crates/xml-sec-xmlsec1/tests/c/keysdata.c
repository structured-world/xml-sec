/* Key-data klasses as a libxmlsec1 caller uses them: the registry and its
 * enabled subset, lookups, a custom binary key-data klass driven through
 * every dispatcher, key-data lists, a custom store klass, the binary value
 * helpers, a transform context's extra key data, and Base64 node content.
 * Built unmodified against the pinned libxmlsec1 and against
 * this crate, both must print the same. */

#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/list.h>
#include <xmlsec/buffer.h>

/* ---- a binary key-data klass: the base object followed by its value ---- */
typedef struct { xmlSecKeyData base; xmlSecBuffer value; } BinaryData;

static int calls_initialize = 0;
static int calls_finalize = 0;

static int binary_initialize(xmlSecKeyDataPtr data) {
    ++calls_initialize;
    return xmlSecBufferInitialize(xmlSecKeyDataBinaryValueGetBuffer(data), 0);
}

static int binary_duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecBufferPtr from = xmlSecKeyDataBinaryValueGetBuffer(src);
    return xmlSecKeyDataBinaryValueSetBuffer(dst, xmlSecBufferGetData(from), xmlSecBufferGetSize(from));
}

static void binary_finalize(xmlSecKeyDataPtr data) {
    ++calls_finalize;
    xmlSecBufferFinalize(xmlSecKeyDataBinaryValueGetBuffer(data));
}

static int binary_generate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type) {
    xmlSecByte bytes[64];
    (void)type;
    if (sizeBits == 0 || sizeBits / 8 > sizeof(bytes)) {
        return -1;
    }
    memset(bytes, 0x5a, sizeBits / 8);
    return xmlSecKeyDataBinaryValueSetBuffer(data, bytes, sizeBits / 8);
}

static xmlSecKeyDataType binary_type(xmlSecKeyDataPtr data) {
    (void)data;
    return xmlSecKeyDataTypeSymmetric;
}

static void binary_dump(xmlSecKeyDataPtr data, FILE *output) {
    fprintf(output, "binary dump: %d bits\n", (int)xmlSecKeyDataGetSize(data));
}

static void binary_xml_dump(xmlSecKeyDataPtr data, FILE *output) {
    fprintf(output, "<Binary bits=\"%d\"/>\n", (int)xmlSecKeyDataGetSize(data));
}

static int binary_xml_read(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr ctx) {
    printf("xml read: %s key=%d node=%d ctx=%d\n", id->name, key != NULL, node != NULL, ctx != NULL);
    return 7;
}

static int binary_bin_write(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlSecByte **buf, xmlSecSize *size,
                            xmlSecKeyInfoCtxPtr ctx) {
    (void)key;
    (void)ctx;
    printf("bin write: %s\n", id->name);
    *buf = NULL;
    *size = 0;
    return 0;
}

static xmlSecKeyDataKlass binaryKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-binary", xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    BAD_CAST "urn:test:binary", BAD_CAST "TestBinary", BAD_CAST "urn:test",
    binary_initialize, binary_duplicate, binary_finalize, binary_generate,
    binary_type, xmlSecKeyDataBinaryValueGetSize, NULL,
    binary_xml_read, NULL, NULL, binary_bin_write,
    binary_dump, binary_xml_dump, NULL, NULL,
};

/* ---- a klass without methods, and a too-small one ---- */
static xmlSecKeyDataKlass plainKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(xmlSecKeyData),
    BAD_CAST "test-plain", xmlSecKeyDataUsageKeyInfoNodeRead, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

/* ---- a store klass counting its lifecycle ---- */
typedef struct { xmlSecKeyDataStore base; int value; } CountingStore;

static int store_initialize(xmlSecKeyDataStorePtr store) {
    ((CountingStore *)store)->value = 41;
    printf("store initialize: %s\n", store->id->name);
    return 0;
}

static void store_finalize(xmlSecKeyDataStorePtr store) {
    printf("store finalize: value=%d\n", ((CountingStore *)store)->value);
}

static xmlSecKeyDataStoreKlass storeKlass = {
    sizeof(xmlSecKeyDataStoreKlass), sizeof(CountingStore),
    BAD_CAST "test-store", store_initialize, store_finalize, NULL, NULL,
};

static int failing_initialize(xmlSecKeyDataStorePtr store) {
    (void)store;
    return -1;
}

static xmlSecKeyDataStoreKlass failingStoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass), sizeof(xmlSecKeyDataStore),
    BAD_CAST "failing-store", failing_initialize, store_finalize, NULL, NULL,
};

/* ---- a transform klass that only verifies ---- */
static int checker_verify(xmlSecTransformPtr transform, const xmlSecByte *data, xmlSecSize size,
                          xmlSecTransformCtxPtr ctx) {
    (void)ctx;
    printf("verify: %s [%.*s]\n", transform->id->name, (int)size, (const char *)data);
    transform->status = xmlSecTransformStatusOk;
    return 0;
}

static xmlSecTransformKlass checkerKlass = {
    sizeof(xmlSecTransformKlass), sizeof(xmlSecTransform),
    BAD_CAST "checker", NULL, xmlSecTransformUsageSignatureMethod,
    NULL, NULL, NULL, NULL, NULL, NULL, checker_verify,
    xmlSecTransformDefaultGetDataType, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

static const char *name_of(xmlSecKeyDataId id) {
    return id != NULL ? (const char *)id->name : "none";
}

int main(void) {
    xmlSecKeyDataPtr data;
    xmlSecKeyDataPtr copy;
    xmlSecKeyDataStorePtr store;
    xmlSecPtrListPtr list;
    xmlSecPtrListPtr listCopy;
    xmlSecByte *written = (xmlSecByte *)"x";
    xmlSecSize writtenSize = 1;
    int dummy = 0;

    printf("ids init: %d\n", xmlSecKeyDataIdsInit());
    xmlSecKeyDataIdListDebugDump(xmlSecKeyDataIdsGet(), stdout);
    xmlSecKeyDataIdListDebugDump(xmlSecKeyDataIdsGetEnabled(), stdout);
    xmlSecKeyDataIdListDebugXmlDump(xmlSecKeyDataIdsGetEnabled(), stdout);

    printf("register: %d disabled: %d\n", xmlSecKeyDataIdsRegister(&binaryKlass),
           xmlSecKeyDataIdsRegisterDisabled(&plainKlass));
    printf("find: %d %d %d %d\n",
           xmlSecKeyDataIdListFind(xmlSecKeyDataIdsGet(), &binaryKlass),
           xmlSecKeyDataIdListFind(xmlSecKeyDataIdsGetEnabled(), &plainKlass),
           xmlSecKeyDataIdListFind(xmlSecKeyDataIdsGet(), &plainKlass),
           xmlSecKeyDataIdListFind(xmlSecKeyDataIdsGet(), xmlSecKeyDataNameId));
    printf("by node: %s %s %s\n",
           name_of(xmlSecKeyDataIdListFindByNode(xmlSecKeyDataIdsGet(), BAD_CAST "KeyName",
                                                 BAD_CAST "http://www.w3.org/2000/09/xmldsig#",
                                                 xmlSecKeyDataUsageKeyInfoNodeRead)),
           name_of(xmlSecKeyDataIdListFindByNode(xmlSecKeyDataIdsGet(), BAD_CAST "TestBinary",
                                                 BAD_CAST "urn:test", xmlSecKeyDataUsageKeyInfoNodeRead)),
           name_of(xmlSecKeyDataIdListFindByNode(xmlSecKeyDataIdsGet(), BAD_CAST "TestBinary",
                                                 BAD_CAST "urn:test", xmlSecKeyDataUsageKeyValueNodeRead)));
    printf("by href: %s %s\n",
           name_of(xmlSecKeyDataIdListFindByHref(xmlSecKeyDataIdsGet(),
                                                 BAD_CAST "http://www.w3.org/2001/04/xmlenc#EncryptedKey",
                                                 xmlSecKeyDataUsageAny)),
           name_of(xmlSecKeyDataIdListFindByHref(xmlSecKeyDataIdsGet(), BAD_CAST "urn:none",
                                                 xmlSecKeyDataUsageAny)));
    printf("by name: %s %s\n",
           name_of(xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGetEnabled(), BAD_CAST "test-binary",
                                                 xmlSecKeyDataUsageAny)),
           name_of(xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGetEnabled(), BAD_CAST "key-value",
                                                 xmlSecKeyDataUsageAny)));

    /* objects of the binary klass through every dispatcher */
    data = xmlSecKeyDataCreate(&binaryKlass);
    printf("create: %d initialize=%d valid=%d id=%d\n", data != NULL, calls_initialize,
           xmlSecKeyDataIsValid(data), xmlSecKeyDataCheckId(data, &binaryKlass));
    printf("generate: %d size=%d type=%u\n", xmlSecKeyDataGenerate(data, 128, xmlSecKeyDataTypeSession),
           (int)xmlSecKeyDataGetSize(data), xmlSecKeyDataGetType(data));
    printf("generate too big: %d\n", xmlSecKeyDataGenerate(data, 4096, xmlSecKeyDataTypeSession));
    xmlSecKeyDataDebugDump(data, stdout);
    xmlSecKeyDataDebugXmlDump(data, stdout);
    copy = xmlSecKeyDataDuplicate(data);
    printf("duplicate: %d size=%d initialize=%d\n", copy != NULL, (int)xmlSecKeyDataBinaryValueGetSize(copy),
           calls_initialize);
    printf("set buffer: %d %d size=%d\n", xmlSecKeyDataBinaryValueSetBuffer(copy, BAD_CAST "abc", 3),
           xmlSecKeyDataBinaryValueSetBuffer(copy, BAD_CAST "abc", 0), (int)xmlSecKeyDataGetSize(copy));
    printf("xml read: %d\n", xmlSecKeyDataXmlRead(&binaryKlass, (xmlSecKeyPtr)&dummy, (xmlNodePtr)&dummy, NULL));
    printf("xml read without key: %d\n", xmlSecKeyDataXmlRead(&binaryKlass, NULL, (xmlNodePtr)&dummy, NULL));
    printf("xml write missing: %d\n", xmlSecKeyDataXmlWrite(&binaryKlass, (xmlSecKeyPtr)&dummy, (xmlNodePtr)&dummy, NULL));
    printf("bin read missing: %d\n", xmlSecKeyDataBinRead(&binaryKlass, (xmlSecKeyPtr)&dummy, BAD_CAST "x", 1, NULL));
    printf("bin write: %d size=%d\n", xmlSecKeyDataBinWrite(&binaryKlass, (xmlSecKeyPtr)&dummy, &written, &writtenSize, NULL),
           (int)writtenSize);

    /* a list owning key data: duplicates through the klass, dumps, frees */
    list = xmlSecPtrListCreate(xmlSecKeyDataListId);
    xmlSecPtrListAdd(list, data);
    xmlSecPtrListAdd(list, copy);
    listCopy = xmlSecPtrListDuplicate(list);
    printf("list: %d copy: %d initialize=%d\n", (int)xmlSecPtrListGetSize(list),
           (int)xmlSecPtrListGetSize(listCopy), calls_initialize);
    xmlSecPtrListDebugDump(listCopy, stdout);
    xmlSecPtrListDestroy(list);
    xmlSecPtrListDestroy(listCopy);
    printf("finalize: %d\n", calls_finalize);

    /* a klass without methods */
    data = xmlSecKeyDataCreate(&plainKlass);
    printf("plain: size=%d type=%u generate=%d duplicate=%d binary=%d\n", (int)xmlSecKeyDataGetSize(data),
           xmlSecKeyDataGetType(data), xmlSecKeyDataGenerate(data, 8, 0), xmlSecKeyDataDuplicate(data) != NULL,
           xmlSecKeyDataBinaryValueGetBuffer(data) != NULL);
    xmlSecKeyDataDestroy(data);

    /* the built-in KeyInfo child klasses */
    printf("builtin: %s %s %s %s\n", name_of(xmlSecKeyDataNameId), name_of(xmlSecKeyDataValueId),
           name_of(xmlSecKeyDataEncryptedKeyId), name_of(xmlSecKeyDataKeyInfoReferenceId));
    printf("builtin usage: %u objSize=%d\n", xmlSecKeyDataNameId->usage,
           xmlSecKeyDataNameId->objSize == sizeof(xmlSecKeyData));

    /* stores */
    store = xmlSecKeyDataStoreCreate(&storeKlass);
    printf("store: %d valid=%d id=%d value=%d\n", store != NULL, xmlSecKeyDataStoreIsValid(store),
           xmlSecKeyDataStoreCheckId(store, &storeKlass), ((CountingStore *)store)->value);
    list = xmlSecPtrListCreate(xmlSecKeyDataStorePtrListId);
    xmlSecPtrListAdd(list, store);
    xmlSecPtrListDestroy(list);
    printf("failing store: %s\n", xmlSecKeyDataStoreCreate(&failingStoreKlass) == NULL ? "refused" : "created");

    /* a transform context's extra key data */
    {
        xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
        xmlSecKeyDataPtr ensured;
        xmlSecKeyDataPtr own = xmlSecKeyDataCreate(&plainKlass);
        printf("extra get: %s\n", xmlSecTransformCtxExtraKeyDataGet(ctx, &binaryKlass) == NULL ? "none" : "some");
        ensured = xmlSecTransformCtxExtraKeyDataEnsure(ctx, &binaryKlass);
        printf("extra ensure: %d again same: %d get same: %d\n", ensured != NULL,
               xmlSecTransformCtxExtraKeyDataEnsure(ctx, &binaryKlass) == ensured,
               xmlSecTransformCtxExtraKeyDataGet(ctx, &binaryKlass) == ensured);
        printf("extra adopt: %d", xmlSecTransformCtxExtraKeyDataAdopt(ctx, own));
        printf(" duplicate klass: %d\n", xmlSecTransformCtxExtraKeyDataAdopt(ctx, xmlSecKeyDataCreate(&binaryKlass)));
        printf("extra list: %d\n", (int)xmlSecPtrListGetSize(ctx->extraKeyData));
        xmlSecTransformCtxDestroy(ctx);
        printf("extra finalize: %d\n", calls_finalize);
    }

    /* Base64 node content and hex dumps */
    {
        static const char xml[] = "<a>\n  Zm9v\n  YmFy  \n</a>";
        xmlDocPtr doc = xmlReadMemory(xml, (int)strlen(xml), "b.xml", NULL, 0);
        xmlNodePtr root = xmlDocGetRootElement(doc);
        xmlNodePtr out = xmlNewDocNode(doc, NULL, BAD_CAST "out", NULL);
        xmlSecBufferPtr buf = xmlSecBufferCreate(0);
        xmlChar *trimmed = xmlSecGetNodeContentAndTrim(root);
        printf("trimmed: [%s]\n", (const char *)trimmed);
        xmlFree(trimmed);
        printf("node read: %d [%.*s]\n", xmlSecBufferBase64NodeContentRead(buf, root),
               (int)xmlSecBufferGetSize(buf), (const char *)xmlSecBufferGetData(buf));
        printf("node write: %d", xmlSecBufferBase64NodeContentWrite(buf, out, 4));
        trimmed = xmlNodeGetContent(out);
        printf(" [%s]\n", (const char *)trimmed);
        xmlFree(trimmed);
        xmlSecBufferSetData(buf, BAD_CAST "0123456789abcdef0123456789abcdefXY", 34);
        xmlSecBufferDebugHexDump(buf, stdout);
        printf("\n");
        {
            xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
            xmlSecTransformPtr checker = xmlSecTransformCreate(&checkerKlass);
            printf("verify node: %d status=%d\n", xmlSecTransformVerifyNodeContent(checker, root, ctx),
                   checker->status);
            printf("verify without node: %d\n", xmlSecTransformVerifyNodeContent(checker, NULL, ctx));
            xmlSecTransformDestroy(checker);
            xmlSecTransformCtxDestroy(ctx);
        }
        xmlSecBufferDestroy(buf);
        xmlFreeNode(out);
        xmlFreeDoc(doc);
    }

    printf("persist: %d", xmlSecImportGetPersistKey());
    xmlSecImportSetPersistKey();
    printf(" %d\n", xmlSecImportGetPersistKey());

    xmlSecKeyDataIdsShutdown();
    printf("after shutdown: %d\n", (int)xmlSecPtrListGetSize(xmlSecKeyDataIdsGet()));
    printf("done\n");
    return 0;
}
