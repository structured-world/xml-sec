/* Keys, key requirements and use-with records as a libxmlsec1 caller uses
 * them: ownership of the value, name and data list, copies, swaps,
 * matching against requirements, generation through a klass and the debug
 * dumps. The key data is a binary klass of the program's own. Built against
 * the pinned libxmlsec1 and against this crate, both must print the same
 * results, dumps and reports. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/list.h>
#include <xmlsec/buffer.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

typedef struct { xmlSecKeyData base; xmlSecBuffer value; } BinaryData;

static int binary_initialize(xmlSecKeyDataPtr data) {
    return xmlSecBufferInitialize(xmlSecKeyDataBinaryValueGetBuffer(data), 0);
}

static int binary_duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecBufferPtr from = xmlSecKeyDataBinaryValueGetBuffer(src);
    return xmlSecKeyDataBinaryValueSetBuffer(dst, xmlSecBufferGetData(from), xmlSecBufferGetSize(from));
}

static void binary_finalize(xmlSecKeyDataPtr data) {
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

static xmlSecKeyDataType symmetric(xmlSecKeyDataPtr data) {
    (void)data;
    return xmlSecKeyDataTypeSymmetric;
}

static xmlSecKeyDataType public_type(xmlSecKeyDataPtr data) {
    (void)data;
    return xmlSecKeyDataTypePublic;
}

static void binary_dump(xmlSecKeyDataPtr data, FILE *output) {
    fprintf(output, "binary dump: %s %d bits\n", data->id->name, (int)xmlSecKeyDataGetSize(data));
}

static void binary_xml_dump(xmlSecKeyDataPtr data, FILE *output) {
    fprintf(output, "<Binary name=\"%s\" bits=\"%d\"/>\n", data->id->name, (int)xmlSecKeyDataGetSize(data));
}

static xmlSecKeyDataKlass secretKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-secret", xmlSecKeyDataUsageKeyValueNode,
    BAD_CAST "urn:test:secret", BAD_CAST "TestSecret", BAD_CAST "urn:test",
    binary_initialize, binary_duplicate, binary_finalize, binary_generate,
    symmetric, xmlSecKeyDataBinaryValueGetSize, NULL,
    NULL, NULL, NULL, NULL,
    binary_dump, binary_xml_dump, NULL, NULL,
};

static xmlSecKeyDataKlass publicKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-public", xmlSecKeyDataUsageKeyValueNode,
    BAD_CAST "urn:test:public", BAD_CAST "TestPublic", BAD_CAST "urn:test",
    binary_initialize, binary_duplicate, binary_finalize, binary_generate,
    public_type, xmlSecKeyDataBinaryValueGetSize, NULL,
    NULL, NULL, NULL, NULL,
    binary_dump, binary_xml_dump, NULL, NULL,
};

static int public_bin_read(xmlSecKeyDataId id, xmlSecKeyPtr key, const xmlSecByte *buf, xmlSecSize size,
                           xmlSecKeyInfoCtxPtr ctx) {
    xmlSecKeyDataPtr data = xmlSecKeyDataCreate(id);
    printf("  bin read: %d bytes type=0x%04x mode=%d\n", (int)size, ctx->keyReq.keyType, ctx->mode);
    xmlSecKeyDataBinaryValueSetBuffer(data, buf, size);
    return xmlSecKeySetValue(key, data);
}

static xmlSecKeyDataKlass readableKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-readable", xmlSecKeyDataUsageKeyValueNode,
    BAD_CAST "urn:test:readable", BAD_CAST "TestReadable", BAD_CAST "urn:test",
    binary_initialize, binary_duplicate, binary_finalize, binary_generate,
    public_type, xmlSecKeyDataBinaryValueGetSize, NULL,
    NULL, NULL, public_bin_read, NULL,
    binary_dump, binary_xml_dump, NULL, NULL,
};

/* The caller reads key files; the library reads keys from memory. */
static void reading(void) {
    xmlSecKeyPtr key;

    printf("reading\n");
    key = xmlSecKeyReadMemory(&readableKlass, BAD_CAST "abcdef", 6);
    printf("  memory: %d\n", key != NULL ? (int)xmlSecKeyGetSize(key) : -1);
    xmlSecKeyDestroy(key);
    printf("  no bin read: %p\n", (void *)xmlSecKeyReadMemory(&secretKlass, BAD_CAST "abc", 3));
    printf("  empty: %p\n", (void *)xmlSecKeyReadMemory(&readableKlass, BAD_CAST "abc", 0));
}

static xmlSecKeyDataKlass extraKlass = {
    sizeof(xmlSecKeyDataKlass), sizeof(BinaryData),
    BAD_CAST "test-extra", xmlSecKeyDataUsageKeyValueNode,
    BAD_CAST "urn:test:extra", BAD_CAST "TestExtra", BAD_CAST "urn:test",
    binary_initialize, binary_duplicate, binary_finalize, binary_generate,
    public_type, xmlSecKeyDataBinaryValueGetSize, NULL,
    NULL, NULL, NULL, NULL,
    binary_dump, binary_xml_dump, NULL, NULL,
};

static void use_with(void) {
    xmlSecKeyUseWithPtr a = xmlSecKeyUseWithCreate(BAD_CAST "app", BAD_CAST "id<1>");
    xmlSecKeyUseWithPtr b;
    xmlSecKeyUseWith c;
    xmlSecPtrList list;
    int ret;

    /* C leaves the order of argument evaluation unspecified, so a call and
     * the fields it sets are never printed in one statement. */
    printf("use with\n");
    xmlSecKeyUseWithDebugDump(a, stdout);
    xmlSecKeyUseWithDebugXmlDump(a, stdout);
    b = xmlSecKeyUseWithDuplicate(a);
    printf("  duplicate: %s %s\n", (const char *)b->application, (const char *)b->identifier);
    printf("  set: %d\n", xmlSecKeyUseWithSet(b, NULL, BAD_CAST "only"));
    xmlSecKeyUseWithDebugDump(b, stdout);
    xmlSecKeyUseWithInitialize(&c);
    ret = xmlSecKeyUseWithCopy(&c, a);
    printf("  copy: %d %s\n", ret, (const char *)c.application);
    xmlSecKeyUseWithReset(&c);
    printf("  reset: %p %p\n", (void *)c.application, (void *)c.identifier);
    xmlSecKeyUseWithFinalize(&c);
    xmlSecPtrListInitialize(&list, xmlSecKeyUseWithPtrListId);
    xmlSecPtrListAdd(&list, a);
    xmlSecPtrListAdd(&list, b);
    xmlSecPtrListDebugDump(&list, stdout);
    xmlSecPtrListDebugXmlDump(&list, stdout);
    printf("  list name: %s\n", (const char *)xmlSecPtrListGetName(&list));
    xmlSecPtrListFinalize(&list);
    printf("  null: %d\n", xmlSecKeyUseWithSet(NULL, NULL, NULL));
}

static void requirements(void) {
    xmlSecKeyReq req;
    xmlSecKeyReq copy;
    xmlSecKeyPtr key = xmlSecKeyGenerate(&secretKlass, 128, xmlSecKeyDataTypeSession);
    int ret;

    printf("requirements\n");
    /* the order C evaluates arguments in is unspecified: initialize first */
    ret = xmlSecKeyReqInitialize(&req);
    printf("  init: %d usage=0x%08x type=%u\n", ret, req.keyUsage, req.keyType);
    printf("  any: %d\n", xmlSecKeyReqMatchKey(&req, key));
    req.keyId = &publicKlass;
    printf("  other klass: %d\n", xmlSecKeyReqMatchKey(&req, key));
    req.keyId = &secretKlass;
    req.keyType = xmlSecKeyDataTypePublic;
    printf("  other type: %d\n", xmlSecKeyReqMatchKey(&req, key));
    req.keyType = xmlSecKeyDataTypeSymmetric;
    req.keyBitsSize = 256;
    printf("  too small: %d\n", xmlSecKeyReqMatchKey(&req, key));
    req.keyBitsSize = 128;
    key->usage = xmlSecKeyUsageVerify;
    req.keyUsage = xmlSecKeyUsageSign;
    printf("  other usage: %d\n", xmlSecKeyReqMatchKey(&req, key));
    req.keyUsage = xmlSecKeyUsageVerify;
    printf("  match: %d\n", xmlSecKeyReqMatchKey(&req, key));
    printf("  value: %d\n", xmlSecKeyReqMatchKeyValue(&req, key->value));
    xmlSecPtrListAdd(&req.keyUseWithList, xmlSecKeyUseWithCreate(BAD_CAST "a", BAD_CAST "b"));
    xmlSecKeyReqInitialize(&copy);
    ret = xmlSecKeyReqCopy(&copy, &req);
    printf("  copy: %d uses=%d\n", ret, (int)xmlSecPtrListGetSize(&copy.keyUseWithList));
    xmlSecKeyReqDebugDump(&copy, stdout);
    xmlSecKeyReqDebugXmlDump(&copy, stdout);
    xmlSecKeyReqReset(&copy);
    xmlSecKeyReqDebugDump(&copy, stdout);
    printf("  invalid key: %d\n", xmlSecKeyReqMatchKey(&req, NULL));
    xmlSecKeyReqFinalize(&copy);
    xmlSecKeyReqFinalize(&req);
    xmlSecKeyDestroy(key);
}

static void keys(void) {
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecKeyPtr other;
    xmlSecKeyPtr copy;
    xmlSecKeyDataPtr data;
    xmlSecKeyDataPtr name;
    xmlSecKeyReq req;
    xmlSecPtrList list;
    int ret;

    printf("keys\n");
    printf("  created: usage=0x%08x type=%u size=%d value=%p\n", key->usage, xmlSecKeyGetType(key),
           (int)xmlSecKeyGetSize(key), (void *)xmlSecKeyGetValue(key));
    ret = xmlSecKeySetName(key, BAD_CAST "first");
    printf("  set name: %d %s\n", ret, (const char *)xmlSecKeyGetName(key));
    ret = xmlSecKeySetNameEx(key, BAD_CAST "second-and-more", 6);
    printf("  set name ex: %d %s\n", ret, (const char *)xmlSecKeyGetName(key));
    ret = xmlSecKeySetNameEx(key, BAD_CAST "x", 0);
    printf("  set name ex empty: %d %p\n", ret, (void *)xmlSecKeyGetName(key));
    xmlSecKeySetName(key, BAD_CAST "named");
    data = xmlSecKeyDataCreate(&secretKlass);
    xmlSecKeyDataGenerate(data, 192, xmlSecKeyDataTypeSession);
    ret = xmlSecKeySetValue(key, data);
    printf("  set value: %d type=%u size=%d\n", ret, xmlSecKeyGetType(key), (int)xmlSecKeyGetSize(key));
    printf("  value data: %d\n", xmlSecKeyGetData(key, xmlSecKeyDataValueId) == data);
    printf("  no data: %p\n", (void *)xmlSecKeyGetData(key, xmlSecKeyDataNameId));
    name = xmlSecKeyEnsureData(key, &extraKlass);
    printf("  ensured: %d again=%d\n", name != NULL, xmlSecKeyEnsureData(key, &extraKlass) == name);
    other = xmlSecKeyGenerate(&publicKlass, 64, xmlSecKeyDataTypePermanent);
    data = xmlSecKeyDataCreate(&extraKlass);
    xmlSecKeyDataGenerate(data, 32, xmlSecKeyDataTypeSession);
    ret = xmlSecKeyAdoptData(key, data);
    printf("  adopt replaces: %d size=%d\n", ret, (int)xmlSecPtrListGetSize(key->dataList));
    ret = xmlSecKeyAdoptData(key, xmlSecKeyDataDuplicate(other->value));
    printf("  adopt other klass: %d size=%d\n", ret, (int)xmlSecPtrListGetSize(key->dataList));
    printf("  ensure without methods: %d\n", xmlSecKeyEnsureData(other, xmlSecKeyDataNameId) != NULL);
    printf("  duplicate without methods: %p\n", (void *)xmlSecKeyDuplicate(other));
    xmlSecPtrListEmpty(other->dataList);
    key->notValidBefore = 1000;
    key->notValidAfter = 2000;
    key->usage = xmlSecKeyUsageSign | xmlSecKeyUsageVerify;
    xmlSecKeyDebugDump(key, stdout);
    xmlSecKeyDebugXmlDump(key, stdout);

    copy = xmlSecKeyDuplicate(key);
    printf("  duplicate: %s usage=%u valid=%ld..%ld data=%d value=%d\n", (const char *)copy->name, copy->usage,
           (long)copy->notValidBefore, (long)copy->notValidAfter, (int)xmlSecPtrListGetSize(copy->dataList),
           copy->value != key->value && xmlSecKeyGetSize(copy) == 192);
    ret = xmlSecKeySwap(copy, other);
    printf("  swap: %d %s/%s\n", ret, (const char *)xmlSecKeyGetName(copy), (const char *)xmlSecKeyGetName(other));
    xmlSecKeyReqInitialize(&req);
    printf("  match name: %d other name: %d any: %d\n", xmlSecKeyMatch(key, BAD_CAST "named", &req),
           xmlSecKeyMatch(key, BAD_CAST "nope", &req), xmlSecKeyMatch(key, NULL, &req));
    ret = xmlSecKeyCopy(copy, key);
    printf("  copy into: %d %s\n", ret, (const char *)copy->name);
    xmlSecKeyEmpty(copy);
    printf("  emptied: usage=%u name=%p value=%p list=%p\n", copy->usage, (void *)copy->name, (void *)copy->value,
           (void *)copy->dataList);
    printf("  match empty: %d\n", xmlSecKeyMatch(copy, NULL, &req));

    xmlSecPtrListInitialize(&list, xmlSecKeyPtrListId);
    xmlSecPtrListAdd(&list, xmlSecKeyDuplicate(key));
    printf("  list: %s %d\n", (const char *)xmlSecPtrListGetName(&list), (int)xmlSecPtrListGetSize(&list));
    xmlSecPtrListDebugDump(&list, stdout);
    xmlSecPtrListFinalize(&list);

    printf("  generate fails: %p\n", (void *)xmlSecKeyGenerate(&secretKlass, 0, xmlSecKeyDataTypeSession));
    printf("  generate by unknown name: %p\n", (void *)xmlSecKeyGenerateByName(BAD_CAST "nope", 128, 0));
    xmlSecKeyDataIdsRegister(&secretKlass);
    printf("  invalid dump:\n");
    xmlSecKeyDebugDump(copy, stdout);
    xmlSecKeyDestroy(copy);
    copy = xmlSecKeyGenerateByName(BAD_CAST "test-secret", 64, xmlSecKeyDataTypeSession);
    printf("  generate by name: %d\n", copy != NULL ? (int)xmlSecKeyGetSize(copy) : -1);
    xmlSecKeyDestroy(copy);
    printf("  null adopt: %d\n", xmlSecKeyAdoptData(key, NULL));
    xmlSecKeyReqFinalize(&req);
    xmlSecKeyDestroy(other);
    xmlSecKeyDestroy(key);
}

int main(void) {
    xmlSecErrorsSetCallback(record);
    xmlSecKeyDataIdsInit();
    use_with();
    requirements();
    keys();
    reading();
    xmlSecKeyDataIdsShutdown();
    printf("done\n");
    return 0;
}
