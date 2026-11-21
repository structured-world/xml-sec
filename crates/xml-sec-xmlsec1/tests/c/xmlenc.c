/* The encryption context as a libxmlsec1 caller uses it to decrypt: an
 * Element EncryptedData replaced by its plaintext, the replaced node
 * returned on request, a Content one, one without a Type decrypted to a
 * buffer and left in place, a missing key, a wrong key, and a node that is
 * no EncryptedData, and keys derived by PBKDF2, HKDF and ConcatKDF from a
 * named master key. The cipher values are made with the AES-CBC transform
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
#include <xmlsec/io.h>
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

static const char resource[] = "resource bytes read through the caller's callbacks";
static size_t resource_position;
/* When set, the resource the callbacks read instead. */
static xmlChar *referenced_value;

static int match_resource(const char *uri) {
    return strncmp(uri, "example:", 8) == 0;
}

static void *open_resource(const char *uri) {
    (void)uri;
    resource_position = 0;
    return &resource_position;
}

static int read_resource(void *context, char *buffer, int len) {
    const char *source = referenced_value != NULL ? (const char *)referenced_value : resource;
    size_t left = strlen(source) - resource_position;
    size_t count = left < (size_t)len ? left : (size_t)len;
    (void)context;
    memcpy(buffer, source + resource_position, count);
    resource_position += count;
    return (int)count;
}

static int close_resource(void *context) {
    (void)context;
    return 0;
}

/* Encrypts the resource a URI names, read through the caller's callbacks,
 * and decrypts it to a buffer again. */
static void uri_round_trip(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, NULL, NULL, NULL);
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    xmlSecBufferPtr result;
    xsDocSetRootElement(doc, tmpl);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    printf("uri\n");
    printf("  register: %d\n", xmlSecIORegisterCallbacks(match_resource, open_resource,
                                                         read_resource, close_resource));
    ctx->encKey = aes_key(0x66);
    printf("  encrypt: %d\n", xmlSecEncCtxUriEncrypt(ctx, tmpl, BAD_CAST "example:resource"));
    xmlSecEncCtxDestroy(ctx);
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x66);
    result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
    printf("  decrypted: %.*s\n", result != NULL ? (int)xmlSecBufferGetSize(result) : 0,
           result != NULL ? (const char *)xmlSecBufferGetData(result) : "");
    xmlSecEncCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* An EncryptedData without EncryptionMethod, decrypted with the context's
 * default method, as its recipient knows it (XML Encryption 1.1 section
 * 3.1). */
static void default_method(void) {
    static const char bytes[] = "default method bytes";
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, NULL, NULL, NULL);
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    xmlSecBufferPtr result;
    xmlNodePtr method;
    xsDocSetRootElement(doc, tmpl);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    printf("default method\n");
    ctx->encKey = aes_key(0x88);
    printf("  encrypt: %d\n",
           xmlSecEncCtxBinaryEncrypt(ctx, tmpl, (const xmlSecByte *)bytes, sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    method = xmlSecFindNode(tmpl, xmlSecNodeEncryptionMethod, xmlSecEncNs);
    xsUnlinkNode(method);
    xsFreeNode(method);
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x88);
    ctx->defEncMethodId = xmlSecTransformAes128CbcId;
    result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
    printf("  decrypted: %.*s\n", result != NULL ? (int)xmlSecBufferGetSize(result) : 0,
           result != NULL ? (const char *)xmlSecBufferGetData(result) : "");
    xmlSecEncCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* An EncryptedData whose CipherReference names a resource the caller's
 * input callbacks read: its cipher value moved out of the document. */
static void cipher_reference(void) {
    static const char bytes[] = "referenced cipher bytes";
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, NULL, NULL, NULL);
    xmlNodePtr cipher;
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(NULL);
    xmlSecBufferPtr result;
    xsDocSetRootElement(doc, tmpl);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    printf("cipher reference\n");
    ctx->encKey = aes_key(0x99);
    printf("  encrypt: %d\n",
           xmlSecEncCtxBinaryEncrypt(ctx, tmpl, (const xmlSecByte *)bytes, sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    /* The Base64 cipher value becomes the external resource. */
    cipher = xmlSecFindNode(tmpl, xmlSecNodeCipherValue, xmlSecEncNs);
    referenced_value = xmlSecGetNodeContentAndTrim(cipher);
    xsUnlinkNode(cipher);
    xsFreeNode(cipher);
    cipher = xmlSecTmplEncDataEnsureCipherReference(tmpl, BAD_CAST "example:cipher");
    xmlSecTmplCipherReferenceAddTransform(cipher, xmlSecTransformBase64Id);
    ctx = xmlSecEncCtxCreate(NULL);
    ctx->encKey = aes_key(0x99);
    ctx->transformCtx.enabledUris = xmlSecTransformUriTypeAny;
    result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
    printf("  decrypted: %.*s\n", result != NULL ? (int)xmlSecBufferGetSize(result) : 0,
           result != NULL ? (const char *)xmlSecBufferGetData(result) : "");
    xmlSecEncCtxDestroy(ctx);
    xsFree(referenced_value);
    referenced_value = NULL;
    xsFreeDoc(doc);
}

#define RSA_KEY "tests/fixtures/keys/rsa/rsa-2048-key.pem"

/* A keys manager holding the RSA key "recipient" and the AES key "kek". */
static xmlSecKeysMngrPtr recipients(void) {
    static xmlSecByte bytes[8192];
    size_t size;
    xmlSecKeyPtr key;
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    FILE *file = fopen(RSA_KEY, "rb");
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    if (file == NULL) {
        return mngr;
    }
    size = fread(bytes, 1, sizeof(bytes), file);
    fclose(file);
    key = xmlSecCryptoAppKeyLoadMemory(bytes, (xmlSecSize)size, xmlSecKeyDataFormatPem, NULL, NULL,
                                       NULL);
    xmlSecKeySetName(key, BAD_CAST "recipient");
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    key = aes_key(0x77);
    xmlSecKeySetName(key, BAD_CAST "kek");
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    return mngr;
}

/* Changes the first character of the EncryptedKey's cipher value. */
static void tamper(xmlNodePtr enc_key) {
    xmlNodePtr value = xmlSecFindNode(enc_key, xmlSecNodeCipherValue, xmlSecEncNs);
    xmlChar *text = xmlSecGetNodeContentAndTrim(value);
    text[0] = text[0] == 'A' ? 'B' : 'A';
    xsNodeSetContent(value, text);
    xsFree(text);
}

/* A generated AES session key carried to the recipient `name` in an
 * EncryptedKey of `transport`: the data encrypted, then decrypted with the
 * key the keys manager resolves; with `tampered` set, the EncryptedKey's
 * cipher value is changed first. Every cipher value is random, so only
 * the outcome is printed. */
static void session_key(const char *label, xmlSecTransformId transport, const char *name,
                        int tampered) {
    static const char bytes[] = "session key payload";
    xmlSecKeysMngrPtr mngr = recipients();
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr tmpl = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId, NULL, NULL, NULL, NULL);
    xmlNodePtr enc_key;
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(mngr);
    xmlSecBufferPtr result;
    xsDocSetRootElement(doc, tmpl);
    xmlSecTmplEncDataEnsureCipherValue(tmpl);
    enc_key = xmlSecTmplKeyInfoAddEncryptedKey(xmlSecTmplEncDataEnsureKeyInfo(tmpl, NULL), transport,
                                               NULL, NULL, NULL);
    xmlSecTmplEncDataEnsureCipherValue(enc_key);
    xmlSecTmplKeyInfoAddKeyName(xmlSecTmplEncDataEnsureKeyInfo(enc_key, NULL), BAD_CAST name);
    printf("%s\n", label);
    ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 128, xmlSecKeyDataTypeSession);
    printf("  encrypt: %d\n",
           xmlSecEncCtxBinaryEncrypt(ctx, tmpl, (const xmlSecByte *)bytes, sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    if (tampered) {
        tamper(enc_key);
        quiet = 1;
    }
    ctx = xmlSecEncCtxCreate(mngr);
    result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
    quiet = 0;
    printf("  decrypted: %d same=%d failure=%s\n",
           result != NULL ? (int)xmlSecBufferGetSize(result) : -1,
           result != NULL && xmlSecBufferGetSize(result) == sizeof(bytes) - 1 &&
               memcmp(xmlSecBufferGetData(result), bytes, sizeof(bytes) - 1) == 0,
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    xmlSecEncCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

#define DERIVED_HEAD                                                                      \
    "<xenc:EncryptedData xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "                 \
    "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" "                                    \
    "xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\">"
#define DERIVED_TAIL                                                                      \
    "<xenc11:DerivedKeyName>session</xenc11:DerivedKeyName>"                               \
    "<xenc11:MasterKeyName>master</xenc11:MasterKeyName></xenc11:DerivedKey></ds:KeyInfo>" \
    "<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>"

static const char pbkdf2_template[] =
    DERIVED_HEAD
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>"
    "<ds:KeyInfo><xenc11:DerivedKey>"
    "<xenc11:KeyDerivationMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\">"
    "<xenc11:PBKDF2-params><xenc11:Salt><xenc11:Specified>Df3dRAhjGh8=</xenc11:Specified>"
    "</xenc11:Salt><xenc11:IterationCount>1000</xenc11:IterationCount>"
    "<xenc11:KeyLength>32</xenc11:KeyLength>"
    "<xenc11:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>"
    "</xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>" DERIVED_TAIL;

static const char hkdf_template[] =
    DERIVED_HEAD
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>"
    "<ds:KeyInfo><xenc11:DerivedKey>"
    "<xenc11:KeyDerivationMethod Algorithm=\"http://www.w3.org/2021/04/xmldsig-more#hkdf\">"
    "<m:HKDFParams xmlns:m=\"http://www.w3.org/2021/04/xmldsig-more#\">"
    "<m:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>"
    "<m:Salt>AAECAwQFBgcICQoL</m:Salt><m:Info>aW5mbw==</m:Info>"
    "<m:KeyLength>32</m:KeyLength></m:HKDFParams></xenc11:KeyDerivationMethod>" DERIVED_TAIL;

static const char concat_kdf_template[] =
    DERIVED_HEAD
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>"
    "<ds:KeyInfo><xenc11:DerivedKey>"
    "<xenc11:KeyDerivationMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">"
    "<xenc11:ConcatKDFParams AlgorithmID=\"00123456789ABCDEF0\" PartyUInfo=\"00414C494345313233\" "
    "PartyVInfo=\"00424F424259343536\">"
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
    "</xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>" DERIVED_TAIL;

/* Data encrypted under the key the template's DerivedKey derives from the
 * master key "master" of `klass`, found through the keys manager, then
 * decrypted by a fresh context deriving the key again: the derived key is
 * deterministic, so its bytes and name are printed. With `master_name`
 * other than "master" the recipient finds no master key. */
static void derived_key(const char *label, const char *template, xmlSecKeyDataId klass,
                        const char *master_name) {
    static const char bytes[] = "derived key payload";
    xmlSecByte secret[24];
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    xmlSecKeysMngrPtr recipient = xmlSecKeysMngrCreate();
    xmlDocPtr doc = xsReadMemory(template, (int)strlen(template), "derived.xml", NULL, 0);
    xmlSecEncCtxPtr ctx;
    xmlSecBufferPtr result;
    xmlSecKeyPtr key;
    memset(secret, 0x5c, sizeof(secret));
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    key = xmlSecKeyReadMemory(klass, secret, sizeof(secret));
    xmlSecKeySetName(key, BAD_CAST "master");
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    xmlSecCryptoAppDefaultKeysMngrInit(recipient);
    key = xmlSecKeyReadMemory(klass, secret, sizeof(secret));
    xmlSecKeySetName(key, BAD_CAST master_name);
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(recipient, key);
    printf("%s\n", label);
    ctx = xmlSecEncCtxCreate(mngr);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    ctx = xmlSecEncCtxCreate(recipient);
    result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc));
    printf("  decrypted: %.*s failure=%s\n", result != NULL ? (int)xmlSecBufferGetSize(result) : 0,
           result != NULL ? (const char *)xmlSecBufferGetData(result) : "",
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    if (ctx->encKey != NULL) {
        xmlSecBufferPtr value = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(ctx->encKey));
        xmlSecSize index;
        printf("  key %s:", (const char *)xmlSecKeyGetName(ctx->encKey));
        for (index = 0; index < xmlSecBufferGetSize(value); index++) {
            printf("%02x", xmlSecBufferGetData(value)[index]);
        }
        printf("\n");
    }
    xmlSecEncCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(recipient);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

#define VECTORS "tests/fixtures/xmlenc/aleksey-xmlenc-01/"
#define EC_KEYS "tests/fixtures/xmlenc/keys/ec/"

/* The bytes of the file at `path`, NUL-terminated; NULL when unreadable. */
static xmlSecByte *file_bytes(const char *path, size_t *size) {
    static xmlSecByte bytes[1 << 16];
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    *size = fread(bytes, 1, sizeof(bytes) - 1, file);
    fclose(file);
    bytes[*size] = 0;
    return bytes;
}

/* Adds the PEM key at `path` to `mngr` under `name`. */
static void adopt_pem(xmlSecKeysMngrPtr mngr, const char *path, const char *name) {
    size_t size = 0;
    xmlSecByte *bytes = file_bytes(path, &size);
    xmlSecKeyPtr key;
    if (bytes == NULL) {
        printf("  missing key file %s\n", path);
        return;
    }
    key = xmlSecCryptoAppKeyLoadMemory(bytes, (xmlSecSize)size, xmlSecKeyDataFormatPem, NULL, NULL,
                                       NULL);
    if (key == NULL) {
        printf("  key %s not loaded\n", name);
        return;
    }
    xmlSecKeySetName(key, BAD_CAST name);
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
}

/* A keys manager holding the private key `private_path` under
 * `private_name` and the public key `public_path` under `public_name`, the
 * two parties of an agreement as one side holds them. */
static xmlSecKeysMngrPtr parties(const char *private_path, const char *private_name,
                                 const char *public_path, const char *public_name) {
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    adopt_pem(mngr, private_path, private_name);
    adopt_pem(mngr, public_path, public_name);
    return mngr;
}

/* Decrypts `doc` with `mngr`, its key under an EncryptedKey whose KEK an
 * AgreementMethod agrees on (three EncryptedKey levels), and compares the
 * result with `expected`. */
static void decrypt_agreed(xmlDocPtr doc, xmlSecKeysMngrPtr mngr, const xmlSecByte *expected,
                           size_t expected_size) {
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(mngr);
    xmlSecBufferPtr result;
    ctx->keyInfoReadCtx.maxEncryptedKeyLevel = 3;
    result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc));
    printf("  decrypted: %d same=%d failure=%s\n",
           result != NULL ? (int)xmlSecBufferGetSize(result) : -1,
           result != NULL && expected != NULL && xmlSecBufferGetSize(result) == expected_size &&
               memcmp(xmlSecBufferGetData(result), expected, expected_size) == 0,
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    xmlSecEncCtxDestroy(ctx);
}

/* The donor vector `name`, encrypted to the recipient's key under an
 * agreement with the originator's: decrypted by the recipient holding its
 * private key `private_path` and the originator's public key
 * `public_path`. */
static void agreement_vector_with(const char *label, const char *name, const char *private_path,
                                  const char *public_path) {
    char path[512];
    static xmlSecByte expected[1 << 16];
    size_t expected_size = 0;
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecKeysMngrPtr mngr;
    printf("%s\n", label);
    snprintf(path, sizeof(path), VECTORS "%s.data", name);
    data = file_bytes(path, &expected_size);
    if (data != NULL) {
        memcpy(expected, data, expected_size);
    }
    snprintf(path, sizeof(path), VECTORS "%s.xml", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing vector %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "vector.xml", NULL, 0);
    mngr = parties(private_path, "recipient-key-name", public_path, "originator-key-name");
    decrypt_agreed(doc, mngr, expected, expected_size);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

/* An ECDH-ES donor vector over the P-`curve` keys. */
static void agreement_vector(const char *label, const char *name, const char *curve) {
    char private_path[256];
    char public_path[256];
    snprintf(private_path, sizeof(private_path), EC_KEYS "ec-prime%sv1-second-key.pem", curve);
    snprintf(public_path, sizeof(public_path), EC_KEYS "ec-prime%sv1-pubkey.pem", curve);
    agreement_vector_with(label, name, private_path, public_path);
}

#define XDH_KEYS "tests/fixtures/xmlenc/keys/xdh/"

/* The donor template `name` encrypted by the originator holding its
 * private P-256 key and the recipient's public key, then decrypted by the
 * recipient: the agreement runs on both sides. The ephemeral session key
 * makes the cipher values random, so only the outcome is printed. With
 * `wrong` set, the recipient holds a different originator key. */
static void agreement_round_trip(const char *label, const char *name, int wrong) {
    static const char bytes[] = "agreed key payload";
    char path[512];
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr originator =
        parties(EC_KEYS "ec-prime256v1-key.pem", "originator-key-name",
                EC_KEYS "ec-prime256v1-second-pubkey.pem", "recipient-key-name");
    xmlSecKeysMngrPtr recipient =
        parties(EC_KEYS "ec-prime256v1-second-key.pem", "recipient-key-name",
                wrong ? EC_KEYS "ec-prime256v1-second-pubkey.pem" : EC_KEYS "ec-prime256v1-pubkey.pem",
                "originator-key-name");
    printf("%s\n", label);
    snprintf(path, sizeof(path), VECTORS "%s.tmpl", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing template %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "template.xml", NULL, 0);
    ctx = xmlSecEncCtxCreate(originator);
    ctx->keyInfoReadCtx.maxEncryptedKeyLevel = 3;
    ctx->keyInfoWriteCtx.maxEncryptedKeyLevel = 3;
    ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 128, xmlSecKeyDataTypeSession);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    if (wrong) {
        quiet = 1;
    }
    decrypt_agreed(doc, recipient, (const xmlSecByte *)bytes, sizeof(bytes) - 1);
    quiet = 0;
    xmlSecKeysMngrDestroy(recipient);
    xmlSecKeysMngrDestroy(originator);
    xsFreeDoc(doc);
}

#define DHX_KEYS "tests/fixtures/xmlenc/keys/dhx/"

/* Enables in `list` the klasses the donor's DH-ES recipe names
 * (agreement-method,enc-key,key-value,key-name,dh): KeyValue is registered
 * disabled. */
static void enable_dh_recipe(xmlSecPtrListPtr list) {
    xmlSecPtrListAdd(list, (void *)xmlSecKeyDataAgreementMethodId);
    xmlSecPtrListAdd(list, (void *)xmlSecKeyDataEncryptedKeyId);
    xmlSecPtrListAdd(list, (void *)xmlSecKeyDataValueId);
    xmlSecPtrListAdd(list, (void *)xmlSecKeyDataNameId);
    xmlSecPtrListAdd(list, (void *)xmlSecKeyDataDhId);
}

/* Decrypts the DH-ES `doc` with the recipient's manager `mngr` under the
 * donor's recipe and compares the result with `expected`. */
static void decrypt_dh(xmlDocPtr doc, xmlSecKeysMngrPtr mngr, const xmlSecByte *expected,
                       size_t expected_size) {
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(mngr);
    xmlSecBufferPtr result;
    ctx->keyInfoReadCtx.maxEncryptedKeyLevel = 3;
    enable_dh_recipe(&(ctx->keyInfoReadCtx.enabledKeyData));
    result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc));
    printf("  decrypted: %d same=%d failure=%s\n",
           result != NULL ? (int)xmlSecBufferGetSize(result) : -1,
           result != NULL && expected != NULL && xmlSecBufferGetSize(result) == expected_size &&
               memcmp(xmlSecBufferGetData(result), expected, expected_size) == 0,
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    xmlSecEncCtxDestroy(ctx);
}

/* The donor's DH-ES vector: the recipient holds only its private key and
 * reads the originator's public key from the DHKeyValue of its role. */
static void dh_agreement_vector(void) {
    static const char name[] = "enc_dh_concatkdf_sha256_kw_aes128_aes128gcm";
    char path[512];
    static xmlSecByte expected[1 << 16];
    size_t expected_size = 0;
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecKeysMngrPtr mngr;
    printf("agreement dh-es concatkdf sha256\n");
    snprintf(path, sizeof(path), VECTORS "%s.data", name);
    data = file_bytes(path, &expected_size);
    if (data != NULL) {
        memcpy(expected, data, expected_size);
    }
    snprintf(path, sizeof(path), VECTORS "%s.xml", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing vector %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "vector.xml", NULL, 0);
    mngr = xmlSecKeysMngrCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    adopt_pem(mngr, DHX_KEYS "dhx-rfc5114-3-second-key.pem", "dhx-rfc5114-3-second");
    decrypt_dh(doc, mngr, expected, expected_size);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

/* The donor's DH-ES template encrypted by the originator holding its
 * private key and the recipient's public key, under the donor's recipe,
 * then decrypted by the recipient holding only its private key. */
static void dh_agreement_round_trip(void) {
    static const char bytes[] = "agreed key payload";
    char path[512];
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr originator =
        parties(DHX_KEYS "dhx-rfc5114-3-first-key.pem", "dhx-rfc5114-3-first",
                DHX_KEYS "dhx-rfc5114-3-second-pubkey.pem", "dhx-rfc5114-3-second");
    xmlSecKeysMngrPtr recipient = xmlSecKeysMngrCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(recipient);
    adopt_pem(recipient, DHX_KEYS "dhx-rfc5114-3-second-key.pem", "dhx-rfc5114-3-second");
    printf("agreement dh-es round trip\n");
    snprintf(path, sizeof(path), VECTORS "enc_dh_concatkdf_sha256_kw_aes128_aes128gcm.tmpl");
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing template\n");
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "template.xml", NULL, 0);
    ctx = xmlSecEncCtxCreate(originator);
    ctx->keyInfoReadCtx.maxEncryptedKeyLevel = 3;
    ctx->keyInfoWriteCtx.maxEncryptedKeyLevel = 3;
    enable_dh_recipe(&(ctx->keyInfoReadCtx.enabledKeyData));
    enable_dh_recipe(&(ctx->keyInfoWriteCtx.enabledKeyData));
    ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 128, xmlSecKeyDataTypeSession);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    decrypt_dh(doc, recipient, (const xmlSecByte *)bytes, sizeof(bytes) - 1);
    xmlSecKeysMngrDestroy(recipient);
    xmlSecKeysMngrDestroy(originator);
    xsFreeDoc(doc);
}

/* An AES-128-GCM EncryptedData whose content key the AgreementMethod of
 * its own KeyInfo agrees on, no EncryptedKey between them. */
static const char direct_agreement_template[] =
    "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
    " Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/>"
    "<dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\">"
    "<xenc:AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\">"
    "<xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\""
    " Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">"
    "<xenc11:ConcatKDFParams AlgorithmID=\"00123456\" PartyUInfo=\"00123456\" PartyVInfo=\"00123456\">"
    "<dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
    "</xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>"
    "<xenc:OriginatorKeyInfo><dsig:KeyName>originator-key-name</dsig:KeyName></xenc:OriginatorKeyInfo>"
    "<xenc:RecipientKeyInfo><dsig:KeyName>recipient-key-name</dsig:KeyName></xenc:RecipientKeyInfo>"
    "</xenc:AgreementMethod></dsig:KeyInfo>"
    "<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>";

/* The direct agreement template encrypted by the originator, its content
 * key found by its KeyInfo read, then decrypted by the recipient: with
 * `wrong` set, the recipient holds a different originator key. */
static void direct_agreement_round_trip(const char *label, int wrong) {
    static const char bytes[] = "agreed content payload";
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr originator =
        parties(EC_KEYS "ec-prime256v1-key.pem", "originator-key-name",
                EC_KEYS "ec-prime256v1-second-pubkey.pem", "recipient-key-name");
    xmlSecKeysMngrPtr recipient =
        parties(EC_KEYS "ec-prime256v1-second-key.pem", "recipient-key-name",
                wrong ? EC_KEYS "ec-prime256v1-second-pubkey.pem" : EC_KEYS "ec-prime256v1-pubkey.pem",
                "originator-key-name");
    printf("%s\n", label);
    doc = xsReadMemory(direct_agreement_template, (int)strlen(direct_agreement_template),
                       "template.xml", NULL, 0);
    ctx = xmlSecEncCtxCreate(originator);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    if (wrong) {
        quiet = 1;
    }
    decrypt_agreed(doc, recipient, (const xmlSecByte *)bytes, sizeof(bytes) - 1);
    quiet = 0;
    xmlSecKeysMngrDestroy(recipient);
    xmlSecKeysMngrDestroy(originator);
    xsFreeDoc(doc);
}

#define MLKEM_KEYS "tests/fixtures/xmldsig/keys/ml-kem/"

/* A keys manager holding the ML-KEM key file `path` under `name`, with the
 * key data's klass name and size printed, and its type for a private key
 * file: libxmlsec1 reports every OpenSSL 3 key as private, which this
 * library does only for a key that holds its private part. */
static xmlSecKeysMngrPtr mlkem_manager(const char *path, const char *name) {
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    size_t size = 0;
    xmlSecByte *bytes = file_bytes(path, &size);
    xmlSecKeyPtr key;
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    if (bytes == NULL) {
        printf("  missing key file %s\n", path);
        return mngr;
    }
    key = xmlSecCryptoAppKeyLoadMemory(bytes, (xmlSecSize)size, xmlSecKeyDataFormatPem, NULL, NULL,
                                       NULL);
    if (key == NULL) {
        printf("  key %s not loaded\n", name);
        return mngr;
    }
    printf("  key: %s size=%d", xmlSecKeyDataGetName(xmlSecKeyGetValue(key)),
           (int)xmlSecKeyDataGetSize(xmlSecKeyGetValue(key)));
    if (strstr(path, "pubkey") == NULL) {
        printf(" type=%u", xmlSecKeyDataGetType(xmlSecKeyGetValue(key)));
    }
    printf("\n");
    xmlSecKeySetName(key, BAD_CAST name);
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    return mngr;
}

/* Decrypts the EncryptedData of `doc` with `mngr` and prints the size of the
 * content and whether `expected` holds it. */
static void decrypt_kem(xmlDocPtr doc, xmlSecKeysMngrPtr mngr, const xmlSecByte *expected,
                        size_t expected_size) {
    xmlSecEncCtxPtr ctx = xmlSecEncCtxCreate(mngr);
    xmlNodePtr node = xmlSecFindNode(xsDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    xmlSecBufferPtr result = xmlSecEncCtxDecryptToBuffer(ctx, node);
    int found = 0;
    if (result != NULL && expected != NULL) {
        size_t size = xmlSecBufferGetSize(result);
        for (size_t at = 0; size > 0 && at + size <= expected_size; at++) {
            if (memcmp(expected + at, xmlSecBufferGetData(result), size) == 0) {
                found = 1;
                break;
            }
        }
    }
    printf("  decrypted: %d found=%d failure=%s\n",
           result != NULL ? (int)xmlSecBufferGetSize(result) : -1, found,
           xmlSecEncCtxGetFailureReasonString(ctx->failureReason));
    xmlSecEncCtxDestroy(ctx);
}

/* The donor's ML-KEM vector `name`, decrypted with the private key file
 * `key` of the recipient named `key_name`. */
static void mlkem_vector(const char *name, const char *key, const char *key_name) {
    char path[512];
    static xmlSecByte expected[1 << 16];
    size_t expected_size = 0;
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecKeysMngrPtr mngr;
    printf("ml-kem vector %s\n", name);
    snprintf(path, sizeof(path), VECTORS "%s.data", name);
    data = file_bytes(path, &expected_size);
    if (data != NULL) {
        memcpy(expected, data, expected_size);
    }
    snprintf(path, sizeof(path), VECTORS "%s.xml", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing vector %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "vector.xml", NULL, 0);
    snprintf(path, sizeof(path), MLKEM_KEYS "%s", key);
    mngr = mlkem_manager(path, key_name);
    decrypt_kem(doc, mngr, expected, expected_size);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

/* The donor's ML-KEM template `name` encrypted for the public key file
 * `public` of the recipient named `key_name`, the content key the secret its
 * EncryptedKey encapsulates, then decrypted with the private key file
 * `private`. The ciphertext is fresh each time, so only outcomes print. */
static void mlkem_round_trip(const char *name, const char *public, const char *private,
                             const char *key_name) {
    static const char bytes[] = "encapsulated content";
    char path[512];
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr sender;
    xmlSecKeysMngrPtr recipient;
    printf("ml-kem round trip %s\n", name);
    snprintf(path, sizeof(path), VECTORS "%s.tmpl", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing template %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "template.xml", NULL, 0);
    snprintf(path, sizeof(path), MLKEM_KEYS "%s", public);
    sender = mlkem_manager(path, key_name);
    ctx = xmlSecEncCtxCreate(sender);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    snprintf(path, sizeof(path), MLKEM_KEYS "%s", private);
    recipient = mlkem_manager(path, key_name);
    decrypt_kem(doc, recipient, (const xmlSecByte *)bytes, sizeof(bytes) - 1);
    xmlSecKeysMngrDestroy(recipient);
    xmlSecKeysMngrDestroy(sender);
    xsFreeDoc(doc);
}

/* The donor's keys.xml ChaCha20 keys, by name. */
#define CHACHA20_KEY "zAKV37t4gV9srAUvRFjxERSJ13wGpDwoIMkcJxlD0MU="
#define CHACHA20_POLY1305_KEY "rSyWevC59TMmFuoDBdEC4VvlwiJOqalHn3GffX4CcPA="

/* A keys manager holding the ChaCha20 key whose Base64 value is `value`
 * under `name`. */
static xmlSecKeysMngrPtr chacha_manager(const char *value, const char *name) {
    xmlSecByte bytes[32];
    xmlSecSize written = 0;
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    xmlSecKeyInfoCtxPtr info = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    if (xmlSecBase64Decode_ex(BAD_CAST value, bytes, sizeof(bytes), &written) < 0 ||
        xmlSecKeyDataBinRead(xmlSecKeyDataChaCha20Id, key, bytes, written, info) < 0) {
        printf("  key %s not read\n", name);
        xmlSecKeyDestroy(key);
    } else {
        xmlSecKeySetName(key, BAD_CAST name);
        xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    }
    xmlSecKeyInfoCtxDestroy(info);
    return mngr;
}

/* The donor's ChaCha vector `name`, decrypted with the key `value` under
 * `key_name`. */
static void chacha_vector(const char *name, const char *value, const char *key_name) {
    char path[512];
    static xmlSecByte expected[1 << 16];
    size_t expected_size = 0;
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecKeysMngrPtr mngr;
    printf("chacha vector %s\n", name);
    snprintf(path, sizeof(path), VECTORS "%s.data", name);
    data = file_bytes(path, &expected_size);
    if (data != NULL) {
        memcpy(expected, data, expected_size);
    }
    snprintf(path, sizeof(path), VECTORS "%s.xml", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing vector %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "vector.xml", NULL, 0);
    mngr = chacha_manager(value, key_name);
    decrypt_kem(doc, mngr, expected, expected_size);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);
}

/* The donor's ChaCha template `name` encrypted with the key `value` under
 * `key_name` and decrypted again; whether the method then names a nonce, as
 * the encryption writes the one it drew when the template has none. The
 * nonce is fresh when drawn, so only outcomes print. */
static void chacha_round_trip(const char *name, const char *value, const char *key_name) {
    static const char bytes[] = "stream cipher content";
    char path[512];
    xmlSecByte *data;
    xmlDocPtr doc;
    xmlSecEncCtxPtr ctx;
    xmlSecKeysMngrPtr mngr;
    xmlNodePtr method;
    printf("chacha round trip %s\n", name);
    snprintf(path, sizeof(path), VECTORS "%s.tmpl", name);
    data = file_bytes(path, &(size_t){0});
    if (data == NULL) {
        printf("  missing template %s\n", name);
        return;
    }
    doc = xsReadMemory((const char *)data, (int)strlen((const char *)data), "template.xml", NULL, 0);
    mngr = chacha_manager(value, key_name);
    ctx = xmlSecEncCtxCreate(mngr);
    printf("  encrypt: %d\n", xmlSecEncCtxBinaryEncrypt(ctx, xsDocGetRootElement(doc),
                                                        (const xmlSecByte *)bytes,
                                                        sizeof(bytes) - 1));
    xmlSecEncCtxDestroy(ctx);
    method = xmlSecFindChild(xsDocGetRootElement(doc), xmlSecNodeEncryptionMethod, xmlSecEncNs);
    printf("  nonce written: %d\n",
           method != NULL && xmlSecFindChild(method, BAD_CAST "Nonce",
                                             BAD_CAST "http://www.w3.org/2021/04/xmldsig-more#") != NULL);
    decrypt_kem(doc, mngr, (const xmlSecByte *)bytes, sizeof(bytes) - 1);
    xmlSecKeysMngrDestroy(mngr);
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
    uri_round_trip();
    default_method();
    cipher_reference();
    session_key("session key rsa-oaep", xmlSecTransformRsaOaepId, "recipient", 0);
    session_key("session key rsa-oaep tampered", xmlSecTransformRsaOaepId, "recipient", 1);
    session_key("session key rsa-1_5", xmlSecTransformRsaPkcs1Id, "recipient", 0);
    session_key("session key kw-aes128", xmlSecTransformKWAes128Id, "kek", 0);
    session_key("session key kw-aes128 tampered", xmlSecTransformKWAes128Id, "kek", 1);
    derived_key("derived key pbkdf2", pbkdf2_template, xmlSecKeyDataPbkdf2Id, "master");
    derived_key("derived key hkdf", hkdf_template, xmlSecKeyDataHkdfId, "master");
    derived_key("derived key concatkdf", concat_kdf_template, xmlSecKeyDataConcatKdfId, "master");
    derived_key("derived key without its master", pbkdf2_template, xmlSecKeyDataPbkdf2Id,
                "another");
    agreement_vector("agreement ecdh-es p256 concatkdf sha256",
                     "enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm", "256");
    agreement_vector("agreement ecdh-es p256 concatkdf sha512 ka-nonce",
                     "enc_ecdh_p256_concatkdf_sha512_kw_aes256_aes128gcm_kanonce", "256");
    agreement_vector("agreement ecdh-es p256 hkdf sha384",
                     "enc_ecdh_p256_hkdf_sha384_kw_aes256_aes128gcm", "256");
    agreement_vector("agreement ecdh-es p256 pbkdf2 sha256",
                     "enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm", "256");
    agreement_vector("agreement ecdh-es p384 concatkdf sha384",
                     "enc_ecdh_p384_concatkdf_sha384_kw_aes192_aes192gcm", "384");
    agreement_vector("agreement ecdh-es p521 concatkdf sha512",
                     "enc_ecdh_p521_concatkdf_sha512_kw_aes256_aes256gcm", "521");
    agreement_vector_with("agreement x25519 concatkdf sha256",
                          "enc_xdh_x25519_concatkdf_sha256_kw_aes256_aes128gcm",
                          XDH_KEYS "xdh-x25519-second-key.pem", XDH_KEYS "xdh-x25519-first-pubkey.pem");
    agreement_vector_with("agreement x25519 hkdf sha512",
                          "enc_xdh_x25519_hkdf_sha512_kw_aes256_aes128gcm",
                          XDH_KEYS "xdh-x25519-second-key.pem", XDH_KEYS "xdh-x25519-first-pubkey.pem");
    agreement_vector_with("agreement x448 concatkdf sha384",
                          "enc_xdh_x448_concatkdf_sha384_kw_aes256_aes128gcm",
                          XDH_KEYS "xdh-x448-second-key.pem", XDH_KEYS "xdh-x448-first-pubkey.pem");
    agreement_vector("agreement ecdh-es p256 concatkdf sha1",
                     "enc_ecdh_p256_concatkdf_sha1_kw_aes256_aes128gcm", "256");
    agreement_vector("agreement ecdh-es p256 concatkdf sha3-256",
                     "enc_ecdh_p256_concatkdf_sha3_256_kw_aes256_aes128gcm", "256");
    agreement_vector("agreement ecdh-es p256 pbkdf2 sha1",
                     "enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm", "256");
    agreement_round_trip("agreement ecdh-es round trip",
                         "enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm", 0);
    agreement_round_trip("agreement ecdh-es with another originator key",
                         "enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm", 1);
    dh_agreement_vector();
    dh_agreement_round_trip();
    direct_agreement_round_trip("agreement in the data KeyInfo", 0);
    direct_agreement_round_trip("agreement in the data KeyInfo with another originator key", 1);
    mlkem_vector("enc-aes128gcm-kt-ml-kem-512", "ml-kem-512-key.pem", "TestKeyName-ml-kem-512");
    mlkem_vector("enc-aes256gcm-kt-ml-kem-1024", "ml-kem-1024-key.pem", "TestKeyName-ml-kem-1024");
    mlkem_vector("enc-aes256-kt-ml-kem-512", "ml-kem-512-key.pem", "TestKeyName-ml-kem-512");
    mlkem_vector("enc-aes256-kt-ml-kem-768", "ml-kem-768-key.pem", "TestKeyName-ml-kem-768");
    mlkem_vector("enc-aes256-kt-ml-kem-1024", "ml-kem-1024-key.pem", "TestKeyName-ml-kem-1024");
    quiet = 1;
    mlkem_vector("enc-aes128gcm-kt-ml-kem-512", "ml-kem-768-key.pem", "TestKeyName-ml-kem-512");
    quiet = 0;
    mlkem_round_trip("enc-aes128gcm-kt-ml-kem-512", "ml-kem-512-pubkey.pem", "ml-kem-512-key.pem",
                     "TestKeyName-ml-kem-512");
    mlkem_round_trip("enc-aes256-kt-ml-kem-768", "ml-kem-768-pubkey.pem", "ml-kem-768-key.pem",
                     "TestKeyName-ml-kem-768");
    mlkem_round_trip("enc-aes256gcm-kt-ml-kem-1024", "ml-kem-1024-pubkey.pem",
                     "ml-kem-1024-key.pem", "TestKeyName-ml-kem-1024");
    chacha_vector("enc-chacha20-keyname", CHACHA20_KEY, "test-chacha20");
    chacha_vector("enc-chacha20poly1305-keyname", CHACHA20_POLY1305_KEY, "test-chacha20poly1305");
    chacha_vector("enc-chacha20poly1305-aad-keyname", CHACHA20_POLY1305_KEY,
                  "test-chacha20poly1305");
    chacha_round_trip("enc-chacha20-keyname", CHACHA20_KEY, "test-chacha20");
    chacha_round_trip("enc-chacha20-keyname-missing-nonce", CHACHA20_KEY, "test-chacha20");
    chacha_round_trip("enc-chacha20poly1305-keyname", CHACHA20_POLY1305_KEY,
                      "test-chacha20poly1305");
    chacha_round_trip("enc-chacha20poly1305-keyname-missing-nonce", CHACHA20_POLY1305_KEY,
                      "test-chacha20poly1305");
    chacha_round_trip("enc-chacha20poly1305-aad-keyname", CHACHA20_POLY1305_KEY,
                      "test-chacha20poly1305");

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
