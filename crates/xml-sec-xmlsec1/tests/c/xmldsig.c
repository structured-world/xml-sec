/* The signature context as a libxmlsec1 caller uses it: signing an
 * enveloped template with an HMAC key and an RSA key, verifying the signed
 * documents, a tampered payload, a tampered signature value, a missing key,
 * a node that is no Signature, the reference contexts it leaves, and the
 * buffers it keeps when asked. HMAC and RSA PKCS#1 v1.5 signatures are
 * deterministic, so both libraries write the same documents. Built against
 * the libxmlsec1 oracle with its default crypto library and against this
 * crate, both must print the same. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/dl.h>
#include <xmlsec/io.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>

#define RSA_KEY "tests/fixtures/keys/rsa/rsa-2048-key.pem"

/* Only the reason of a report is compared: the chain of reports above it
 * names the functions each library is built from. The whole report goes to
 * standard error. */
static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    fprintf(stderr, "xmldsig: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
            object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
            msg != NULL ? msg : "(null)");
    if (reason != XMLSEC_ERRORS_R_XMLSEC_FAILED) {
        printf("  report: reason=%d\n", reason);
    }
}

static const char secret[] = "secret-of-thirty-two-octets-long";

static const char payload[] =
    "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data></Envelope>";

static xmlSecKeyPtr hmac_key(void) {
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecKeyDataBinRead(xmlSecKeyDataHmacId, key, (const xmlSecByte *)secret,
                         sizeof(secret) - 1, ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    xmlSecKeySetName(key, BAD_CAST "hmac");
    return key;
}

static xmlSecKeyPtr rsa_key(void) {
    static xmlSecByte bytes[8192];
    size_t size;
    FILE *file = fopen(RSA_KEY, "rb");
    if (file == NULL) {
        return NULL;
    }
    size = fread(bytes, 1, sizeof(bytes), file);
    fclose(file);
    return xmlSecCryptoAppKeyLoadMemory(bytes, (xmlSecSize)size, xmlSecKeyDataFormatPem, NULL,
                                        NULL, NULL);
}

static void dump(const char *label, xmlDocPtr doc) {
    xmlChar *text = NULL;
    int size = 0;
    xsDocDumpMemory(doc, &text, &size);
    printf("%s: %.*s", label, size, (const char *)text);
    xsFree(text);
}

static void print_buffer(const char *label, xmlSecBufferPtr buffer) {
    if (buffer == NULL || xmlSecBufferGetData(buffer) == NULL) {
        printf("  %s: none\n", label);
        return;
    }
    printf("  %s: %.*s\n", label, (int)xmlSecBufferGetSize(buffer),
           (const char *)xmlSecBufferGetData(buffer));
}

/* The payload with an enveloped template signing #data with `method`. */
static xmlDocPtr signed_template(xmlSecTransformId method) {
    static const xmlChar *ids[] = {BAD_CAST "Id", NULL};
    xmlDocPtr doc = xsReadMemory(payload, (int)strlen(payload), "doc.xml", NULL, 0);
    xmlNodePtr signature = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, method, NULL);
    /* The payload's Id is an ID only once the caller registers it. */
    xmlSecAddIDs(doc, NULL, ids);
    xmlNodePtr reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha256Id,
                                                           NULL, BAD_CAST "#data", NULL);
    xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
    xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
    xmlSecAddChildNode(xsDocGetRootElement(doc), signature);
    return doc;
}

static xmlNodePtr signature_of(xmlDocPtr doc) {
    return xmlSecFindNode(xsDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
}

static void references(xmlSecDSigCtxPtr ctx) {
    xmlSecSize i;
    for (i = 0; i < xmlSecPtrListGetSize(&(ctx->signedInfoReferences)); ++i) {
        xmlSecDSigReferenceCtxPtr reference =
            (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(ctx->signedInfoReferences), i);
        printf("  reference %d: uri=%s status=%s origin=%d digest=%s\n", (int)i,
               reference->uri != NULL ? (const char *)reference->uri : "(null)",
               xmlSecDSigCtxGetStatusString(reference->status), (int)reference->origin,
               reference->digestMethod != NULL ? (const char *)reference->digestMethod->id->name
                                               : "(null)");
    }
}

/* Signs a template of `method` with `key`, printing the outcome. */
static xmlDocPtr sign(const char *label, xmlSecTransformId method, xmlSecKeyPtr key) {
    xmlDocPtr doc = signed_template(method);
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    int ret;
    printf("%s\n", label);
    ctx->signKey = key;
    ret = xmlSecDSigCtxSign(ctx, signature_of(doc));
    printf("  sign: %d status=%s method=%s\n", ret, xmlSecDSigCtxGetStatusString(ctx->status),
           ctx->signMethod != NULL ? (const char *)ctx->signMethod->id->name : "(null)");
    references(ctx);
    dump("  signed", doc);
    xmlSecDSigCtxDestroy(ctx);
    return doc;
}

/* Verifies the signature of `doc` with `key` and the context `flags`. */
static void verify(const char *label, xmlDocPtr doc, xmlSecKeyPtr key, unsigned int flags) {
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    int ret;
    printf("%s\n", label);
    ctx->flags = flags;
    ctx->signKey = key;
    ret = xmlSecDSigCtxVerify(ctx, signature_of(doc));
    printf("  verify: %d status=%s reason=%s\n", ret, xmlSecDSigCtxGetStatusString(ctx->status),
           xmlSecDSigCtxGetFailureReasonString(ctx->failureReason));
    /* libxmlsec1 digests the references before it checks the signature
     * value; the library checks the value first and dereferences nothing
     * when it fails, so the references of a failed value are not compared. */
    if (ctx->failureReason != xmlSecDSigFailureReasonSignature) {
        references(ctx);
    }
    if ((flags & XMLSEC_DSIG_FLAGS_STORE_SIGNATURE) != 0) {
        print_buffer("pre-sign", xmlSecDSigCtxGetPreSignBuffer(ctx));
    }
    if ((flags & XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES) != 0 &&
        xmlSecPtrListGetSize(&(ctx->signedInfoReferences)) > 0) {
        print_buffer("pre-digest",
                     xmlSecDSigReferenceCtxGetPreDigestBuffer(
                         (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(
                             &(ctx->signedInfoReferences), 0)));
    }
    xmlSecDSigCtxDestroy(ctx);
}

/* Signs a template of `method` keeping the buffers the storage `flags` ask
 * for: the canonical SignedInfo and the first reference's digested bytes. */
static void sign_keeping(const char *label, unsigned int flags) {
    xmlDocPtr doc = signed_template(xmlSecTransformHmacSha256Id);
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    printf("%s\n", label);
    ctx->flags = flags;
    ctx->signKey = hmac_key();
    printf("  sign: %d\n", xmlSecDSigCtxSign(ctx, signature_of(doc)));
    print_buffer("pre-sign", xmlSecDSigCtxGetPreSignBuffer(ctx));
    print_buffer("pre-digest", xmlSecDSigReferenceCtxGetPreDigestBuffer(
                                   (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(
                                       &(ctx->signedInfoReferences), 0)));
    xmlSecDSigCtxDestroy(ctx);
    xsFreeDoc(doc);
}

static int refuse_reference(xmlSecTransformCtxPtr ctx) {
    (void)ctx;
    return -1;
}

static int admit_reference(xmlSecTransformCtxPtr ctx) {
    (void)ctx;
    return 0;
}

/* Signs and verifies with a pre-execute callback the reference contexts
 * inherit: one that refuses stops the operation, one that admits does not. */
static void callbacks(void) {
    xmlDocPtr doc = signed_template(xmlSecTransformHmacSha256Id);
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    printf("pre-execute callback\n");
    ctx->transformCtx.preExecCallback = refuse_reference;
    ctx->signKey = hmac_key();
    printf("  refusing sign: %d\n", xmlSecDSigCtxSign(ctx, signature_of(doc)) < 0 ? -1 : 0);
    xmlSecDSigCtxDestroy(ctx);
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->transformCtx.preExecCallback = admit_reference;
    ctx->signKey = hmac_key();
    printf("  admitting sign: %d\n", xmlSecDSigCtxSign(ctx, signature_of(doc)));
    xmlSecDSigCtxDestroy(ctx);
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->transformCtx.preExecCallback = refuse_reference;
    ctx->signKey = hmac_key();
    printf("  refusing verify: %d\n", xmlSecDSigCtxVerify(ctx, signature_of(doc)) < 0 ? -1 : 0);
    xmlSecDSigCtxDestroy(ctx);
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->referencePreExecuteCallback = refuse_reference;
    ctx->signKey = hmac_key();
    printf("  refusing reference verify: %d\n",
           xmlSecDSigCtxVerify(ctx, signature_of(doc)) < 0 ? -1 : 0);
    xmlSecDSigCtxDestroy(ctx);
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->referencePreExecuteCallback = admit_reference;
    ctx->signKey = hmac_key();
    printf("  admitting reference verify: %d", xmlSecDSigCtxVerify(ctx, signature_of(doc)));
    printf(" status=%s\n", xmlSecDSigCtxGetStatusString(ctx->status));
    xmlSecDSigCtxDestroy(ctx);
    xsFreeDoc(doc);
}

static const char resource[] = "detached payload read through the caller's callbacks";
static size_t resource_position;

static int match_resource(const char *uri) {
    return strncmp(uri, "example:", 8) == 0;
}

static void *open_resource(const char *uri) {
    (void)uri;
    resource_position = 0;
    return &resource_position;
}

static int read_resource(void *context, char *buffer, int len) {
    size_t left = sizeof(resource) - 1 - resource_position;
    size_t count = left < (size_t)len ? left : (size_t)len;
    (void)context;
    memcpy(buffer, resource + resource_position, count);
    resource_position += count;
    return (int)count;
}

static int close_resource(void *context) {
    (void)context;
    return 0;
}

/* A detached signature over a resource the caller's input callbacks read:
 * signed, then verified with the same callbacks. */
static void detached(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr signature =
        xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, xmlSecTransformHmacSha256Id, NULL);
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    xsDocSetRootElement(doc, signature);
    xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha256Id, NULL,
                                    BAD_CAST "example:payload", NULL);
    printf("detached\n");
    printf("  register: %d\n", xmlSecIORegisterCallbacks(match_resource, open_resource,
                                                         read_resource, close_resource));
    ctx->signKey = hmac_key();
    ctx->enabledReferenceUris = xmlSecTransformUriTypeAny;
    printf("  sign: %d\n", xmlSecDSigCtxSign(ctx, signature));
    dump("  signed", doc);
    xmlSecDSigCtxDestroy(ctx);
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->signKey = hmac_key();
    ctx->enabledReferenceUris = xmlSecTransformUriTypeAny;
    printf("  verify: %d", xmlSecDSigCtxVerify(ctx, signature));
    printf(" status=%s\n", xmlSecDSigCtxGetStatusString(ctx->status));
    xmlSecDSigCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* A SignedInfo reference over a Manifest whose own reference covers the
 * payload: signing writes both digests. */
static void manifest(void) {
    static const xmlChar *ids[] = {BAD_CAST "Id", NULL};
    xmlDocPtr doc = xsReadMemory(payload, (int)strlen(payload), "doc.xml", NULL, 0);
    xmlNodePtr signature = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
                                                     xmlSecTransformHmacSha256Id, NULL);
    xmlNodePtr object;
    xmlNodePtr list;
    xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(NULL);
    xmlSecAddChildNode(xsDocGetRootElement(doc), signature);
    /* Each chain ends in a canonicalization, so neither library adds one. */
    xmlSecTmplReferenceAddTransform(
        xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha256Id, NULL,
                                        BAD_CAST "#manifest",
                                        BAD_CAST "http://www.w3.org/2000/09/xmldsig#Manifest"),
        xmlSecTransformExclC14NId);
    object = xmlSecTmplSignatureAddObject(signature, NULL, NULL, NULL);
    list = xmlSecTmplObjectAddManifest(object, BAD_CAST "manifest");
    xmlSecTmplReferenceAddTransform(
        xmlSecTmplManifestAddReference(list, xmlSecTransformSha256Id, NULL, BAD_CAST "#data", NULL),
        xmlSecTransformExclC14NId);
    xmlSecAddIDs(doc, NULL, ids);
    printf("manifest\n");
    ctx->signKey = hmac_key();
    printf("  sign: %d\n", xmlSecDSigCtxSign(ctx, signature));
    dump("  signed", doc);
    xmlSecDSigCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* Replaces the text of the first `name` element in `ns` of `doc`. */
static void tamper(xmlDocPtr doc, const xmlChar *name, const xmlChar *ns, const char *text) {
    xmlNodePtr node = xmlSecFindNode(xsDocGetRootElement(doc), name, ns);
    xsNodeSetContent(node, BAD_CAST text);
}

int main(void) {
    xmlDocPtr doc;
    xmlSecDSigCtxPtr ctx;
    xmlSecKeysMngrPtr mngr;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    sign_keeping("hmac sign keeping buffers", XMLSEC_DSIG_FLAGS_STORE_SIGNATURE |
                                                  XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES);
    callbacks();
    detached();
    manifest();

    doc = sign("hmac sign", xmlSecTransformHmacSha256Id, hmac_key());
    verify("hmac verify", doc, hmac_key(), 0);
    verify("hmac verify keeping buffers", doc, hmac_key(),
           XMLSEC_DSIG_FLAGS_STORE_SIGNATURE | XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES);
    tamper(doc, BAD_CAST "SignatureValue", xmlSecDSigNs, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    verify("hmac tampered signature value", doc, hmac_key(), 0);
    xsFreeDoc(doc);

    doc = sign("rsa sign", xmlSecTransformRsaSha256Id, rsa_key());
    verify("rsa verify", doc, rsa_key(), 0);
    tamper(doc, BAD_CAST "Data", BAD_CAST "urn:envelope", "changed");
    verify("rsa tampered payload", doc, rsa_key(), 0);
    xsFreeDoc(doc);

    /* No key and a keys manager that has none. */
    doc = sign("hmac sign again", xmlSecTransformHmacSha256Id, hmac_key());
    mngr = xmlSecKeysMngrCreate();
    xmlSecCryptoAppDefaultKeysMngrInit(mngr);
    ctx = xmlSecDSigCtxCreate(mngr);
    printf("missing key\n");
    printf("  verify: %d", xmlSecDSigCtxVerify(ctx, signature_of(doc)));
    printf(" status=%s reason=%s\n", xmlSecDSigCtxGetStatusString(ctx->status),
           xmlSecDSigCtxGetFailureReasonString(ctx->failureReason));
    xmlSecDSigCtxDestroy(ctx);

    /* A node that is no Signature, and a context that already ran. */
    ctx = xmlSecDSigCtxCreate(NULL);
    ctx->signKey = hmac_key();
    printf("not a signature\n");
    printf("  verify: %d", xmlSecDSigCtxVerify(ctx, xsDocGetRootElement(doc)));
    printf(" status=%s\n", xmlSecDSigCtxGetStatusString(ctx->status));
    xmlSecDSigCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
    xsFreeDoc(doc);

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
