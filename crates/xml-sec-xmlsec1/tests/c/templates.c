/* The templates.h functions as a libxmlsec1 caller uses them: signature,
 * reference, object and manifest templates, encrypted data and keys, KeyInfo
 * and X509Data children and transform content, including the refusals of a
 * second unique child. Built against the pinned libxmlsec1 and against this
 * crate, both must print the same trees, results and reports. Algorithms
 * are klasses of the program's own: a template reads only their href. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/transforms.h>
#include <xmlsec/templates.h>

/* A parser's own diagnostic after "xml error: " (its code and wording) is
 * the parser's, not part of the contract, so only its presence is printed. */
static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    const char *diagnostic = msg != NULL ? strstr(msg, "xml error: ") : NULL;
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%.*s%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           diagnostic != NULL ? (int)(diagnostic - msg) : (int)strlen(msg != NULL ? msg : "(null)"),
           msg != NULL ? msg : "(null)", diagnostic != NULL ? "xml error: <parser diagnostic>" : "");
}

/* Every dumped node is its document's element, so the document is dumped. */
static void dump_node(const char *label, xmlDocPtr doc, xmlNodePtr node) {
    xmlChar *text = NULL;
    int size = 0;
    (void)node;
    xsDocDumpMemory(doc, &text, &size);
    printf("%s: %.*s", label, size, (const char *)text);
    xsFree(text);
}

/* Prints the Algorithm attribute of `node` as `label` and releases it. */
static void print_algorithm(const char *label, xmlNodePtr node) {
    xmlChar *value = xsGetProp(node, BAD_CAST "Algorithm");
    printf("%s: %s\n", label, value != NULL ? (const char *)value : "(null)");
    xsFree(value);
}

#define KLASS(var, label, uri)                                                                   \
    static struct _xmlSecTransformKlass var = {.klassSize = sizeof(xmlSecTransformKlass),       \
                                               .objSize = sizeof(xmlSecTransform),              \
                                               .name = BAD_CAST label,                          \
                                               .href = uri}

KLASS(c14n, "c14n", BAD_CAST "urn:alg:c14n");
KLASS(sign, "sign", BAD_CAST "urn:alg:sign");
KLASS(digest, "digest", BAD_CAST "urn:alg:digest");
KLASS(cipher, "cipher", BAD_CAST "urn:alg:cipher");
KLASS(nohref, "nohref", NULL);

static void signature(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr root = xsNewDocNode(doc, NULL, BAD_CAST "Doc", NULL);
    xmlNodePtr signNode;
    xmlNodePtr ref;
    xmlNodePtr obj;
    xmlNodePtr manifest;
    xmlNodePtr keyInfo;
    xmlNodePtr x509;
    xmlNodePtr serial;
    xmlNodePtr transform;
    xmlNodePtr retrieval;
    const xmlChar *nsList[] = {BAD_CAST "a", BAD_CAST "urn:a", BAD_CAST "#default", BAD_CAST "urn:d", NULL};
    const xmlChar *badList[] = {BAD_CAST "a", NULL};

    xsDocSetRootElement(doc, root);
    printf("signature\n");
    signNode = xmlSecTmplSignatureCreateNsPref(doc, &c14n, &sign, BAD_CAST "sig1", BAD_CAST "ds");
    xsAddChild(root, signNode);
    printf("  no c14n: %p\n", (void *)xmlSecTmplSignatureCreate(doc, NULL, &sign, NULL));
    printf("  no href: %p\n", (void *)xmlSecTmplSignatureCreate(doc, &c14n, &nohref, NULL));

    ref = xmlSecTmplSignatureAddReference(signNode, &digest, BAD_CAST "r1", BAD_CAST "#obj", BAD_CAST "urn:type");
    transform = xmlSecTmplReferenceAddTransform(ref, &c14n);
    printf("  c14n incl: %d\n", xmlSecTmplTransformAddC14NInclNamespaces(transform, BAD_CAST "a #default"));
    printf("  c14n incl again: %d\n", xmlSecTmplTransformAddC14NInclNamespaces(transform, BAD_CAST "b"));
    transform = xmlSecTmplReferenceAddTransform(ref, &sign);
    printf("  xpath: %d\n", xmlSecTmplTransformAddXPath(transform, BAD_CAST "not(a<b)", nsList));
    printf("  xpath again: %d\n", xmlSecTmplTransformAddXPath(transform, BAD_CAST "1", NULL));
    printf("  xpath2: %d\n", xmlSecTmplTransformAddXPath2(transform, BAD_CAST "union", BAD_CAST "//a", NULL));
    printf("  xpath2 bad list: %d\n", xmlSecTmplTransformAddXPath2(transform, BAD_CAST "subtract", BAD_CAST "//b", badList));
    printf("  xpointer: %d\n", xmlSecTmplTransformAddXPointer(transform, BAD_CAST "xpointer(id('x'))", NULL));
    printf("  xpointer again: %d\n", xmlSecTmplTransformAddXPointer(transform, BAD_CAST "x", NULL));
    printf("  hmac: %d\n", xmlSecTmplTransformAddHmacOutputLength(transform, 160));
    printf("  hmac again: %d\n", xmlSecTmplTransformAddHmacOutputLength(transform, 80));
    printf("  hmac zero: %d\n", xmlSecTmplTransformAddHmacOutputLength(transform, 0));
    printf("  no transform href: %p\n", (void *)xmlSecTmplReferenceAddTransform(ref, &nohref));
    printf("  ref no digest: %p\n", (void *)xmlSecTmplSignatureAddReference(signNode, NULL, NULL, NULL, NULL));

    obj = xmlSecTmplSignatureAddObject(signNode, BAD_CAST "obj", BAD_CAST "text/xml", BAD_CAST "utf-8");
    xmlSecTmplObjectAddSignProperties(obj, BAD_CAST "props", BAD_CAST "#sig1");
    manifest = xmlSecTmplObjectAddManifest(obj, BAD_CAST "man");
    xmlSecTmplManifestAddReference(manifest, &digest, NULL, BAD_CAST "urn:x", NULL);
    printf("  manifest no node: %p\n", (void *)xmlSecTmplManifestAddReference(NULL, &digest, NULL, NULL, NULL));

    keyInfo = xmlSecTmplSignatureEnsureKeyInfo(signNode, BAD_CAST "ki");
    printf("  ensure again: %d\n", xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL) == keyInfo);
    xmlSecTmplKeyInfoAddKeyName(keyInfo, BAD_CAST "a&b");
    xmlSecTmplKeyInfoAddKeyValue(keyInfo);
    x509 = xmlSecTmplKeyInfoAddX509Data(keyInfo);
    serial = xmlSecTmplX509DataAddIssuerSerial(x509);
    printf("  issuer serial again: %p\n", (void *)xmlSecTmplX509DataAddIssuerSerial(x509));
    xmlSecTmplX509IssuerSerialAddIssuerName(serial, BAD_CAST "CN=a<b");
    printf("  issuer name again: %p\n", (void *)xmlSecTmplX509IssuerSerialAddIssuerName(serial, NULL));
    xmlSecTmplX509IssuerSerialAddSerialNumber(serial, BAD_CAST "42");
    printf("  serial again: %p\n", (void *)xmlSecTmplX509IssuerSerialAddSerialNumber(serial, NULL));
    xmlSecTmplX509DataAddSubjectName(x509);
    xmlSecTmplX509DataAddSKI(x509);
    xmlSecTmplX509DataAddDigest(x509, BAD_CAST "urn:alg:digest");
    printf("  digest again: %p\n", (void *)xmlSecTmplX509DataAddDigest(x509, BAD_CAST "urn:alg:digest"));
    printf("  digest null: %p\n", (void *)xmlSecTmplX509DataAddDigest(x509, NULL));
    xmlSecTmplX509DataAddCertificate(x509);
    printf("  certificate again: %p\n", (void *)xmlSecTmplX509DataAddCertificate(x509));
    xmlSecTmplX509DataAddCRL(x509);
    retrieval = xmlSecTmplKeyInfoAddRetrievalMethod(keyInfo, BAD_CAST "#x509", BAD_CAST "urn:type:x509");
    xmlSecTmplRetrievalMethodAddTransform(retrieval, &c14n);
    xmlSecTmplRetrievalMethodAddTransform(retrieval, &sign);

    print_algorithm("  sign method", xmlSecTmplSignatureGetSignMethodNode(signNode));
    print_algorithm("  c14n method", xmlSecTmplSignatureGetC14NMethodNode(signNode));
    printf("  method of bare node: %p\n", (void *)xmlSecTmplSignatureGetSignMethodNode(root));
    printf("  key info of bare node: %p\n", (void *)xmlSecTmplSignatureEnsureKeyInfo(root, NULL));
    dump_node("  tree", doc, root);
    xsFreeDoc(doc);
}

static void reference_with_children(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr signNode = xmlSecTmplSignatureCreate(doc, &c14n, &sign, NULL);
    xmlNodePtr ref;

    printf("reference transforms first\n");
    xsDocSetRootElement(doc, signNode);
    ref = xmlSecTmplSignatureAddReference(signNode, &digest, NULL, NULL, NULL);
    xmlSecTmplReferenceAddTransform(ref, &c14n);
    dump_node("  tree", doc, signNode);
    xsFreeDoc(doc);
}

static void encryption(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr enc;
    xmlNodePtr keyInfo;
    xmlNodePtr encKey;
    xmlNodePtr cref;
    xmlNodePtr transform;

    printf("encryption\n");
    enc = xmlSecTmplEncDataCreate(doc, &cipher, BAD_CAST "ed", BAD_CAST "urn:content", BAD_CAST "text/plain",
                                  BAD_CAST "base64");
    xsDocSetRootElement(doc, enc);
    print_algorithm("  method", xmlSecTmplEncDataGetEncMethodNode(enc));
    keyInfo = xmlSecTmplEncDataEnsureKeyInfo(enc, BAD_CAST "eki");
    printf("  ensure again: %d\n", xmlSecTmplEncDataEnsureKeyInfo(enc, NULL) == keyInfo);
    encKey = xmlSecTmplKeyInfoAddEncryptedKey(keyInfo, &cipher, BAD_CAST "ek", NULL, BAD_CAST "bob");
    xmlSecTmplReferenceListAddDataReference(encKey, BAD_CAST "#ed");
    xmlSecTmplReferenceListAddKeyReference(encKey, BAD_CAST "#ek2");
    xmlSecTmplReferenceListAddDataReference(encKey, NULL);
    print_algorithm("  key method", xmlSecTmplEncDataGetEncMethodNode(encKey));
    xmlSecTmplEncDataEnsureCipherValue(encKey);
    printf("  cipher reference on value: %p\n", (void *)xmlSecTmplEncDataEnsureCipherReference(encKey, NULL));
    xmlSecTmplEncDataAddEncProperty(enc, BAD_CAST "p1", BAD_CAST "#ed");
    xmlSecTmplEncDataAddEncProperty(enc, NULL, NULL);
    xmlSecTmplEncDataEnsureEncProperties(enc, BAD_CAST "props");
    cref = xmlSecTmplEncDataEnsureCipherReference(enc, BAD_CAST "urn:data");
    printf("  ensure again: %d\n", xmlSecTmplEncDataEnsureCipherReference(enc, NULL) == cref);
    printf("  cipher value on reference: %p\n", (void *)xmlSecTmplEncDataEnsureCipherValue(enc));
    xmlSecTmplCipherReferenceAddTransform(cref, &c14n);
    xmlSecTmplCipherReferenceAddTransform(cref, &sign);
    transform = xmlSecTmplEncDataGetEncMethodNode(enc);
    printf("  oaep: %d\n", xmlSecTmplTransformAddRsaOaepParam(transform, BAD_CAST "label", 5));
    printf("  oaep again: %d\n", xmlSecTmplTransformAddRsaOaepParam(transform, BAD_CAST "x", 1));
    printf("  mgf: %d\n", xmlSecTmplTransformAddRsaMgf(transform, BAD_CAST "urn:alg:mgf"));
    printf("  mgf again: %d\n", xmlSecTmplTransformAddRsaMgf(transform, BAD_CAST "urn:alg:mgf"));
    printf("  rsa digest: %d\n", xmlSecTmplTransformAddRsaDigest(transform, BAD_CAST "urn:alg:digest"));
    printf("  rsa digest again: %d\n", xmlSecTmplTransformAddRsaDigest(transform, BAD_CAST "urn:alg:digest"));
    dump_node("  tree", doc, enc);
    xsFreeDoc(doc);

    doc = xsNewDoc(BAD_CAST "1.0");
    enc = xmlSecTmplEncDataCreate(doc, NULL, NULL, NULL, NULL, NULL);
    xsDocSetRootElement(doc, enc);
    printf("  no method: %p\n", (void *)xmlSecTmplEncDataGetEncMethodNode(enc));
    printf("  bad method: %p\n", (void *)xmlSecTmplEncDataCreate(doc, &nohref, NULL, NULL, NULL, NULL));
    dump_node("  bare", doc, enc);
    /* the refused node stays the caller's */
    transform = xsNewDocNode(doc, NULL, BAD_CAST "x", NULL);
    printf("  key info of bare node: %p\n", (void *)xmlSecTmplEncDataEnsureKeyInfo(transform, NULL));
    xsFreeNode(transform);
    xsFreeDoc(doc);
}

static void stylesheet(void) {
    xmlDocPtr doc = xsNewDoc(BAD_CAST "1.0");
    xmlNodePtr transform = xsNewDocNode(doc, NULL, BAD_CAST "Transform", NULL);

    printf("stylesheet\n");
    xsDocSetRootElement(doc, transform);
    xsNodeSetContent(transform, BAD_CAST "old");
    printf("  xslt: %d\n", xmlSecTmplTransformAddXsltStylesheet(
                               transform, BAD_CAST "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'/>"));
    printf("  bad xslt: %d\n", xmlSecTmplTransformAddXsltStylesheet(transform, BAD_CAST "<a>"));
    dump_node("  tree", doc, transform);
    xsFreeDoc(doc);
}

int main(void) {
    xmlSecErrorsSetCallback(record);
    signature();
    reference_with_children();
    encryption();
    stylesheet();
    printf("done\n");
    return 0;
}
