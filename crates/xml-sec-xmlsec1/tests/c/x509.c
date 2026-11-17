/* X.509 certificates as a libxmlsec1 caller uses them through the default
 * crypto library: the default keys manager with its X.509 store, trusted
 * and untrusted certificates and CRLs loaded from memory, a KeyInfo whose
 * X509Data carries or names the signer's certificate read with and without
 * a path to a trusted certificate, the verification flags and time, a key
 * loaded from a certificate, a key's certificates written into X509Data
 * templates, keys from PKCS#12 and the keys manager's key verification.
 * The program reads the files and passes their bytes. Built against the
 * libxmlsec1 oracle with its default crypto library and against this crate,
 * both must print the same; a report prints its reason only, its wording
 * belonging to each implementation. */

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
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>

#define ROOT "tests/fixtures/keys/cacert.pem"
#define INTERMEDIATE "tests/fixtures/keys/ca2cert.pem"
#define LEAF "tests/fixtures/keys/rsa/rsa-2048-cert.pem"
#define LEAF_KEY "tests/fixtures/keys/rsa/rsa-2048-key.pem"
#define CRL "tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem"
#define PKCS12 "tests/fixtures/keys/pkcs12/rsa-key-unrelated-ca.p12.b64"

#define DSIG "http://www.w3.org/2000/09/xmldsig#"

/* 2026-03-20T00:00:00Z: inside the validity of every certificate here and
 * of the CRL. */
#define IN_CRL_WINDOW 1773964800
/* 2001-09-09T01:46:40Z: before every certificate here. */
#define BEFORE_ISSUE 1000000000

static int quiet = 0;
/* The reason of the first report since the last `first_report()`: the
 * cause of a failure, before the chain of reports above it, whose length
 * each implementation's layering sets. */
static int first_reason = 0;

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    /* The whole report goes to standard error, which is not compared. */
    fprintf(stderr, "x509: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
            object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
            msg != NULL ? msg : "(null)");
    if (!quiet && first_reason == 0) {
        first_reason = reason;
    }
}

/* Prints the reason of the first report since the last call, if any. */
static void first_report(void) {
    if (first_reason != 0) {
        printf("  first report: reason=%d\n", first_reason);
    }
    first_reason = 0;
}

/* The bytes of the file `path` in `out`; returns their size. */
static xmlSecSize read_file(const char *path, xmlSecByte *out, xmlSecSize capacity) {
    size_t size;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    size = fread(out, 1, capacity - 1, file);
    fclose(file);
    out[size] = '\0';
    return (xmlSecSize)size;
}

/* The Base64 body of the PEM file `path`, between its BEGIN and END lines. */
static const char *pem_body(const char *path, char *out, size_t capacity) {
    char *begin;
    char *end;
    if (read_file(path, (xmlSecByte *)out, (xmlSecSize)capacity) == 0) {
        return "";
    }
    begin = strstr(out, "-----BEGIN");
    begin = begin != NULL ? strchr(begin, '\n') : NULL;
    end = begin != NULL ? strstr(begin, "-----END") : NULL;
    if (end == NULL) {
        return "";
    }
    *end = '\0';
    return begin + 1;
}

/* Loads the certificate file `path` into the X.509 store of `mngr`. */
static void load_cert(const char *label, xmlSecKeysMngrPtr mngr, const char *path,
                      xmlSecKeyDataType type) {
    static xmlSecByte bytes[16384];
    xmlSecSize size = read_file(path, bytes, sizeof(bytes));
    printf("%s: %d\n", label,
           xmlSecCryptoAppKeysMngrCertLoadMemory(mngr, bytes, size, xmlSecKeyDataFormatPem, type));
}

/* A default keys manager with the root trusted, when `root`, and the
 * intermediate known, when `intermediate`. */
static xmlSecKeysMngrPtr manager(const char *label, int root, int intermediate) {
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    printf("%s: init=%d\n", label, xmlSecCryptoAppDefaultKeysMngrInit(mngr));
    if (root) {
        load_cert("  trusted root", mngr, ROOT, xmlSecKeyDataTypeTrusted);
    }
    if (intermediate) {
        load_cert("  untrusted intermediate", mngr, INTERMEDIATE, 0);
    }
    return mngr;
}

/* Prints what `key` holds. */
static void show(xmlSecKeyPtr key) {
    xmlSecKeyDataPtr value = xmlSecKeyGetValue(key);
    printf("  key: klass=%s size=%u x509=%d valid=[%ld,%ld]\n",
           value != NULL ? (const char *)value->id->name : "(none)",
           value != NULL ? (unsigned)xmlSecKeyDataGetSize(value) : 0u,
           xmlSecKeyGetData(key, xmlSecKeyDataX509Id) != NULL, (long)key->notValidBefore,
           (long)key->notValidAfter);
}

/* Reads the KeyInfo of `xml` with the keys manager `mngr`, the flags and
 * the certificate verification time given. */
static void read_key_info(const char *label, xmlSecKeysMngrPtr mngr, const char *xml,
                          unsigned int flags, time_t at) {
    xmlDocPtr doc = xsReadMemory(xml, (int)strlen(xml), "keyinfo.xml", NULL, 0);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(mngr);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    ctx->flags = flags;
    ctx->certsVerificationTime = at;
    printf("%s:\n", label);
    first_reason = 0;
    printf("  read: %d\n", xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx));
    first_report();
    show(key);
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* A KeyInfo whose X509Data carries `first` and, when not null, `second`. */
static const char *carrying(char *out, size_t capacity, const char *first, const char *second) {
    snprintf(out, capacity,
             "<KeyInfo xmlns='" DSIG "'><X509Data>"
             "<X509Certificate>%s</X509Certificate>%s%s%s"
             "</X509Data></KeyInfo>",
             first, second != NULL ? "<X509Certificate>" : "", second != NULL ? second : "",
             second != NULL ? "</X509Certificate>" : "");
    return out;
}

/* Writes the X.509 data of `key` into the KeyInfo template `xml`. */
static void write_template(const char *label, xmlSecKeyPtr key, const char *xml) {
    xmlDocPtr doc = xsReadMemory(xml, (int)strlen(xml), "template.xml", NULL, 0);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlChar *text = NULL;
    int size = 0;
    ctx->mode = xmlSecKeyInfoModeWrite;
    ctx->keyReq.keyType = xmlSecKeyDataTypeAny;
    printf("%s: %d\n", label, xmlSecKeyInfoNodeWrite(xsDocGetRootElement(doc), key, ctx));
    xsDocDumpMemory(doc, &text, &size);
    printf("%.*s", size, text != NULL ? (const char *)text : "");
    xsFree(text);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

int main(void) {
    static char leaf_file[8192];
    static char intermediate_file[8192];
    const char *leaf;
    const char *intermediate;
    static char xml[20000];
    static xmlSecByte bytes[16384];
    static xmlSecByte decoded[16384];
    xmlSecKeysMngrPtr mngr;
    xmlSecKeyPtr key;
    xmlSecKeyInfoCtxPtr ctx;
    xmlSecSize size;
    xmlSecSize length = 0;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }
    leaf = pem_body(LEAF, leaf_file, sizeof(leaf_file));
    intermediate = pem_body(INTERMEDIATE, intermediate_file, sizeof(intermediate_file));

    /* The signer's certificate verifies through a known intermediate or one
     * the document carries; without a trusted root it supplies no key. */
    mngr = manager("root and intermediate", 1, 1);
    read_key_info("leaf alone", mngr, carrying(xml, sizeof(xml), leaf, NULL), 0, 0);
    read_key_info("leaf before its validity", mngr, carrying(xml, sizeof(xml), leaf, NULL), 0,
                  BEFORE_ISSUE);
    xmlSecKeysMngrDestroy(mngr);

    mngr = manager("root only", 1, 0);
    read_key_info("leaf and intermediate", mngr,
                  carrying(xml, sizeof(xml), leaf, intermediate), 0, 0);
    read_key_info("leaf alone", mngr, carrying(xml, sizeof(xml), leaf, NULL), 0, 0);
    xmlSecKeysMngrDestroy(mngr);

    mngr = manager("nothing trusted", 0, 1);
    read_key_info("leaf", mngr, carrying(xml, sizeof(xml), leaf, NULL), 0, 0);
    read_key_info("leaf, stop on invalid", mngr, carrying(xml, sizeof(xml), leaf, NULL),
                  XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT, 0);
    read_key_info("leaf, not verified", mngr, carrying(xml, sizeof(xml), leaf, NULL),
                  XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS, 0);
    xmlSecKeysMngrDestroy(mngr);

    /* A certificate the store knows, named by its subject. */
    mngr = manager("root, intermediate and leaf", 1, 1);
    load_cert("  untrusted leaf", mngr, LEAF, 0);
    read_key_info("subject name", mngr,
                  "<KeyInfo xmlns='" DSIG "'><X509Data><X509SubjectName>"
                  "CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),"
                  "ST=California,C=US</X509SubjectName></X509Data></KeyInfo>",
                  0, 0);
    read_key_info("unknown subject, stop on unknown", mngr,
                  "<KeyInfo xmlns='" DSIG "'><X509Data><X509SubjectName>CN=Nobody"
                  "</X509SubjectName></X509Data></KeyInfo>",
                  XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT, 0);
    xmlSecKeysMngrDestroy(mngr);

    /* A CRL revoking the signer: no key, whichever reason each reports. */
    mngr = manager("root, intermediate and CRL", 1, 1);
    size = read_file(CRL, bytes, sizeof(bytes));
    printf("  crl: %d\n",
           xmlSecCryptoAppKeysMngrCrlLoadMemory(mngr, bytes, size, xmlSecKeyDataFormatPem));
    quiet = 1;
    read_key_info("revoked leaf", mngr, carrying(xml, sizeof(xml), leaf, NULL), 0, IN_CRL_WINDOW);
    quiet = 0;
    xmlSecKeysMngrDestroy(mngr);

    /* A key from a certificate format holds its key and its certificate. */
    size = read_file(LEAF, bytes, sizeof(bytes));
    key = xmlSecCryptoAppKeyLoadMemory(bytes, size, xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
    printf("key from certificate:\n");
    if (key != NULL) {
        show(key);
        xmlSecKeyDestroy(key);
    }

    /* A private key with its certificate and the intermediate, written into
     * templates, then verified by the keys manager. */
    size = read_file(LEAF_KEY, bytes, sizeof(bytes));
    key = xmlSecCryptoAppKeyLoadMemory(bytes, size, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    size = read_file(LEAF, bytes, sizeof(bytes));
    printf("key certificate: %d\n",
           xmlSecCryptoAppKeyCertLoadMemory(key, bytes, size, xmlSecKeyDataFormatPem));
    size = read_file(INTERMEDIATE, bytes, sizeof(bytes));
    printf("other certificate: %d\n",
           xmlSecCryptoAppKeyCertLoadMemory(key, bytes, size, xmlSecKeyDataFormatPem));
    write_template("empty X509Data", key,
                   "<KeyInfo xmlns='" DSIG "'><X509Data/></KeyInfo>");
    write_template("certificate node", key,
                   "<KeyInfo xmlns='" DSIG "'><X509Data><X509Certificate/></X509Data></KeyInfo>");
    write_template("names, serial and key identifier", key,
                   "<KeyInfo xmlns='" DSIG "'><X509Data><X509SubjectName/><X509IssuerSerial/>"
                   "<X509SKI/></X509Data></KeyInfo>");

    /* The default keys manager finds a key it holds by its certificate. */
    mngr = manager("keys manager holding the key", 0, 0);
    printf("  adopt: %d\n", xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, xmlSecKeyDuplicate(key)));
    read_key_info("subject of the held key", mngr,
                  "<KeyInfo xmlns='" DSIG "'><X509Data><X509SubjectName>"
                  "CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),"
                  "ST=California,C=US</X509SubjectName></X509Data></KeyInfo>",
                  0, 0);
    xmlSecKeysMngrDestroy(mngr);

    mngr = manager("verify key with root", 1, 0);
    ctx = xmlSecKeyInfoCtxCreate(mngr);
    printf("  verify: %d\n", xmlSecCryptoAppDefaultKeysMngrVerifyKey(mngr, key, ctx));
    xmlSecKeyInfoCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
    mngr = manager("verify key without root", 0, 0);
    ctx = xmlSecKeyInfoCtxCreate(mngr);
    quiet = 1;
    printf("  verify: %d\n", xmlSecCryptoAppDefaultKeysMngrVerifyKey(mngr, key, ctx));
    quiet = 0;
    xmlSecKeyInfoCtxDestroy(ctx);
    xmlSecKeysMngrDestroy(mngr);
    xmlSecKeyDestroy(key);

    /* A PKCS#12 key with an unrelated CA: the CA is the key's certificate
     * data, not its key certificate. */
    size = read_file(PKCS12, bytes, sizeof(bytes));
    key = size > 0 && xmlSecBase64Decode_ex(bytes, decoded, sizeof(decoded), &length) == 0
              ? xmlSecCryptoAppPkcs12LoadMemory(decoded, length, "secret", NULL, NULL)
              : NULL;
    printf("pkcs12:\n");
    if (key != NULL) {
        show(key);
        write_template("pkcs12 certificates", key,
                       "<KeyInfo xmlns='" DSIG "'><X509Data/></KeyInfo>");
        xmlSecKeyDestroy(key);
    }

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    printf("done\n");
    return 0;
}
