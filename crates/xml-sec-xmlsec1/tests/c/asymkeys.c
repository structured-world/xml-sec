/* The RSA, DSA and EC key-data klasses of the default crypto library as a
 * libxmlsec1 caller uses them: the klasses' identities, reading a public key
 * from its KeyValue child, the key's size, type and dumps, refusing a second
 * value, duplicating, and writing the key back under the key requirements.
 * Built against the pinned libxmlsec1 with its default crypto library and
 * against this crate, both must print the same. Failures whose reports name
 * the implementation's own reader print their result only. */

#include <stdio.h>
#include <stdlib.h>
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

#define DSIG "http://www.w3.org/2000/09/xmldsig#"
#define DSIG11 "http://www.w3.org/2009/xmldsig11#"

static int quiet;

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

/* tests/fixtures/keys/rsa/rsa-2048-pubkey.pem */
static const char rsaModulus[] =
    "DE25678435E5806896BD5D9FDB56C23F8340793930A2E5AF37D2BDE1235E574D71CEEBCF8361916FEA33174FD86D"
    "0F238FB5037AE22070BA01AC2FE348CB69EE0269EB38F7A07857F7B35956FE5205498138945B07C79FCB76A94EF4"
    "EF5A5CC94213B85955C1443AA60347461CF451B8C07A975DB9C32F9604C5B13BA073528A1EF66D0EA505E32A8909"
    "285725F5977886DDC4A975BC72E1E08B2AED6335D370EEB75BDF89E9D14E8B50D362128C90AE778CCB0CA1D96578"
    "451DA941E04DBC4AD1305260C6B6B01D6B19F715ABE41A9CE96C4475C05E264CFC113AB8FAA516AFA0E68B1265B1"
    "DF1F6A82FF41BFC0A2A55B3231D183E341206AFCC6EBA2874A2D";
static const char rsaExponent[] = "010001";

/* tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem */
static const char ecPoint[] =
    "04fe130d43176a7acfb3442623c6c62b497bc779a1342b75d6796fdfee85eae5a94998ed66e3c79dbf8e0b0042"
    "70f1ca78ad63db8ada1d783c225e57c33c7660dc";

/* tests/fixtures/keys/dsa/dsa-2048-public.pem */
static const char dsaP[] =
    "ee6053a5eddb044cebe039fbef8731678ba7ea05dad44a661db4021944a9d3b13b641e54ae6027f37543881d815e"
    "e9677aa601a1b23bef7125258174ef86d5102f888f0266360925a868365042157c4dc0baa1fa3dcf9d347aff8d5d"
    "f2e2ef5ed320e6014ef58b5b0cf40038ef5820e1dcc77ea754e352a1a642a28ff674ec36019d9ce503043d5401ca"
    "fb06d50bb270421542a94bb469a82c385e8b91f4d70fb5ebb98480cf67838aa3afee90181bc2e84dfae530ed7162"
    "ff2d2788a8e2cfbf9b20dfaa75de56c942ccb7cd91a6d35ab4fda05e116a98273df686bf6ab7848ef40b45190830"
    "181774df7cc09fc8a863242d8e68cc3b83f00dfdee3f41019ab9";
static const char dsaQ[] = "d094a9173ea610840178a01a279c6cc08977fe113d1b36e1c1e4a1d4dfc3c177";
static const char dsaG[] =
    "49d14f2709557a09525d5bb21dcea4838ab19b6cdb1a87019d53db1174ddf4ff32e9d34cb54d0456b55baa8377c6"
    "7af8a65e6930b78a0b0ba39fdfe7dda17b4866bcf6063dab6d9d59d201ef40d71b26f800fa8ac5f7fac9143fe4fb"
    "f3692087ce9a09c73da1d71fcee3ec7790b0f94220dfed60dba7ba722bc59b7c6765418b6347f1b859fe73064de8"
    "332f45d229679501e1964eef0e1f6e6f6b19be5de69da8f0141900b60e6f700b7c4cb531951ff5033e92a717eade"
    "2f92114f506aff8327a2fd445a7971cb7acbf948bdbb8dfc9b0c2d26451004ab0f7ef742d7ab41a4aee8bb6147c2"
    "f74efb43e961157755b6f94d3aacb595733d4a30a6c9b290a930";
static const char dsaY[] =
    "98f63ce54659626e49fb4205aa9d51890bafef71a39af1a0bbf16fffa5ec9ed47662f492d7e6ed93db44ebfa9209"
    "7e9cc8fa5a00e5c07642f2554986a16057d707767e295601c74a37b86b12da05daa0c4f7245c20e010ef3abd34bc"
    "0cbd3115aec6a12540133fec2d7097c78757e1bda306a8d7c3581d34718380cbc1c02a2d9fd9ac57ca5222427fc0"
    "44febc99bd97e39924ac58cc73c594dd86f2ca0f77fd0cc2c713c564821eaece8ae959bcaf4485c0ee97a48e6e23"
    "f8f47b6fdfd615a65caa4b38f3474f6977fc2e72b211053521d0ff21770374dad1759d869693cffa3488de9fde42"
    "5333e2efc05bd80f757c5d9356337484c5bbd80b4adb967a9010";

/* The DER SubjectPublicKeyInfo of the keys above around their components:
 * rsaEncryption with NULL parameters and the 0x00-prefixed 2048-bit modulus,
 * and id-ecPublicKey on prime256v1 with the uncompressed point. */
static const char rsaSpkiPrefix[] =
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100";
static const char rsaSpkiSuffix[] = "0203010001";
static const char ecSpkiPrefix[] = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

static const char *text(const xmlChar *value) {
    return value != NULL ? (const char *)value : "(null)";
}

/* The Base64 of the hex digits of `hex`, which may hold separators. */
static xmlChar *base64(const char *hex) {
    unsigned char bytes[512];
    size_t count = 0;
    int high = -1;
    const char *cursor;
    for (cursor = hex; *cursor != '\0'; ++cursor) {
        int digit;
        if (*cursor >= '0' && *cursor <= '9') {
            digit = *cursor - '0';
        } else if (*cursor >= 'a' && *cursor <= 'f') {
            digit = *cursor - 'a' + 10;
        } else if (*cursor >= 'A' && *cursor <= 'F') {
            digit = *cursor - 'A' + 10;
        } else {
            continue;
        }
        if (high < 0) {
            high = digit;
        } else {
            bytes[count++] = (unsigned char)(high * 16 + digit);
            high = -1;
        }
    }
    return xmlSecBase64Encode(bytes, count, 0);
}

/* A document whose root element is `xml`. */
static xmlDocPtr parse(const char *xml) {
    return xsReadMemory(xml, (int)strlen(xml), "key.xml", NULL, 0);
}

static void describe(const char *label, xmlSecKeyDataId id) {
    printf("%s: name=%s href=%s usage=0x%x node=%s ns=%s methods=%d%d%d%d%d%d%d%d%d%d%d\n", label,
           text(id->name), text(id->href), id->usage, text(id->dataNodeName),
           text(id->dataNodeNs),
           id->initialize != NULL, id->duplicate != NULL, id->finalize != NULL,
           id->getType != NULL, id->getSize != NULL, id->xmlRead != NULL, id->xmlWrite != NULL,
           id->binRead != NULL, id->binWrite != NULL, id->debugDump != NULL,
           id->debugXmlDump != NULL);
}

static void show_key(const char *label, xmlSecKeyPtr key) {
    xmlSecKeyDataPtr value = xmlSecKeyGetValue(key);
    if (value == NULL) {
        printf("%s: no value\n", label);
        return;
    }
    /* libxmlsec1's OpenSSL 3 library cannot tell a public key from a private
     * one and reports both; only the public bit is common to all. */
    printf("%s: klass=%s size=%d public=%d\n", label, value->id->name, (int)xmlSecKeyGetSize(key),
           (xmlSecKeyGetType(key) & xmlSecKeyDataTypePublic) != 0);
    xmlSecKeyDataDebugDump(value, stdout);
    xmlSecKeyDataDebugXmlDump(value, stdout);
}

/* Writes the value of `key` into an empty element `name` in `ns` and prints
 * the document, whose element it is. */
static void write_key(const char *label, xmlSecKeyDataId id, xmlSecKeyPtr key,
                      xmlSecKeyInfoCtxPtr ctx, const char *name, const char *ns) {
    char xml[256];
    xmlDocPtr doc;
    xmlChar *dumped = NULL;
    int size = 0;
    int ret;
    snprintf(xml, sizeof(xml), "<%s xmlns=\"%s\"/>", name, ns);
    doc = parse(xml);
    ret = xmlSecKeyDataXmlWrite(id, key, xsDocGetRootElement(doc), ctx);
    xsDocDumpMemory(doc, &dumped, &size);
    printf("%s: %d\n%.*s", label, ret, size, (const char *)dumped);
    xsFree(dumped);
    xsFreeDoc(doc);
}

/* Reads the key element `xml` with klass `id`, prints the key, refuses a
 * second value, duplicates it and writes it back. */
static void round_trip(const char *label, xmlSecKeyDataId id, const char *xml, const char *name,
                       const char *ns) {
    xmlDocPtr doc = parse(xml);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    xmlSecKeyPtr empty = xmlSecKeyCreate();
    xmlSecKeyPtr copy;

    printf("%s read: %d\n", label, xmlSecKeyDataXmlRead(id, key, xsDocGetRootElement(doc), ctx));
    show_key(label, key);
    printf("%s second value: %d\n", label,
           xmlSecKeyDataXmlRead(id, key, xsDocGetRootElement(doc), ctx));
    copy = xmlSecKeyDuplicate(key);
    show_key("duplicate", copy);
    xmlSecKeyDestroy(copy);

    ctx->mode = xmlSecKeyInfoModeWrite;
    ctx->keyReq.keyType = 0;
    write_key("write nothing requested", id, key, ctx, name, ns);
    ctx->keyReq.keyType = xmlSecKeyDataTypePublic;
    write_key("write public", id, key, ctx, name, ns);
    write_key("write without value", id, empty, ctx, name, ns);

    xmlSecKeyDestroy(empty);
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* Reads `xml` with klass `id` and prints only whether it was refused. */
static void refused(const char *label, xmlSecKeyDataId id, const char *xml) {
    xmlDocPtr doc = parse(xml);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    int ret;
    quiet = 1;
    ret = xmlSecKeyDataXmlRead(id, key, xsDocGetRootElement(doc), ctx);
    quiet = 0;
    printf("%s: %s, %s\n", label, ret < 0 ? "refused" : "accepted",
           xmlSecKeyGetValue(key) == NULL ? "no value" : "value");
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

/* Reads the SPKI `prefix` `body` `suffix` (hex) from a DEREncodedKeyValue,
 * prints the key and writes it back as a DEREncodedKeyValue. */
static void der(const char *label, const char *prefix, const char *body, const char *suffix) {
    static char hex[2048];
    static char xml[2048];
    xmlChar *encoded;
    xmlDocPtr doc;
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();

    snprintf(hex, sizeof(hex), "%s%s%s", prefix, body, suffix);
    encoded = base64(hex);
    snprintf(xml, sizeof(xml), "<DEREncodedKeyValue xmlns=\"" DSIG11 "\">%s</DEREncodedKeyValue>",
             encoded);
    xsFree(encoded);
    doc = parse(xml);
    printf("%s read: %d\n", label,
           xmlSecKeyDataXmlRead(xmlSecKeyDataDEREncodedKeyValueId, key, xsDocGetRootElement(doc),
                                ctx));
    show_key(label, key);
    ctx->mode = xmlSecKeyInfoModeWrite;
    write_key("der write", xmlSecKeyDataDEREncodedKeyValueId, key, ctx, "DEREncodedKeyValue",
              DSIG11);
    xmlSecKeyDestroy(key);
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
}

int main(void) {
    static char xml[8192];
    xmlChar *parts[4];
    int i;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    describe("rsa", xmlSecKeyDataRsaId);
    describe("dsa", xmlSecKeyDataDsaId);
    describe("ec", xmlSecKeyDataEcId);

    parts[0] = base64(rsaModulus);
    parts[1] = base64(rsaExponent);
    snprintf(xml, sizeof(xml),
             "<RSAKeyValue xmlns=\"" DSIG "\"><Modulus>%s</Modulus><Exponent>%s</Exponent>"
             "</RSAKeyValue>",
             parts[0], parts[1]);
    round_trip("rsa", xmlSecKeyDataRsaId, xml, "RSAKeyValue", DSIG);
    snprintf(xml, sizeof(xml),
             "<RSAKeyValue xmlns=\"" DSIG "\"><Modulus>%s</Modulus></RSAKeyValue>", parts[0]);
    refused("rsa without exponent", xmlSecKeyDataRsaId, xml);
    xsFree(parts[0]);
    xsFree(parts[1]);

    parts[0] = base64(ecPoint);
    snprintf(xml, sizeof(xml),
             "<ECKeyValue xmlns=\"" DSIG11 "\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/>"
             "<PublicKey>%s</PublicKey></ECKeyValue>",
             parts[0]);
    round_trip("ec", xmlSecKeyDataEcId, xml, "ECKeyValue", DSIG11);
    snprintf(xml, sizeof(xml),
             "<ECKeyValue xmlns=\"" DSIG11 "\"><NamedCurve URI=\"urn:oid:1.2.3.4\"/>"
             "<PublicKey>%s</PublicKey></ECKeyValue>",
             parts[0]);
    refused("ec on an unknown curve", xmlSecKeyDataEcId, xml);
    xsFree(parts[0]);

    parts[0] = base64(dsaP);
    parts[1] = base64(dsaQ);
    parts[2] = base64(dsaG);
    parts[3] = base64(dsaY);
    snprintf(xml, sizeof(xml),
             "<DSAKeyValue xmlns=\"" DSIG "\"><P>%s</P><Q>%s</Q><G>%s</G><Y>%s</Y></DSAKeyValue>",
             parts[0], parts[1], parts[2], parts[3]);
    round_trip("dsa", xmlSecKeyDataDsaId, xml, "DSAKeyValue", DSIG);
    for (i = 0; i < 4; ++i) {
        xsFree(parts[i]);
    }

    describe("der", xmlSecKeyDataDEREncodedKeyValueId);
    der("der rsa", rsaSpkiPrefix, rsaModulus, rsaSpkiSuffix);
    der("der ec", ecSpkiPrefix, ecPoint, "");
    refused("der empty", xmlSecKeyDataDEREncodedKeyValueId,
            "<DEREncodedKeyValue xmlns=\"" DSIG11 "\"/>");
    refused("der garbage", xmlSecKeyDataDEREncodedKeyValueId,
            "<DEREncodedKeyValue xmlns=\"" DSIG11 "\">AAECAw==</DEREncodedKeyValue>");
    refused("der with a child", xmlSecKeyDataDEREncodedKeyValueId,
            "<DEREncodedKeyValue xmlns=\"" DSIG11 "\"><x/></DEREncodedKeyValue>");

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
