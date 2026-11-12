/* The RSA, RSA-PSS and ECDSA signature transform klasses of the default
 * crypto library as a libxmlsec1 caller uses them to verify: their
 * identities, the key requirements, a key of the wrong family, and
 * verifying a valid signature and a tampered one through a transform
 * context. The signatures were made with the private keys of the fixtures
 * whose public keys the program reads. Built against the pinned libxmlsec1
 * with its default crypto library and against this crate, both must print
 * the same. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/base64.h>
#include <xmlsec/dl.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           msg != NULL ? msg : "(null)");
}

static const xmlSecByte input[] = "The quick brown fox jumps over the lazy dog";

/* tests/fixtures/keys/rsa/rsa-2048-pubkey.pem */
static const char rsaModulus[] =
    "DE25678435E5806896BD5D9FDB56C23F8340793930A2E5AF37D2BDE1235E574D71CEEBCF8361916FEA33174FD86D"
    "0F238FB5037AE22070BA01AC2FE348CB69EE0269EB38F7A07857F7B35956FE5205498138945B07C79FCB76A94EF4"
    "EF5A5CC94213B85955C1443AA60347461CF451B8C07A975DB9C32F9604C5B13BA073528A1EF66D0EA505E32A8909"
    "285725F5977886DDC4A975BC72E1E08B2AED6335D370EEB75BDF89E9D14E8B50D362128C90AE778CCB0CA1D96578"
    "451DA941E04DBC4AD1305260C6B6B01D6B19F715ABE41A9CE96C4475C05E264CFC113AB8FAA516AFA0E68B1265B1"
    "DF1F6A82FF41BFC0A2A55B3231D183E341206AFCC6EBA2874A2D";

/* tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem */
static const char ecPoint[] =
    "04fe130d43176a7acfb3442623c6c62b497bc779a1342b75d6796fdfee85eae5a94998ed66e3c79dbf8e0b0042"
    "70f1ca78ad63db8ada1d783c225e57c33c7660dc";

/* RSA PKCS#1 v1.5 with SHA-256 over `input` by rsa-2048-key.pem */
static const char rsaSha256[] =
    "b26de1f0706baf5c588d2f46c46b0e46649ea9eb7edd669077694db8e476bb813912cae7a318b0808e2c930a769a"
    "4118f2be13211ee28837a0789559e8a70ff2805a94061fa4b0c8a260e09b6bfaa75feb29d8145e1b51c32fec570c"
    "29093b481af95e5e100710730bc03368111c3bc7e9f486888d0efd84fd6311525c80690527b8e6f75844659a32f7"
    "6145b6b6fcea4c458a3512aba04d37a3e5c0a334c22ed4c4f6b9ec65f597537e7e9c557fce19c348f4e2c9313581"
    "fbbcc8da997fb9f90aed6a1065670c15d4fa4331e6872f0d797bd4a6b74d859428ae70873636336c96ae6a7999b9"
    "df6fb7a19ca674ca5958d59f78ed8247c07711e99747e60a7f28";

/* RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt by the same key */
static const char rsaPssSha256[] =
    "55f1abc75c214e3f3b80a69ae82f6aea50c9b2bed29bde1fa169b9bbe5d085f01f0d5738f8655ddd914a4ce8c506"
    "ff3a166669b5ad231d9494673b54761c1385a1d081b49e204f27077d8a414979a967cc5f8194682c1e1467bbe961"
    "d76b8f7b517a1078d66fe4df049bde980abb130515a1cf27baf986422a30245e40271864630ac3469c6c42e8a92a"
    "b95fd6fff26152cbe9a74433460c9c2b3ce9f277bf3ebebc486a57392b0b46074453b7c562144c17552431cde953"
    "31d7a0b1912018d6de151b690c7dcbdd18f6eedc555c42ed21bc1b2a1d3050f9902b5b5d2f2604f2f751b31f5f91"
    "5fd29ba448efb45f4c7ace71b3e6c6446edfb93334f0c0a807f2";

/* ECDSA with SHA-256 by ec-prime256v1-key.pem, as XMLDSig's r || s */
static const char ecdsaSha256[] =
    "7982809FC2C645877938A246A4362D30A016A43B45B966639A03A3A2EE2EEF69"
    "6BA50A3EAF0EDC6B3EF8FF77F052E855AB0B4497CFA242D10B0DC762BD087F2D";

/* The bytes of the hex digits of `hex`; returns their number. */
static xmlSecSize unhex(const char *hex, xmlSecByte *out) {
    xmlSecSize count = 0;
    int high = -1;
    for (; *hex != '\0'; ++hex) {
        int digit;
        if (*hex >= '0' && *hex <= '9') {
            digit = *hex - '0';
        } else if (*hex >= 'a' && *hex <= 'f') {
            digit = *hex - 'a' + 10;
        } else if (*hex >= 'A' && *hex <= 'F') {
            digit = *hex - 'A' + 10;
        } else {
            continue;
        }
        if (high < 0) {
            high = digit;
        } else {
            out[count++] = (xmlSecByte)(high * 16 + digit);
            high = -1;
        }
    }
    return count;
}

static xmlChar *base64(const char *hex) {
    xmlSecByte bytes[512];
    return xmlSecBase64Encode(bytes, unhex(hex, bytes), 0);
}

/* A key read by `id` from the KeyValue element `xml`. */
static xmlSecKeyPtr read_key(xmlSecKeyDataId id, const char *xml) {
    xmlDocPtr doc = xsReadMemory(xml, (int)strlen(xml), "key.xml", NULL, 0);
    xmlSecKeyInfoCtxPtr ctx = xmlSecKeyInfoCtxCreate(NULL);
    xmlSecKeyPtr key = xmlSecKeyCreate();
    printf("read %s: %d\n", id->name, xmlSecKeyDataXmlRead(id, key, xsDocGetRootElement(doc), ctx));
    xmlSecKeyInfoCtxDestroy(ctx);
    xsFreeDoc(doc);
    return key;
}

/* Verifies the signature `hex`, tampered in its first byte when asked. */
static void verify(xmlSecTransformId id, xmlSecKeyPtr key, const char *hex, int tamper) {
    xmlSecByte value[512];
    xmlSecSize size = unhex(hex, value);
    int ret;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
    transform->operation = xmlSecTransformOperationVerify;
    printf("  set key: %d\n", xmlSecTransformSetKey(transform, key));
    /* C leaves the order of argument evaluation unspecified, so a call and
     * the status it sets are never printed in one statement. */
    ret = xmlSecTransformCtxBinaryExecute(ctx, input, sizeof(input) - 1);
    printf("  execute: %d status=%d\n", ret, transform->status);
    if (tamper) {
        value[0] ^= 0x01;
    }
    ret = xmlSecTransformVerify(transform, value, size, ctx);
    printf("  verify%s: %d status=%d\n", tamper ? " tampered" : "", ret, transform->status);
    xmlSecTransformCtxDestroy(ctx);
}

static void check(xmlSecTransformId id, xmlSecKeyPtr key, xmlSecKeyPtr other, const char *hex) {
    xmlSecKeyReq req;
    xmlSecTransformCtxPtr ctx = xmlSecTransformCtxCreate();
    xmlSecTransformPtr transform = xmlSecTransformCtxCreateAndAppend(ctx, id);

    printf("%s: href=%s usage=0x%x methods=%d%d%d%d%d\n", id->name, id->href, id->usage,
           id->setKeyReq != NULL, id->setKey != NULL, id->verify != NULL, id->pushBin != NULL,
           id->execute != NULL);
    xmlSecKeyReqInitialize(&req);
    transform->operation = xmlSecTransformOperationSign;
    printf("  sign req: %d", xmlSecTransformSetKeyReq(transform, &req));
    printf(" klass=%s type=0x%x usage=0x%x\n", req.keyId->name, req.keyType, req.keyUsage);
    transform->operation = xmlSecTransformOperationVerify;
    printf("  verify req: %d", xmlSecTransformSetKeyReq(transform, &req));
    printf(" type=0x%x usage=0x%x\n", req.keyType, req.keyUsage);
    xmlSecKeyReqFinalize(&req);
    printf("  wrong family: %d\n", xmlSecTransformSetKey(transform, other));
    xmlSecTransformCtxDestroy(ctx);

    verify(id, key, hex, 0);
    verify(id, key, hex, 1);
}

int main(void) {
    static char xml[2048];
    xmlChar *encoded;
    xmlSecKeyPtr rsa;
    xmlSecKeyPtr ec;

    xmlSecErrorsSetCallback(record);
    if (xmlSecInit() < 0 || xmlSecCryptoDLLoadLibrary(xmlSecGetDefaultCrypto()) < 0) {
        printf("no default crypto library\n");
        return 1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        printf("crypto init failed\n");
        return 1;
    }

    encoded = base64(rsaModulus);
    snprintf(xml, sizeof(xml),
             "<RSAKeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Modulus>%s</Modulus>"
             "<Exponent>AQAB</Exponent></RSAKeyValue>",
             encoded);
    xsFree(encoded);
    rsa = read_key(xmlSecKeyDataRsaId, xml);
    encoded = base64(ecPoint);
    snprintf(xml, sizeof(xml),
             "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\">"
             "<NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>%s</PublicKey>"
             "</ECKeyValue>",
             encoded);
    xsFree(encoded);
    ec = read_key(xmlSecKeyDataEcId, xml);

    check(xmlSecTransformRsaSha256Id, rsa, ec, rsaSha256);
    check(xmlSecTransformRsaPssSha256Id, rsa, ec, rsaPssSha256);
    check(xmlSecTransformEcdsaSha256Id, ec, rsa, ecdsaSha256);

    xmlSecKeyDestroy(rsa);
    xmlSecKeyDestroy(ec);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    return 0;
}
