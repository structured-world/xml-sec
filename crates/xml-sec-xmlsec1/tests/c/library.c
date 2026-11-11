/* Library state and the crypto function table as a libxmlsec1 caller sees
 * them. The program is built against the pinned libxmlsec1 and against
 * this crate, and both must print the same: the version check and
 * its reports, the layout of xmlSecCryptoDLFunctions, and dispatch through a
 * table the caller installs itself (which loads no crypto library): its
 * methods and klasses, a missing method, and the registration of its
 * klasses. */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/app.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/list.h>
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

static int inits;

static int caller_init(void) {
    ++inits;
    printf("  caller init\n");
    return 0;
}

static int caller_app_init(const char *config) {
    printf("  caller app init: %s\n", config != NULL ? config : "(null)");
    return 7;
}

/* A transform klass of the caller's: name and sizes only. */
static struct _xmlSecTransformKlass callerSha1Klass;

static xmlSecTransformId caller_sha1(void) {
    callerSha1Klass.klassSize = sizeof(xmlSecTransformKlass);
    callerSha1Klass.objSize = sizeof(xmlSecTransform);
    callerSha1Klass.name = BAD_CAST "caller-sha1";
    callerSha1Klass.href = BAD_CAST "urn:caller:sha1";
    callerSha1Klass.usage = xmlSecTransformUsageDigestMethod;
    return &callerSha1Klass;
}

int main(void) {
    struct _xmlSecCryptoDLFunctions *table;
    xmlSecSize before;
    int ret;

    xmlSecErrorsSetCallback(record);

    printf("layout: size=%d init=%d keydata=%d store=%d aes=%d sha1=%d appinit=%d pwd=%d\n",
           (int)sizeof(struct _xmlSecCryptoDLFunctions),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, cryptoInit),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, keyDataAesGetKlass),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, x509StoreGetKlass),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, transformAes128CbcGetKlass),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, transformSha1GetKlass),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, cryptoAppInit),
           (int)offsetof(struct _xmlSecCryptoDLFunctions, cryptoAppDefaultPwdCallback));

    printf("version exact: %d\n", xmlSecCheckVersionExact());
    printf("version abi: %d\n", xmlSecCheckVersion());
    printf("older subminor exact: %d\n", xmlSecCheckVersionExt(1, 3, 12, xmlSecCheckVersionExactMatch));
    printf("older subminor abi: %d\n",
           xmlSecCheckVersionExt(1, 3, 12, xmlSecCheckVersionABICompatible));
    printf("newer minor abi: %d\n", xmlSecCheckVersionExt(1, 4, 0, xmlSecCheckVersionABICompatible));
    printf("other major: %d\n", xmlSecCheckVersionExt(2, 0, 0, xmlSecCheckVersionABICompatible));
    printf("strlen: %d %d\n", (int)xmlSecStrlen(BAD_CAST "abc"), (int)xmlSecStrlen(NULL));

    printf("init: %d\n", xmlSecInit());
    printf("no table: %p\n", (void *)xmlSecCryptoDLGetFunctions());
    printf("crypto init without table: %d\n", xmlSecCryptoInit());
    printf("klass without table: %p\n", (void *)xmlSecTransformSha1GetKlass());
    printf("pwd callback without table: %p\n", xmlSecCryptoAppGetDefaultPwdCallback());
    printf("set null table: %d\n", xmlSecCryptoDLSetFunctions(NULL));

    table = calloc(1, sizeof(*table));
    table->cryptoInit = caller_init;
    table->cryptoAppInit = caller_app_init;
    table->transformSha1GetKlass = caller_sha1;
    printf("set table: %d\n", xmlSecCryptoDLSetFunctions(table));
    printf("table installed: %d\n", xmlSecCryptoDLGetFunctions() == table);
    /* The call runs before `inits` is read: argument evaluation order is
     * unspecified, so the result is taken in its own statement. */
    ret = xmlSecCryptoInit();
    printf("crypto init: %d inits=%d\n", ret, inits);
    printf("app init: %d\n", xmlSecCryptoAppInit("config"));
    printf("crypto shutdown: %d\n", xmlSecCryptoShutdown());
    printf("sha1 klass: %s\n", xmlSecTransformKlassGetName(xmlSecTransformSha1GetKlass()));
    printf("sha256 klass: %p\n", (void *)xmlSecTransformSha256GetKlass());
    printf("pwd callback: %p\n", xmlSecCryptoAppGetDefaultPwdCallback());

    before = xmlSecPtrListGetSize(xmlSecTransformIdsGet());
    printf("register: %d\n", xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(table));
    printf("registered: %d last=%s\n", (int)(xmlSecPtrListGetSize(xmlSecTransformIdsGet()) - before),
           xmlSecTransformKlassGetName((xmlSecTransformId)xmlSecPtrListGetItem(
               xmlSecTransformIdsGet(), xmlSecPtrListGetSize(xmlSecTransformIdsGet()) - 1)));
    printf("register null: %d\n", xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(NULL));

    printf("shutdown: %d\n", xmlSecShutdown());
    free(table);
    return 0;
}
