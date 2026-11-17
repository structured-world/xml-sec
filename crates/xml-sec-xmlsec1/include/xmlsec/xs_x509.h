/*
 * X.509 functions this library offers beyond libxmlsec1's interface.
 */
#ifndef __XS_X509_H__
#define __XS_X509_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keysmngr.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Gives the X.509 store of the keys manager the UTC history CRLs are checked
 * with: the dataSize bytes at data in the published leap-seconds.list format
 * (NTP seconds and TAI-UTC offsets, with one "#@" expiration line). A later
 * call replaces the list. libxmlsec1 checks CRLs against the system clock;
 * this library reads no clock or file of its own, so without a list a CRL
 * that applies to a certificate path refuses that path.
 *
 * Returns 0 on success or a negative value after an error report.
 */
XMLSEC_EXPORT int xsKeysMngrUtcFactsLoadMemory(xmlSecKeysMngrPtr mngr,
                                               const xmlSecByte* data,
                                               xmlSecSize dataSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XS_X509_H__ */
