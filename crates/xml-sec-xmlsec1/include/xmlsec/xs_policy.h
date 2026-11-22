/*
 * Policy functions this library offers beyond libxmlsec1's interface.
 */
#ifndef __XS_POLICY_H__
#define __XS_POLICY_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Narrows the policy every operation of the library runs under by the profile
 * named profile of the xml-sec policy configuration (TOML, schema version 1)
 * in the dataSize bytes at data: each layer of the profile can remove
 * algorithms, digests, key sources and URI classes and lower limits, never
 * add them. The profile's inheritance root must have base XmlSecCompatible:
 * another base reads documents differently (ID lookup, here(), key names),
 * which narrowing cannot express, and is refused. The library starts from its
 * libxmlsec1-compatible policy;
 * each call narrows what earlier calls left, and the enabled transforms and
 * key data of a context narrow further on top. Every operation's policy is
 * replaced at once, so an operation never runs under a mix; operations already
 * running keep the policy they started with. The library reads no
 * configuration file of its own.
 *
 * Returns 0 on success or a negative value after an error report, leaving the
 * policy unchanged.
 */
XMLSEC_EXPORT int xsPolicyRestrict(const xmlSecByte* data,
                                   xmlSecSize dataSize,
                                   const char* profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XS_POLICY_H__ */
