/* xml-sec operations on a caller's libxml2 document, in place.
 *
 * The library exports the clean C API of xml_sec.h together with the entry
 * point below. A document handle created from an xmlDocPtr is used with the
 * ordinary operations (xs_sign, xs_verify, xs_encrypt, xs_decrypt): each one
 * reads the tree as it is when it starts and changes the tree itself.
 *
 * Pointer contract:
 * - `doc` stays valid until the handle is destroyed; destroying the handle
 *   leaves `doc` to the caller.
 * - While a call on the handle runs, nothing else uses or changes `doc`.
 *   Between calls the caller may change the tree freely.
 * - Nodes an operation does not touch keep their pointers. Nodes it creates
 *   belong to `doc` and are freed with it. Nodes it removes (the element or
 *   content an encryption or decryption replaces, the template children a
 *   signature fills) are freed before the call returns, so the caller's
 *   pointers into them end with the call.
 * - A failed call leaves the tree as it was.
 * - The tree has no serialization of the library's: xs_document_serialize
 *   refuses the handle; the caller serializes `doc` with libxml2.
 *
 * The compiled policies of the clean C API admit no internal DTD, so a
 * document with one is refused when the handle is created. */

#ifndef XML_SEC_LIBXML2_H
#define XML_SEC_LIBXML2_H

#include <libxml/tree.h>

#include "xml_sec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Create a document handle over `doc`, read under the compiled policy of
 * `operation` (XS_OPERATION_*) in `policy`. Returns XS_INVALID_ARGUMENT for
 * a null pointer or a node that is not a document, and XS_INTERNAL when the
 * process has no libxml2 loaded or one outside the supported releases (2.9 to
 * 2.x). The library does not link libxml2; it uses the program's, found by
 * symbol name in the process. That needs a Unix-like target and libxml2's
 * symbols in the global scope (a shared libxml2, or a static one that exports
 * them); on other targets the call always returns XS_INTERNAL. */
xs_status xs_libxml2_document(XsPolicy policy, uint32_t operation, xmlDocPtr doc,
                              XsDocument *out, XsError *error);

#ifdef __cplusplus
}
#endif

#endif
