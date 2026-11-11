/* xml-sec operations on a tree document, in place.
 *
 * The library exports the clean C API of xml_sec.h and the tree functions of
 * xs_tree.h together with the entry point below. A document handle created
 * from an xmlDocPtr is used with the ordinary operations (xs_sign,
 * xs_verify, xs_encrypt, xs_decrypt): each one reads the tree as it is when
 * it starts and changes the tree itself.
 *
 * Handle contract:
 * - `doc` is a tree document of xs_tree.h (xsReadMemory, xsNewDoc); a value
 *   that names nothing live is refused, never dereferenced.
 * - While a call on the handle runs, nothing else uses or changes `doc`.
 *   Between calls the caller may change the tree through the tree functions;
 *   the next operation reads it as it is then.
 * - Nodes an operation does not touch keep their handles. Nodes it creates
 *   belong to `doc`. Handles of nodes it removes (the element or content an
 *   encryption or decryption replaces) are refused afterwards.
 * - A failed call leaves the tree as it was.
 * - Destroying the handle leaves `doc` to the caller, who serializes it with
 *   xsDocDumpMemory and frees it with xsFreeDoc. */

#ifndef XML_SEC_LIBXML2_H
#define XML_SEC_LIBXML2_H

#include <xs_tree.h>

#include "xml_sec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Create a document handle over the tree document `doc`, read under the
 * compiled policy of `operation` (XS_OPERATION_*) in `policy`. Returns
 * XS_INVALID_ARGUMENT for a value that names no live document. */
xs_status xs_tree_document(XsPolicy policy, uint32_t operation, xmlDocPtr doc,
                           XsDocument *out, XsError *error);

#ifdef __cplusplus
}
#endif

#endif
