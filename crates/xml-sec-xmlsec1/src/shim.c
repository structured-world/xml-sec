/* libxml2's allocator as functions: depending on the libxml2 build,
 * xmlMalloc, xmlRealloc and xmlFree are global function pointers or macros,
 * and xmlsec1 hands its callers memory they release with xmlFree. */

#include <stddef.h>
#include <stdio.h>
#include <libxml/xmlmemory.h>

void *xs_xmlsec1_malloc(size_t size) {
    return xmlMalloc(size);
}

void *xs_xmlsec1_realloc(void *mem, size_t size) {
    return xmlRealloc(mem, size);
}

void xs_xmlsec1_free(void *mem) {
    xmlFree(mem);
}

/* Debug dumps write to the caller's C stream. */
int xs_xmlsec1_fputs(void *stream, const char *text) {
    return fputs(text, (FILE *)stream);
}
