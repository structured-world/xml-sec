/* libxml2's allocator as functions: depending on the libxml2 build,
 * xmlMalloc, xmlRealloc and xmlFree are global function pointers or macros,
 * and xmlsec1 hands its callers memory they release with xmlFree. The parser
 * context helpers follow. */

#include <stddef.h>
#include <stdio.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

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

/* The parser context is libxml2's own structure, laid out and named per
 * version; these read and set it with the headers of the linked libxml2. */

/* The default parser options: no network, no external entity or external
 * DTD, no shared dictionary, no libxml2 size ceilings. From libxml2 2.13 these
 * are libxmlsec1's options: XML_PARSE_NO_XXE keeps internal entity
 * substitution and DTD attribute defaults inside the document. Older
 * libxml2 has no such switch, and the same entity and DTD options would read
 * local files an untrusted document names, so they stay off there; internal
 * entity references then remain reference nodes. */
int xs_xmlsec1_default_parser_options(void) {
#if LIBXML_VERSION >= 21300
    return XML_PARSE_NO_XXE | XML_PARSE_NONET | XML_PARSE_NOENT | XML_PARSE_DTDLOAD |
           XML_PARSE_DTDATTR | XML_PARSE_NODICT | XML_PARSE_HUGE;
#else
    return XML_PARSE_NONET | XML_PARSE_NODICT | XML_PARSE_HUGE;
#endif
}

/* Applies `options` and nothing else: libxmlsec1 additionally forces entity
 * substitution and external-subset loading on libxml2 older than 2.13,
 * which loads external entities whatever the options say. */
void xs_xmlsec1_prepare_ctxt(xmlParserCtxtPtr ctxt, int options) {
#if LIBXML_VERSION >= 21300
    xmlCtxtSetOptions(ctxt, options);
#endif
    xmlCtxtUseOptions(ctxt, options);
}

/* The parsed document, which the context no longer owns. */
xmlDocPtr xs_xmlsec1_take_doc(xmlParserCtxtPtr ctxt) {
    xmlDocPtr doc = ctxt->myDoc;
    ctxt->myDoc = NULL;
    return doc;
}

int xs_xmlsec1_well_formed(xmlParserCtxtPtr ctxt) {
    return ctxt->wellFormed;
}

/* Relative references resolve against the file's directory. */
int xs_xmlsec1_set_directory(xmlParserCtxtPtr ctxt, const char *filename) {
    if (ctxt->directory == NULL) {
        ctxt->directory = xmlParserGetDirectory(filename);
        if (ctxt->directory == NULL) {
            return -1;
        }
    }
    return 0;
}

int xs_xmlsec1_push_input(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
#if LIBXML_VERSION < 21500
    return inputPush(ctxt, input);
#else
    return xmlCtxtPushInput(ctxt, input);
#endif
}

/* Frees the context and any document it still owns. */
void xs_xmlsec1_free_ctxt(xmlParserCtxtPtr ctxt) {
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }
    xmlFreeParserCtxt(ctxt);
}
