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

/* libxmlsec1's default parser options for this libxml2: no external entities
 * or network, entities substituted, the DTD read for attribute defaults and
 * IDs, no shared dictionary, no libxml2 size ceilings. */
int xs_xmlsec1_default_parser_options(void) {
    int options = XML_PARSE_NONET | XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR |
                  XML_PARSE_NODICT | XML_PARSE_HUGE;
#if LIBXML_VERSION >= 21300
    options |= XML_PARSE_NO_XXE;
#endif
    return options;
}

void xs_xmlsec1_prepare_ctxt(xmlParserCtxtPtr ctxt, int options) {
#if LIBXML_VERSION < 21300
    /* canonicalization needs IDs, default attributes and expanded entities */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    ctxt->replaceEntities = 1;
#else
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
