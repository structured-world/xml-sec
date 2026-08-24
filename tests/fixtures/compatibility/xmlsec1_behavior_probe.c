#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <xmlsec/crypto.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>

static int callback_count = 0;
static int abort_callback = 0;

static int reference_pre_execute(xmlSecTransformCtxPtr transform_ctx) {
    if(transform_ctx == NULL) {
        return(-1);
    }
    callback_count += 1;
    return(abort_callback ? -1 : 0);
}

static xmlDocPtr load_document(const char* path) {
    return(xmlReadFile(path, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET));
}

static int node_has_non_whitespace_content(xmlNodePtr node) {
    xmlChar* content = xmlNodeGetContent(node);
    int has_content = 0;
    xmlChar* current = content;
    while((current != NULL) && ((*current) != '\0')) {
        if((*current != 0x20) && (*current != 0x09) &&
           (*current != 0x0A) && (*current != 0x0D)) {
            has_content = 1;
            break;
        }
        current += 1;
    }
    if(content != NULL) {
        xmlFree(content);
    }
    return(has_content);
}

static xmlSecDSigCtxPtr verification_context(const char* key_path) {
    xmlSecDSigCtxPtr context = xmlSecDSigCtxCreate(NULL);
    if(context == NULL) {
        return(NULL);
    }
    context->signKey = xmlSecCryptoAppKeyLoadEx(
        key_path,
        xmlSecKeyDataTypePublic,
        xmlSecKeyDataFormatPem,
        NULL,
        NULL,
        NULL
    );
    if(context->signKey == NULL) {
        xmlSecDSigCtxDestroy(context);
        return(NULL);
    }
    context->referencePreExecuteCallback = reference_pre_execute;
    return(context);
}

static int verify_case(const char* document_path, const char* key_path, int mutate, int abort) {
    xmlDocPtr document = load_document(document_path);
    xmlNodePtr signature;
    xmlSecDSigCtxPtr context;
    int result;
    if(document == NULL) {
        return(-1);
    }
    signature = xmlSecFindNode(xmlDocGetRootElement(document), xmlSecNodeSignature, xmlSecDSigNs);
    if(signature == NULL) {
        xmlFreeDoc(document);
        return(-1);
    }
    if(mutate) {
        xmlNodePtr object = xmlSecFindNode(signature, xmlSecNodeObject, xmlSecDSigNs);
        if(object == NULL) {
            xmlFreeDoc(document);
            return(-1);
        }
        xmlNodeSetContent(object, BAD_CAST "tampered");
    }
    context = verification_context(key_path);
    if(context == NULL) {
        xmlFreeDoc(document);
        return(-1);
    }
    callback_count = 0;
    abort_callback = abort;
    result = xmlSecDSigCtxVerify(context, signature);
    printf(
        "%s=%d,%s,%s,%d\n",
        abort ? "abort" : (mutate ? "invalid" : "valid"),
        result,
        xmlSecDSigCtxGetStatusString(context->status),
        xmlSecDSigCtxGetFailureReasonString(context->failureReason),
        callback_count
    );
    xmlSecDSigCtxDestroy(context);
    xmlFreeDoc(document);
    return(0);
}

static int sign_case(const char* template_path, const char* key_path) {
    xmlDocPtr document = load_document(template_path);
    xmlNodePtr signature;
    xmlNodePtr digest_value;
    xmlNodePtr signature_value;
    xmlSecDSigCtxPtr context;
    int empty_before;
    int populated_after;
    int result;
    if(document == NULL) {
        return(-1);
    }
    signature = xmlSecFindNode(xmlDocGetRootElement(document), xmlSecNodeSignature, xmlSecDSigNs);
    if(signature == NULL) {
        xmlFreeDoc(document);
        return(-1);
    }
    digest_value = xmlSecFindNode(signature, xmlSecNodeDigestValue, xmlSecDSigNs);
    signature_value = xmlSecFindNode(signature, xmlSecNodeSignatureValue, xmlSecDSigNs);
    if((digest_value == NULL) || (signature_value == NULL)) {
        xmlFreeDoc(document);
        return(-1);
    }
    empty_before = !node_has_non_whitespace_content(digest_value) &&
        !node_has_non_whitespace_content(signature_value);
    context = xmlSecDSigCtxCreate(NULL);
    if(context == NULL) {
        xmlFreeDoc(document);
        return(-1);
    }
    context->signKey = xmlSecCryptoAppKeyLoadEx(
        key_path,
        xmlSecKeyDataTypePrivate,
        xmlSecKeyDataFormatPem,
        NULL,
        NULL,
        NULL
    );
    if(context->signKey == NULL) {
        xmlSecDSigCtxDestroy(context);
        xmlFreeDoc(document);
        return(-1);
    }
    result = xmlSecDSigCtxSign(context, signature);
    populated_after = node_has_non_whitespace_content(digest_value) &&
        node_has_non_whitespace_content(signature_value);
    printf("sign=%d,%d,%d\n", result, empty_before, populated_after);
    xmlSecDSigCtxDestroy(context);
    xmlFreeDoc(document);
    return(0);
}

int main(int argc, char** argv) {
    int result = 0;
    if(argc != 5) {
        return(2);
    }
    xmlInitParser();
    if(xmlSecInit() < 0) {
        return(3);
    }
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        return(4);
    }
#endif
    if((xmlSecCryptoAppInit(NULL) < 0) || (xmlSecCryptoInit() < 0)) {
        return(5);
    }
    result |= verify_case(argv[1], argv[2], 0, 0);
    result |= verify_case(argv[1], argv[2], 1, 0);
    result |= verify_case(argv[1], argv[2], 0, 1);
    result |= sign_case(argv[3], argv[4]);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
    return(result == 0 ? 0 : 1);
}
