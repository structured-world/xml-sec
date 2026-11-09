/*
 * Signs, verifies, encrypts and decrypts documents libxml2 parsed, in place,
 * through the C ABI only, and checks the pointer contract a libxml2 caller
 * relies on.
 *
 * Usage: roundtrip <private key PEM> <public key PEM>
 */
#include "xml_sec_libxml2.h"

#include <libxml/parser.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,    \
                    #condition);                                                \
            failures++;                                                         \
        }                                                                       \
    } while (0)

/* Report a failed call and stop: later steps depend on its result. */
#define MUST(call)                                                              \
    do {                                                                        \
        xs_status status_ = (call);                                             \
        if (status_ != XS_OK) {                                                 \
            fprintf(stderr, "%s:%d: %s returned %d\n", __FILE__, __LINE__,      \
                    #call, (int)status_);                                       \
            exit(1);                                                            \
        }                                                                       \
    } while (0)

static XsBytes text(const char *value) {
    XsBytes bytes = {(const uint8_t *)value, strlen(value)};
    return bytes;
}

static char *read_file(const char *path, size_t *len) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *data = malloc((size_t)size + 1);
    if (data == NULL || fread(data, 1, (size_t)size, file) != (size_t)size) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(1);
    }
    fclose(file);
    data[size] = '\0';
    *len = (size_t)size;
    return data;
}

static xmlDocPtr parse(const char *xml) {
    xmlDocPtr doc = xmlReadMemory(xml, (int)strlen(xml), NULL, NULL, XML_PARSE_NONET);
    if (doc == NULL) {
        fprintf(stderr, "libxml2 could not parse a fixture\n");
        exit(1);
    }
    return doc;
}

/* The document as libxml2 serializes it, NUL-terminated; free with xmlFree. */
static char *dump(xmlDocPtr doc) {
    xmlChar *memory = NULL;
    int size = 0;
    xmlDocDumpMemory(doc, &memory, &size);
    if (memory == NULL) {
        exit(1);
    }
    return (char *)memory;
}

/* The first element named `name` under `node`, depth first. */
static xmlNodePtr element(xmlNodePtr node, const char *name) {
    for (; node != NULL; node = node->next) {
        xmlNodePtr found;
        if (node->type == XML_ELEMENT_NODE && strcmp((const char *)node->name, name) == 0) {
            return node;
        }
        found = element(node->children, name);
        if (found != NULL) {
            return found;
        }
    }
    return NULL;
}

static XsDocument handle(XsPolicy policy, uint32_t operation, xmlDocPtr doc) {
    XsDocument document = {0};
    MUST(xs_libxml2_document(policy, operation, doc, &document, NULL));
    return document;
}

static XsKeys keys_with(XsPolicy policy, uint32_t operation, const char *name, const char *pem,
                        size_t pem_len, int private_key, uint32_t usages) {
    XsKeys keys = {0};
    XsBytes pem_bytes = {(const uint8_t *)pem, pem_len};
    MUST(xs_keys_new(policy, operation, &keys, NULL));
    if (private_key) {
        MUST(xs_keys_add_private_pem(keys, text(name), pem_bytes, text(""), usages, NULL));
    } else {
        MUST(xs_keys_add_public_pem(keys, text(name), pem_bytes, usages, NULL));
    }
    return keys;
}

/* Whether the first signature of `document` is valid and its evidence accepted. */
static int verified(XsVerifier verifier, XsDocument document) {
    XsBytes ids[1];
    XsVerifyRequest request;
    XsEvidence evidence = {0};
    XsSignatureOutcome outcome;
    uint8_t accepted = 0;
    ids[0] = text("payload");
    request.expected_target_ids = ids;
    request.expected_target_count = 1;
    request.requirement = XS_REQUIRE_ALL;
    request.count = 0;
    MUST(xs_verify(verifier, document, &request, NULL, &evidence, NULL));
    MUST(xs_evidence_signature(evidence, 0, &outcome, NULL));
    MUST(xs_evidence_accepted(evidence, document, &accepted, NULL));
    CHECK(xs_evidence_destroy(evidence) == XS_OK);
    return outcome.outcome == XS_SIGNATURE_VALID && accepted == 1;
}

static const char CONFIGURATION[] =
    "schema_version = 1\n"
    "[profiles.app]\n"
    "base = 'Modern'\n";

static const char TEMPLATE[] =
    "<root><p Id=\"payload\">signed</p><other>kept</other>"
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>"
    "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
    "<ds:Reference URI=\"#payload\"><ds:Transforms>"
    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>"
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
    "<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>"
    "<ds:SignatureValue></ds:SignatureValue>"
    "<ds:KeyInfo><ds:KeyName>signer</ds:KeyName></ds:KeyInfo></ds:Signature></root>";

static const char RSA_SHA256[] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
static const char AES256_GCM[] = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

/* Runs the round trip with the RSA recipient's private and public key files;
 * exits non-zero on any failed check. */
int main(int argc, char **argv) {
    size_t private_len = 0;
    size_t public_len = 0;
    char *private_pem;
    char *public_pem;
    XsProvider provider = {0};
    XsPolicyStore store = {0};
    XsPolicy policy = {0};
    XsCompileContext context = {0, 1};

    if (argc != 3) {
        fprintf(stderr, "usage: roundtrip <private key PEM> <public key PEM>\n");
        return 2;
    }
    LIBXML_TEST_VERSION
    private_pem = read_file(argv[1], &private_len);
    public_pem = read_file(argv[2], &public_len);

    MUST(xs_provider_new_rustcrypto(&provider, NULL));
    MUST(xs_policy_store_new(text(CONFIGURATION), text("app"), provider, &context, NULL, &store,
                             NULL));
    MUST(xs_policy_store_load(store, &policy, NULL));

    /* Sign the template in the caller's tree, verify it there, then see a
     * change the caller makes between calls. */
    {
        xmlDocPtr doc = parse(TEMPLATE);
        xmlNodePtr root = xmlDocGetRootElement(doc);
        xmlNodePtr payload = element(root, "p");
        xmlNodePtr other = element(root, "other");
        xmlNodePtr signature = element(root, "Signature");
        XsKeys keys = keys_with(policy, XS_OPERATION_SIGN, "signer", private_pem, private_len, 1,
                                XS_KEY_USAGE_SIGN);
        XsKeys verify_keys = keys_with(policy, XS_OPERATION_VERIFY, "signer", public_pem,
                                       public_len, 0, XS_KEY_USAGE_VERIFY);
        XsSigner signer = {0};
        XsVerifier verifier = {0};
        XsDocument document = handle(policy, XS_OPERATION_SIGN, doc);
        XsBuffer buffer = {0};
        char *signed_xml;

        MUST(xs_signer_new(policy, provider, keys, text("signer"), text(RSA_SHA256), &signer,
                           NULL));
        MUST(xs_sign(signer, document, NULL, NULL));
        /* The tree is the caller's to serialize. */
        CHECK(xs_document_serialize(document, &buffer, NULL) == XS_DOCUMENT);
        CHECK(xs_document_destroy(document) == XS_OK);

        CHECK(xmlDocGetRootElement(doc) == root);
        CHECK(element(root, "p") == payload);
        CHECK(element(root, "other") == other);
        CHECK(element(root, "Signature") == signature);
        signed_xml = dump(doc);
        CHECK(strstr(signed_xml, "<ds:SignatureValue></ds:SignatureValue>") == NULL);
        CHECK(strstr(signed_xml, "<ds:DigestValue></ds:DigestValue>") == NULL);

        MUST(xs_verifier_new(policy, provider, verify_keys, &verifier, NULL));
        document = handle(policy, XS_OPERATION_VERIFY, doc);
        CHECK(verified(verifier, document));
        /* The same bytes, parsed again by libxml2, verify as a new tree. */
        {
            xmlDocPtr reparsed = parse(signed_xml);
            XsDocument copy = handle(policy, XS_OPERATION_VERIFY, reparsed);
            CHECK(verified(verifier, copy));
            CHECK(xs_document_destroy(copy) == XS_OK);
            xmlFreeDoc(reparsed);
        }
        xmlNodeSetContent(payload, BAD_CAST "Signed");
        CHECK(!verified(verifier, document));
        CHECK(xs_document_destroy(document) == XS_OK);

        xmlFree(signed_xml);
        CHECK(xs_verifier_destroy(verifier) == XS_OK);
        CHECK(xs_signer_destroy(signer) == XS_OK);
        CHECK(xs_keys_destroy(verify_keys) == XS_OK);
        CHECK(xs_keys_destroy(keys) == XS_OK);
        xmlFreeDoc(doc);
    }

    /* Encrypt an element in the caller's tree and recover it there. */
    {
        xmlDocPtr doc = parse("<root><secret Id=\"s\">42<inner a=\"1\"/></secret>"
                              "<public>kept</public></root>");
        xmlNodePtr root = xmlDocGetRootElement(doc);
        xmlNodePtr public_element = element(root, "public");
        XsKeys encrypt_keys = keys_with(policy, XS_OPERATION_ENCRYPT, "recipient", public_pem,
                                        public_len, 0, XS_KEY_USAGE_ENCRYPT);
        XsKeys decrypt_keys = keys_with(policy, XS_OPERATION_DECRYPT, "recipient", private_pem,
                                        private_len, 1, XS_KEY_USAGE_DECRYPT);
        XsEncryptor encryptor = {0};
        XsDecryptor decryptor = {0};
        XsDocument document = handle(policy, XS_OPERATION_ENCRYPT, doc);
        char *xml;

        MUST(xs_encryptor_new(policy, provider, encrypt_keys, text("recipient"), text(AES256_GCM),
                              &encryptor, NULL));
        MUST(xs_encrypt(encryptor, document, text("s"), NULL, NULL));
        CHECK(xs_document_destroy(document) == XS_OK);
        xml = dump(doc);
        CHECK(strstr(xml, "EncryptedData") != NULL);
        CHECK(strstr(xml, ">42<") == NULL);
        xmlFree(xml);
        CHECK(element(root, "secret") == NULL);
        CHECK(element(root, "public") == public_element);

        MUST(xs_decryptor_new(policy, provider, decrypt_keys, text("recipient"), &decryptor,
                              NULL));
        document = handle(policy, XS_OPERATION_DECRYPT, doc);
        MUST(xs_decrypt(decryptor, document, text(""), NULL, NULL, NULL));
        CHECK(xs_document_destroy(document) == XS_OK);
        xml = dump(doc);
        CHECK(strstr(xml, "<secret Id=\"s\">42<inner a=\"1\"/></secret>") != NULL);
        CHECK(strstr(xml, "EncryptedData") == NULL);
        xmlFree(xml);
        CHECK(element(root, "public") == public_element);

        CHECK(xs_encryptor_destroy(encryptor) == XS_OK);
        CHECK(xs_decryptor_destroy(decryptor) == XS_OK);
        CHECK(xs_keys_destroy(encrypt_keys) == XS_OK);
        CHECK(xs_keys_destroy(decrypt_keys) == XS_OK);
        xmlFreeDoc(doc);
    }

    /* A null pointer or a node that is not a document is refused. */
    {
        xmlDocPtr doc = parse("<root/>");
        XsDocument unused = {0};
        CHECK(xs_libxml2_document(policy, XS_OPERATION_VERIFY, NULL, &unused, NULL) ==
              XS_INVALID_ARGUMENT);
        CHECK(xs_libxml2_document(policy, XS_OPERATION_VERIFY,
                                  (xmlDocPtr)xmlDocGetRootElement(doc), &unused, NULL) ==
              XS_INVALID_ARGUMENT);
        CHECK(unused.value == 0);
        xmlFreeDoc(doc);
    }

    CHECK(xs_policy_destroy(policy) == XS_OK);
    CHECK(xs_policy_store_destroy(store) == XS_OK);
    CHECK(xs_provider_destroy(provider) == XS_OK);
    free(private_pem);
    free(public_pem);
    xmlCleanupParser();

    if (failures != 0) {
        fprintf(stderr, "%d checks failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
