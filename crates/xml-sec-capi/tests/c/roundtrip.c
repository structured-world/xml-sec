/*
 * Signs, verifies, encrypts and decrypts through the C ABI only, then checks
 * the handle and error contracts a C caller relies on.
 *
 * Usage: roundtrip <private key PEM> <public key PEM>
 */
#include "xml_sec.h"

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

static int equals(XsBytes bytes, const char *expected) {
    return bytes.len == strlen(expected) && memcmp(bytes.ptr, expected, bytes.len) == 0;
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

/* Copy a library buffer into a NUL-terminated string and release the buffer. */
static char *take_string(XsBuffer buffer) {
    char *copy = malloc(buffer.len + 1);
    if (copy == NULL) {
        exit(1);
    }
    memcpy(copy, buffer.ptr, buffer.len);
    copy[buffer.len] = '\0';
    xs_buffer_free(buffer);
    return copy;
}

static char *serialize(XsDocument document) {
    XsBuffer buffer = {0};
    MUST(xs_document_serialize(document, &buffer, NULL));
    return take_string(buffer);
}

static XsDocument parse(XsPolicy policy, uint32_t operation, const char *xml) {
    XsDocument document = {0};
    MUST(xs_document_parse(policy, operation, text(xml), &document, NULL));
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

static const char CONFIGURATION[] =
    "schema_version = 1\n"
    "[profiles.app]\n"
    "base = 'Modern'\n";

static const char TEMPLATE[] =
    "<root><p Id=\"payload\">signed</p>"
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

/* Verify `document` requiring the `payload` element; returns the evidence. */
static XsEvidence verify(XsVerifier verifier, XsDocument document) {
    XsBytes ids[1];
    XsVerifyRequest request;
    XsEvidence evidence = {0};
    ids[0] = text("payload");
    request.expected_target_ids = ids;
    request.expected_target_count = 1;
    request.requirement = XS_REQUIRE_ALL;
    request.count = 0;
    MUST(xs_verify(verifier, document, &request, &evidence, NULL));
    return evidence;
}

static void check_identity(XsPolicyIdentity identity, uint64_t revision) {
    CHECK(identity.present == 1);
    CHECK(identity.schema_version == 1);
    CHECK(identity.revision == revision);
    CHECK(equals(identity.profile, "app"));
}

int main(int argc, char **argv) {
    size_t private_len = 0;
    size_t public_len = 0;
    char *private_pem;
    char *public_pem;
    XsProvider provider = {0};
    XsPolicyStore store = {0};
    XsPolicy policy = {0};
    XsCompileContext context = {0, 1};
    XsPolicyIdentity identity;

    if (argc != 3) {
        fprintf(stderr, "usage: roundtrip <private key PEM> <public key PEM>\n");
        return 2;
    }
    private_pem = read_file(argv[1], &private_len);
    public_pem = read_file(argv[2], &public_len);

    CHECK(xs_abi_version() == XS_ABI_VERSION);
    MUST(xs_provider_new_rustcrypto(&provider, NULL));
    MUST(xs_policy_store_new(text(CONFIGURATION), text("app"), provider, &context, NULL, &store,
                             NULL));
    MUST(xs_policy_store_load(store, &policy, NULL));
    MUST(xs_policy_identity(policy, &identity, NULL));
    check_identity(identity, 1);

    /* Sign a template and inspect what the policy decided. */
    {
        XsKeys keys =
            keys_with(policy, XS_OPERATION_SIGN, "signer", private_pem, private_len, 1,
                      XS_KEY_USAGE_SIGN);
        XsSigner signer = {0};
        XsDocument document = parse(policy, XS_OPERATION_SIGN, TEMPLATE);
        XsAudit audit = {0};
        XsDecision decision;
        size_t count = 0;
        size_t index;
        int signature_method_seen = 0;
        char *signed_xml;

        MUST(xs_signer_new(policy, provider, keys, text("signer"), text(RSA_SHA256), &signer,
                           NULL));
        MUST(xs_sign(signer, document, &audit, NULL));
        MUST(xs_audit_policy_identity(audit, &identity, NULL));
        check_identity(identity, 1);
        MUST(xs_audit_decision_count(audit, &count, NULL));
        CHECK(count > 0);
        for (index = 0; index < count; index++) {
            MUST(xs_audit_decision(audit, index, &decision, NULL));
            if (decision.kind == XS_DECISION_ALGORITHM &&
                decision.role == XS_ALGORITHM_ROLE_SIGNATURE && equals(decision.text, RSA_SHA256)) {
                signature_method_seen = 1;
            }
        }
        CHECK(signature_method_seen);
        CHECK(xs_audit_decision(audit, count, &decision, NULL) == XS_INVALID_ARGUMENT);

        signed_xml = serialize(document);
        CHECK(strstr(signed_xml, "<ds:SignatureValue></ds:SignatureValue>") == NULL);

        CHECK(xs_audit_destroy(audit) == XS_OK);
        CHECK(xs_document_destroy(document) == XS_OK);
        CHECK(xs_signer_destroy(signer) == XS_OK);
        CHECK(xs_keys_destroy(keys) == XS_OK);

        /* Verify the signed bytes, then a tampered copy. */
        {
            XsKeys verify_keys = keys_with(policy, XS_OPERATION_VERIFY, "signer", public_pem,
                                           public_len, 0, XS_KEY_USAGE_VERIFY);
            XsVerifier verifier = {0};
            XsDocument received = parse(policy, XS_OPERATION_VERIFY, signed_xml);
            XsEvidence evidence;
            XsSignatureOutcome outcome;
            uint8_t accepted = 0;
            size_t signatures = 0;
            char *tampered;

            MUST(xs_verifier_new(policy, provider, verify_keys, &verifier, NULL));
            evidence = verify(verifier, received);
            MUST(xs_evidence_signature_count(evidence, &signatures, NULL));
            CHECK(signatures == 1);
            MUST(xs_evidence_signature(evidence, 0, &outcome, NULL));
            CHECK(outcome.outcome == XS_SIGNATURE_VALID);
            CHECK(outcome.key_trust == XS_KEY_TRUST_CALLER_TRUSTED);
            MUST(xs_evidence_accepted(evidence, received, &accepted, NULL));
            CHECK(accepted == 1);
            MUST(xs_evidence_policy_identity(evidence, &identity, NULL));
            check_identity(identity, 1);
            CHECK(xs_evidence_destroy(evidence) == XS_OK);

            tampered = strstr(signed_xml, ">signed</p>");
            CHECK(tampered != NULL);
            if (tampered != NULL) {
                XsDocument altered;
                tampered[1] = 'S';
                altered = parse(policy, XS_OPERATION_VERIFY, signed_xml);
                evidence = verify(verifier, altered);
                MUST(xs_evidence_signature(evidence, 0, &outcome, NULL));
                CHECK(outcome.outcome != XS_SIGNATURE_VALID);
                MUST(xs_evidence_accepted(evidence, altered, &accepted, NULL));
                CHECK(accepted == 0);
                CHECK(xs_evidence_signature(evidence, 1, &outcome, NULL) == XS_INVALID_ARGUMENT);
                CHECK(xs_evidence_destroy(evidence) == XS_OK);
                CHECK(xs_document_destroy(altered) == XS_OK);
            }

            /* A handle of another type is refused, with a readable error. */
            {
                XsVerifier wrong;
                XsError error = {0};
                XsEvidence unused = {0};
                XsVerifyRequest request = {NULL, 0, XS_REQUIRE_ALL, 0};
                xs_status status;
                XsBytes message = {0};
                wrong.value = received.value;
                CHECK(xs_verify(wrong, received, &request, &unused, &error) == XS_WRONG_HANDLE);
                CHECK(error.value != 0);
                MUST(xs_error_status(error, &status));
                CHECK(status == XS_WRONG_HANDLE);
                MUST(xs_error_message(error, &message));
                CHECK(message.len > 0);
                CHECK(xs_error_destroy(error) == XS_OK);
            }

            CHECK(xs_verifier_destroy(verifier) == XS_OK);
            CHECK(xs_keys_destroy(verify_keys) == XS_OK);
            CHECK(xs_document_destroy(received) == XS_OK);
            CHECK(xs_document_destroy(received) == XS_DESTROYED_HANDLE);
        }
        free(signed_xml);
    }

    /* An algorithm outside the profile is a typed policy refusal. */
    {
        XsKeys keys = keys_with(policy, XS_OPERATION_SIGN, "signer", private_pem, private_len, 1,
                                XS_KEY_USAGE_SIGN);
        XsSigner refused = {0};
        XsError error = {0};
        uint32_t violation = 0;
        CHECK(xs_signer_new(policy, provider, keys, text("signer"),
                            text("http://www.w3.org/2000/09/xmldsig#rsa-sha1"), &refused,
                            &error) == XS_POLICY);
        CHECK(refused.value == 0);
        MUST(xs_error_policy_violation(error, &violation));
        CHECK(violation == XS_VIOLATION_ALGORITHM);
        CHECK(xs_error_destroy(error) == XS_OK);
        CHECK(xs_keys_destroy(keys) == XS_OK);
    }

    /* Encrypt an element for an RSA recipient and recover it. */
    {
        XsKeys encrypt_keys = keys_with(policy, XS_OPERATION_ENCRYPT, "recipient", public_pem,
                                        public_len, 0, XS_KEY_USAGE_ENCRYPT);
        XsKeys decrypt_keys = keys_with(policy, XS_OPERATION_DECRYPT, "recipient", private_pem,
                                        private_len, 1, XS_KEY_USAGE_DECRYPT);
        XsEncryptor encryptor = {0};
        XsDecryptor decryptor = {0};
        XsDocument document =
            parse(policy, XS_OPERATION_ENCRYPT, "<root><secret Id=\"s\">42</secret></root>");
        XsDocument received;
        XsAudit audit = {0};
        XsDecision decision;
        size_t count = 0;
        size_t index;
        int oaep_digest_seen = 0;
        int mask_generation_seen = 0;
        char *encrypted;
        char *decrypted;

        MUST(xs_encryptor_new(policy, provider, encrypt_keys, text("recipient"), text(AES256_GCM),
                              &encryptor, NULL));
        MUST(xs_encrypt(encryptor, document, text("s"), &audit, NULL));
        /* The OAEP digest and mask the policy admitted have their own roles. */
        MUST(xs_audit_decision_count(audit, &count, NULL));
        for (index = 0; index < count; index++) {
            MUST(xs_audit_decision(audit, index, &decision, NULL));
            if (decision.kind == XS_DECISION_ALGORITHM) {
                oaep_digest_seen |= decision.role == XS_ALGORITHM_ROLE_OAEP_DIGEST;
                mask_generation_seen |= decision.role == XS_ALGORITHM_ROLE_MASK_GENERATION;
            }
        }
        CHECK(oaep_digest_seen && mask_generation_seen);
        CHECK(xs_audit_destroy(audit) == XS_OK);
        encrypted = serialize(document);
        CHECK(strstr(encrypted, ">42<") == NULL);
        CHECK(strstr(encrypted, "EncryptedData") != NULL);

        received = parse(policy, XS_OPERATION_DECRYPT, encrypted);
        MUST(xs_decryptor_new(policy, provider, decrypt_keys, text("recipient"), &decryptor,
                              NULL));
        MUST(xs_decrypt(decryptor, received, text(""), NULL, NULL));
        decrypted = serialize(received);
        CHECK(strstr(decrypted, "<secret Id=\"s\">42</secret>") != NULL);

        free(encrypted);
        free(decrypted);
        CHECK(xs_document_destroy(received) == XS_OK);
        CHECK(xs_document_destroy(document) == XS_OK);
        CHECK(xs_encryptor_destroy(encryptor) == XS_OK);
        CHECK(xs_decryptor_destroy(decryptor) == XS_OK);
        CHECK(xs_keys_destroy(encrypt_keys) == XS_OK);
        CHECK(xs_keys_destroy(decrypt_keys) == XS_OK);
    }

    /* A refused replacement publishes nothing; an accepted one is revision 2,
     * and a snapshot already loaded keeps its revision. */
    {
        XsError error = {0};
        XsPolicy next = {0};
        CHECK(xs_policy_store_replace(store, text("schema_version = 1\n[profiles.app\n"),
                                      text("app"), provider, &context, NULL,
                                      &error) == XS_CONFIGURATION);
        CHECK(error.value != 0);
        CHECK(xs_error_destroy(error) == XS_OK);
        MUST(xs_policy_store_load(store, &next, NULL));
        MUST(xs_policy_identity(next, &identity, NULL));
        check_identity(identity, 1);
        CHECK(xs_policy_destroy(next) == XS_OK);

        MUST(xs_policy_store_replace(store, text(CONFIGURATION), text("app"), provider, &context,
                                     NULL, &error));
        CHECK(error.value == 0);
        MUST(xs_policy_store_load(store, &next, NULL));
        MUST(xs_policy_identity(next, &identity, NULL));
        check_identity(identity, 2);
        MUST(xs_policy_identity(policy, &identity, NULL));
        check_identity(identity, 1);
        CHECK(xs_policy_destroy(next) == XS_OK);
    }

    /* Argument validation: null outputs and lengths without bytes. */
    {
        XsBytes dangling = {NULL, 4};
        XsDocument unused = {0};
        CHECK(xs_policy_store_load(store, NULL, NULL) == XS_INVALID_ARGUMENT);
        CHECK(xs_document_parse(policy, XS_OPERATION_VERIFY, dangling, &unused, NULL) ==
              XS_INVALID_ARGUMENT);
        CHECK(xs_document_parse(policy, 99, text("<a/>"), &unused, NULL) == XS_INVALID_ARGUMENT);
    }

    CHECK(xs_policy_destroy(policy) == XS_OK);
    CHECK(xs_policy_destroy(policy) == XS_DESTROYED_HANDLE);
    CHECK(xs_policy_store_destroy(store) == XS_OK);
    CHECK(xs_provider_destroy(provider) == XS_OK);
    free(private_pem);
    free(public_pem);

    if (failures != 0) {
        fprintf(stderr, "%d checks failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
