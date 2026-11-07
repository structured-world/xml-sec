/*
 * xml_sec.h: the stable C ABI of xml-sec.
 *
 * Every object is reached through a typed handle: a slot index and generation
 * in a table the library owns, never a pointer. A wrong, stale, destroyed or
 * concurrently used handle is reported as a status. Every function returns an
 * xs_status; a failing call that receives a non-null `error` stores an error
 * handle there (zero when no detail could be recorded), which the caller
 * destroys with xs_error_destroy. A successful call stores a zero handle.
 * Other outputs are written only when the call succeeds. Pointer parameters
 * must not be null unless their declaration says they may be; `error` always
 * may be.
 *
 * Handles may be used from any thread. A document serves one operation at a
 * time (another one returns XS_BUSY); every other object serves concurrent
 * calls.
 *
 * Byte strings are borrowed for the duration of the call only. Text the
 * library returns as XsBytes is borrowed from the handle it was read from and
 * stays valid until that handle is destroyed. Buffers the library allocates
 * are released with xs_buffer_free.
 *
 * Policy comes only from schema-v1 TOML configuration compiled into a policy
 * store; operations run against one immutable snapshot loaded from it.
 */
#ifndef XML_SEC_H
#define XML_SEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI revision this header describes; compare with xs_abi_version(). */
#define XS_ABI_VERSION 1u

typedef int32_t xs_status;

#define XS_OK 0
#define XS_INVALID_ARGUMENT 1
#define XS_WRONG_HANDLE 2
#define XS_STALE_HANDLE 3
#define XS_DESTROYED_HANDLE 4
#define XS_BUSY 5
#define XS_HANDLE_LIMIT 6
#define XS_OPERATION_DISABLED 7
#define XS_POLICY 8
#define XS_CONFIGURATION 9
#define XS_DOCUMENT 10
#define XS_KEY 11
#define XS_VERIFICATION 12
#define XS_SIGNING 13
#define XS_ENCRYPTION 14
#define XS_CANONICALIZATION 15
#define XS_INTERNAL 16

/* Operations whose compiled policy applies. */
#define XS_OPERATION_VERIFY 1u
#define XS_OPERATION_SIGN 2u
#define XS_OPERATION_ENCRYPT 3u
#define XS_OPERATION_DECRYPT 4u

/* Key usage bits. */
#define XS_KEY_USAGE_SIGN 1u
#define XS_KEY_USAGE_VERIFY 2u
#define XS_KEY_USAGE_ENCRYPT 4u
#define XS_KEY_USAGE_DECRYPT 8u

/* Symmetric key kinds. */
#define XS_SYMMETRIC_HMAC 1u
#define XS_SYMMETRIC_AES 2u
#define XS_SYMMETRIC_CAMELLIA 3u
#define XS_SYMMETRIC_CHACHA20 4u

/* How many signatures a verification requires to pass. */
#define XS_REQUIRE_ALL 0u
#define XS_REQUIRE_AT_LEAST 1u
#define XS_REQUIRE_EXACTLY 2u

/* Outcome of one signature. */
#define XS_SIGNATURE_VALID 1u
#define XS_SIGNATURE_INVALID 2u
#define XS_SIGNATURE_FAILED 3u

/* Trust in the key of a signature that verified or did not. */
#define XS_KEY_TRUST_NOT_EVALUATED 1u
#define XS_KEY_TRUST_NOT_ESTABLISHED 2u
#define XS_KEY_TRUST_CALLER_TRUSTED 3u
#define XS_KEY_TRUST_VALIDATED_X509 4u

/* Kinds of policy decision; zero names a kind this header does not know. */
#define XS_DECISION_ALGORITHM 1u
#define XS_DECISION_URI 2u
#define XS_DECISION_MANIFESTS 3u
#define XS_DECISION_EXCEPTION 4u
#define XS_DECISION_REJECTED 5u

#define XS_ALGORITHM_ROLE_SIGNATURE 1u
#define XS_ALGORITHM_ROLE_CANONICALIZATION 2u
#define XS_ALGORITHM_ROLE_DIGEST 3u
#define XS_ALGORITHM_ROLE_TRANSFORM 4u
#define XS_ALGORITHM_ROLE_DATA_ENCRYPTION 5u
#define XS_ALGORITHM_ROLE_KEY_TRANSPORT 6u
#define XS_ALGORITHM_ROLE_KEY_WRAP 7u

#define XS_URI_ROLE_REFERENCE 1u
#define XS_URI_ROLE_MANIFEST_REFERENCE 2u
#define XS_URI_ROLE_CIPHER_REFERENCE 3u

#define XS_URI_CLASS_EMPTY 1u
#define XS_URI_CLASS_SAME_DOCUMENT 2u
#define XS_URI_CLASS_EXTERNAL 3u

#define XS_MANIFESTS_IGNORE 1u
#define XS_MANIFESTS_PROCESS 2u

/* What a policy refused; zero names a kind this header does not know. */
#define XS_VIOLATION_CONFIGURATION 1u
#define XS_VIOLATION_MANIFEST_PROCESSING_DISABLED 2u
#define XS_VIOLATION_ATTESTED_DIGEST_FORBIDDEN 3u
#define XS_VIOLATION_SIGNATURE_PROFILE 4u
#define XS_VIOLATION_AUTHORIZATION_EXPIRED 5u
#define XS_VIOLATION_ALGORITHM 6u
#define XS_VIOLATION_HMAC_OUTPUT_LENGTH 7u
#define XS_VIOLATION_RESOURCE_LIMIT 8u
#define XS_VIOLATION_KDF_ITERATIONS 9u
#define XS_VIOLATION_INVALID_RESOURCE_LIMIT 10u
#define XS_VIOLATION_KEY_TRUST 11u
#define XS_VIOLATION_XML_INPUT 12u
#define XS_VIOLATION_URI 13u
#define XS_VIOLATION_KEY_SIZE 14u
#define XS_VIOLATION_INVALID_KEY_MATERIAL 15u

/* A borrowed byte string: ptr may be null only when len is zero. */
typedef struct XsBytes {
    const uint8_t *ptr;
    size_t len;
} XsBytes;

/* Bytes the library allocated; release them with xs_buffer_free. */
typedef struct XsBuffer {
    uint8_t *ptr;
    size_t len;
} XsBuffer;

/* Handles: zero names nothing. */
typedef struct XsProvider { uint64_t value; } XsProvider;
typedef struct XsPolicyStore { uint64_t value; } XsPolicyStore;
typedef struct XsPolicy { uint64_t value; } XsPolicy;
typedef struct XsKeys { uint64_t value; } XsKeys;
typedef struct XsDocument { uint64_t value; } XsDocument;
typedef struct XsSigner { uint64_t value; } XsSigner;
typedef struct XsVerifier { uint64_t value; } XsVerifier;
typedef struct XsEncryptor { uint64_t value; } XsEncryptor;
typedef struct XsDecryptor { uint64_t value; } XsDecryptor;
typedef struct XsEvidence { uint64_t value; } XsEvidence;
typedef struct XsAudit { uint64_t value; } XsAudit;
typedef struct XsError { uint64_t value; } XsError;

/* Promises the caller makes to every operation using the compiled policy. */
typedef struct XsCompileContext {
    /* Nonzero: every applicable call supplies its external-resource map. */
    uint8_t external_resources;
    /* Nonzero: every verification names its expected targets. */
    uint8_t target_evidence;
} XsCompileContext;

/* An exception grant the application authenticated. */
typedef struct XsAuthorization {
    XsBytes authorization_id;
    XsBytes authority;
    XsBytes reason;
    /* Inclusive start and exclusive end, Unix seconds and nanoseconds. */
    int64_t not_before_seconds;
    uint32_t not_before_nanos;
    int64_t expires_at_seconds;
    uint32_t expires_at_nanos;
} XsAuthorization;

/* What a verification must establish. */
typedef struct XsVerifyRequest {
    /* IDs of the elements that must be authenticated. */
    const XsBytes *expected_target_ids;
    size_t expected_target_count;
    /* XS_REQUIRE_*, with the signature count it names. */
    uint32_t requirement;
    size_t count;
} XsVerifyRequest;

/* The outcome of one signature in an evidence handle. */
typedef struct XsSignatureOutcome {
    uint32_t outcome;   /* XS_SIGNATURE_* */
    uint32_t key_trust; /* XS_KEY_TRUST_*; zero for a failed verification */
} XsSignatureOutcome;

/* The published snapshot an operation enforced. */
typedef struct XsPolicyIdentity {
    /* Nonzero when the policy was a published snapshot. */
    uint8_t present;
    uint32_t schema_version;
    uint64_t revision;
    /* SHA-256 of the canonical effective settings. */
    uint8_t digest[32];
    /* Borrowed from the handle the identity was read from. */
    XsBytes profile;
} XsPolicyIdentity;

/* One policy decision, borrowed from its audit handle. */
typedef struct XsDecision {
    uint32_t kind;      /* XS_DECISION_* */
    uint32_t role;      /* XS_ALGORITHM_ROLE_* or XS_URI_ROLE_*, by kind */
    uint32_t uri_class; /* XS_URI_CLASS_* of a URI decision */
    uint32_t manifests; /* XS_MANIFESTS_* of a Manifest decision */
    uint32_t violation; /* XS_VIOLATION_* of a refusal */
    /* Algorithm URI, exception authorization ID or refusal message. */
    XsBytes text;
} XsDecision;

/* The ABI revision of the loaded library. */
uint32_t xs_abi_version(void);

/* Engines. */
xs_status xs_provider_new_rustcrypto(XsProvider *out, XsError *error);
/* Present only in libraries built with the AWS-LC FIPS engine. */
xs_status xs_provider_new_aws_lc_fips(XsProvider *out, XsError *error);

/* Compile `profile` of the TOML `configuration` and publish it as revision 1.
 * `authorization` may be null. */
xs_status xs_policy_store_new(XsBytes configuration, XsBytes profile, XsProvider provider,
                              const XsCompileContext *context,
                              const XsAuthorization *authorization, XsPolicyStore *out,
                              XsError *error);
/* Compile a replacement completely, then publish it atomically as the next
 * revision; a refused replacement publishes nothing. */
xs_status xs_policy_store_replace(XsPolicyStore store, XsBytes configuration, XsBytes profile,
                                  XsProvider provider, const XsCompileContext *context,
                                  const XsAuthorization *authorization, XsError *error);
/* The current snapshot; later publications do not change it. */
xs_status xs_policy_store_load(XsPolicyStore store, XsPolicy *out, XsError *error);
/* The identity of a loaded snapshot. */
xs_status xs_policy_identity(XsPolicy policy, XsPolicyIdentity *identity, XsError *error);

/* Key managers, bounded by the resource policy of `operation`. */
xs_status xs_keys_new(XsPolicy policy, uint32_t operation, XsKeys *out, XsError *error);
/* An empty `password` means an unencrypted key. */
xs_status xs_keys_add_private_pem(XsKeys keys, XsBytes name, XsBytes pem, XsBytes password,
                                  uint32_t usages, XsError *error);
xs_status xs_keys_add_public_pem(XsKeys keys, XsBytes name, XsBytes pem, uint32_t usages,
                                 XsError *error);
xs_status xs_keys_add_symmetric(XsKeys keys, XsBytes name, uint32_t kind, XsBytes key,
                                uint32_t usages, XsError *error);

/* Documents, parsed under the compiled policy of `operation`. */
xs_status xs_document_parse(XsPolicy policy, uint32_t operation, XsBytes xml, XsDocument *out,
                            XsError *error);
xs_status xs_document_serialize(XsDocument document, XsBuffer *out, XsError *error);
void xs_buffer_free(XsBuffer buffer);

/* Signing: fills the document's signature template as one new generation.
 * `audit` may be null. */
xs_status xs_signer_new(XsPolicy policy, XsProvider provider, XsKeys keys, XsBytes key_name,
                        XsBytes signature_method, XsSigner *out, XsError *error);
xs_status xs_sign(XsSigner signer, XsDocument document, XsAudit *audit, XsError *error);

/* Verification: `keys` may be the zero handle. Success is a report, not
 * acceptance: ask xs_evidence_accepted with the same document. */
xs_status xs_verifier_new(XsPolicy policy, XsProvider provider, XsKeys keys, XsVerifier *out,
                          XsError *error);
xs_status xs_verify(XsVerifier verifier, XsDocument document, const XsVerifyRequest *request,
                    XsEvidence *out, XsError *error);

/* Encryption for an RSA-OAEP recipient. An empty `element_id` encrypts the
 * root. `audit` may be null. */
xs_status xs_encryptor_new(XsPolicy policy, XsProvider provider, XsKeys keys, XsBytes recipient,
                           XsBytes content_method, XsEncryptor *out, XsError *error);
xs_status xs_encrypt(XsEncryptor encryptor, XsDocument document, XsBytes element_id,
                     XsAudit *audit, XsError *error);

/* Decryption. An empty `encrypted_data_id` recovers the first EncryptedData.
 * `audit` may be null. */
xs_status xs_decryptor_new(XsPolicy policy, XsProvider provider, XsKeys keys, XsBytes key_name,
                           XsDecryptor *out, XsError *error);
xs_status xs_decrypt(XsDecryptor decryptor, XsDocument document, XsBytes encrypted_data_id,
                     XsAudit *audit, XsError *error);

/* Evidence. */
xs_status xs_evidence_accepted(XsEvidence evidence, XsDocument document, uint8_t *accepted,
                               XsError *error);
xs_status xs_evidence_signature_count(XsEvidence evidence, size_t *count, XsError *error);
xs_status xs_evidence_signature(XsEvidence evidence, size_t index, XsSignatureOutcome *outcome,
                                XsError *error);
xs_status xs_evidence_signature_audit(XsEvidence evidence, size_t index, XsAudit *audit,
                                      XsError *error);
xs_status xs_evidence_policy_identity(XsEvidence evidence, XsPolicyIdentity *identity,
                                      XsError *error);

/* Audits. */
xs_status xs_audit_policy_identity(XsAudit audit, XsPolicyIdentity *identity, XsError *error);
xs_status xs_audit_decision_count(XsAudit audit, size_t *count, XsError *error);
xs_status xs_audit_decision(XsAudit audit, size_t index, XsDecision *decision, XsError *error);

/* Errors: the status the failed call returned, the XS_VIOLATION_* of a policy
 * refusal (zero otherwise) and the diagnostic message. */
xs_status xs_error_status(XsError error, xs_status *status);
xs_status xs_error_policy_violation(XsError error, uint32_t *violation);
xs_status xs_error_message(XsError error, XsBytes *message);

/* Destruction: XS_DESTROYED_HANDLE for a second destruction, XS_BUSY while a
 * running call uses the object. Objects holding another keep it alive. */
xs_status xs_provider_destroy(XsProvider handle);
xs_status xs_policy_store_destroy(XsPolicyStore handle);
xs_status xs_policy_destroy(XsPolicy handle);
xs_status xs_keys_destroy(XsKeys handle);
xs_status xs_document_destroy(XsDocument handle);
xs_status xs_signer_destroy(XsSigner handle);
xs_status xs_verifier_destroy(XsVerifier handle);
xs_status xs_encryptor_destroy(XsEncryptor handle);
xs_status xs_decryptor_destroy(XsDecryptor handle);
xs_status xs_evidence_destroy(XsEvidence handle);
xs_status xs_audit_destroy(XsAudit handle);
xs_status xs_error_destroy(XsError handle);

#ifdef __cplusplus
}
#endif

#endif /* XML_SEC_H */
