// Uses the C ABI from C++ through owning wrappers, the way a C++ application
// would: the header compiles as C++, handles are trivially copyable values,
// and destruction is tied to scope.
#include "xml_sec.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <utility>

static_assert(std::is_standard_layout<XsBytes>::value, "XsBytes is a C structure");
static_assert(std::is_trivially_copyable<XsPolicy>::value, "handles are plain values");
static_assert(sizeof(XsPolicy) == sizeof(uint64_t), "a handle is one 64-bit value");

namespace {

int failures = 0;

void check(bool condition, const char *what) {
    if (!condition) {
        std::fprintf(stderr, "check failed: %s\n", what);
        ++failures;
    }
}

XsBytes bytes(const std::string &value) {
    return XsBytes{reinterpret_cast<const uint8_t *>(value.data()), value.size()};
}

// Owns one handle and destroys it at scope end.
template <typename Handle, xs_status (*Destroy)(Handle)> class Owned {
  public:
    Owned() = default;
    Owned(const Owned &) = delete;
    Owned &operator=(const Owned &) = delete;
    ~Owned() {
        if (handle_.value != 0) {
            check(Destroy(handle_) == XS_OK, "destroyed at scope end");
        }
    }
    Handle *out() { return &handle_; }
    Handle get() const { return handle_; }

  private:
    Handle handle_{};
};

using Provider = Owned<XsProvider, xs_provider_destroy>;
using Store = Owned<XsPolicyStore, xs_policy_store_destroy>;
using Policy = Owned<XsPolicy, xs_policy_destroy>;
using Document = Owned<XsDocument, xs_document_destroy>;
using Error = Owned<XsError, xs_error_destroy>;
using Keys = Owned<XsKeys, xs_keys_destroy>;
using Signer = Owned<XsSigner, xs_signer_destroy>;
using Verifier = Owned<XsVerifier, xs_verifier_destroy>;
using Evidence = Owned<XsEvidence, xs_evidence_destroy>;

const char HMAC_SHA256[] = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

std::string serialize(XsDocument document) {
    XsBuffer buffer{};
    check(xs_document_serialize(document, &buffer, nullptr) == XS_OK, "serialize");
    std::string xml(reinterpret_cast<const char *>(buffer.ptr), buffer.len);
    xs_buffer_free(buffer);
    return xml;
}

// The key a lookup finds, and how often it was asked.
struct MacStore {
    std::string secret;
    int calls = 0;
};

std::string message(const Error &error) {
    XsBytes text{};
    if (xs_error_message(error.get(), &text) != XS_OK) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(text.ptr), text.len);
}

} // namespace

int main() {
    const std::string configuration = "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n";
    const XsCompileContext context{0, 1};
    Provider provider;
    Store store;
    Policy policy;

    check(xs_provider_new_rustcrypto(provider.out(), nullptr) == XS_OK, "provider");
    check(xs_policy_store_new(bytes(configuration), bytes("app"), provider.get(), &context,
                              nullptr, store.out(), nullptr) == XS_OK,
          "store");
    check(xs_policy_store_load(store.get(), policy.out(), nullptr) == XS_OK, "load");

    XsPolicyIdentity identity{};
    check(xs_policy_identity(policy.get(), &identity, nullptr) == XS_OK, "identity");
    check(identity.present == 1 && identity.revision == 1, "revision 1");
    check(std::string(reinterpret_cast<const char *>(identity.profile.ptr),
                      identity.profile.len) == "app",
          "profile name");

    {
        Document document;
        check(xs_document_parse(policy.get(), XS_OPERATION_VERIFY, bytes("<root><a/></root>"),
                                document.out(), nullptr) == XS_OK,
              "parse");
        XsBuffer buffer{};
        check(xs_document_serialize(document.get(), &buffer, nullptr) == XS_OK, "serialize");
        std::string xml(reinterpret_cast<const char *>(buffer.ptr), buffer.len);
        xs_buffer_free(buffer);
        check(xml.find("<a/>") != std::string::npos, "serialized content");
    }

    {
        Document document;
        Error error;
        check(xs_document_parse(policy.get(), XS_OPERATION_VERIFY, bytes("<broken"),
                                document.out(), error.out()) == XS_DOCUMENT,
              "malformed XML is a document failure");
        check(!message(error).empty(), "error message");
    }

    {
        Store refused;
        Error error;
        check(xs_policy_store_new(bytes(configuration), bytes("missing"), provider.get(),
                                  &context, nullptr, refused.out(), error.out()) != XS_OK,
              "an unknown profile is refused");
        check(refused.get().value == 0, "no store on failure");
        check(error.get().value != 0, "an error handle on failure");
    }

    // Sign with an HMAC key, then verify with that key supplied only by a key
    // lookup: a captureless lambda is the C function pointer the header names.
    {
        const std::string templ =
            "<root><p Id=\"payload\">signed</p>"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>"
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>"
            "<ds:Reference URI=\"#payload\"><ds:Transforms>"
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>"
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
            "<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>"
            "<ds:SignatureValue></ds:SignatureValue>"
            "<ds:KeyInfo><ds:KeyName>mac</ds:KeyName></ds:KeyInfo></ds:Signature></root>";
        MacStore mac_store;
        mac_store.secret = std::string(32, 'k');
        std::string signed_xml;
        {
            Keys keys;
            Signer signer;
            Document document;
            check(xs_keys_new(policy.get(), XS_OPERATION_SIGN, keys.out(), nullptr) == XS_OK,
                  "signing keys");
            check(xs_keys_add_symmetric(keys.get(), bytes("mac"), XS_SYMMETRIC_HMAC,
                                        bytes(mac_store.secret), XS_KEY_USAGE_SIGN,
                                        nullptr) == XS_OK,
                  "HMAC key");
            check(xs_signer_new(policy.get(), provider.get(), keys.get(), bytes("mac"),
                                bytes(HMAC_SHA256), signer.out(), nullptr) == XS_OK,
                  "signer");
            check(xs_document_parse(policy.get(), XS_OPERATION_SIGN, bytes(templ),
                                    document.out(), nullptr) == XS_OK,
                  "template");
            check(xs_sign(signer.get(), document.get(), nullptr, nullptr) == XS_OK, "sign");
            signed_xml = serialize(document.get());
        }
        Verifier verifier;
        Document received;
        Evidence evidence;
        check(xs_verifier_new(policy.get(), provider.get(), XsKeys{}, verifier.out(), nullptr) ==
                  XS_OK,
              "keyless verifier");
        check(xs_document_parse(policy.get(), XS_OPERATION_VERIFY, bytes(signed_xml),
                                received.out(), nullptr) == XS_OK,
              "signed document");
        const XsKeyLookup lookup{
            [](void *user_data, const XsKeyQuery *query, XsKeys keys) -> xs_status {
                auto *found = static_cast<MacStore *>(user_data);
                ++found->calls;
                if (query->name_count != 1) {
                    return XS_KEY;
                }
                return xs_keys_add_symmetric(keys, query->names[0], XS_SYMMETRIC_HMAC,
                                             bytes(found->secret), XS_KEY_USAGE_VERIFY, nullptr);
            },
            &mac_store};
        // The request borrows the ID's bytes, so they outlive the call.
        const std::string payload = "payload";
        const XsBytes ids[1] = {bytes(payload)};
        const XsVerifyRequest request{ids, 1, XS_REQUIRE_ALL, 0};
        check(xs_verify(verifier.get(), received.get(), &request, &lookup, evidence.out(),
                        nullptr) == XS_OK,
              "verify through the lookup");
        XsSignatureOutcome outcome{};
        check(xs_evidence_signature(evidence.get(), 0, &outcome, nullptr) == XS_OK, "outcome");
        check(outcome.outcome == XS_SIGNATURE_VALID, "the looked-up key verifies");
        check(mac_store.calls == 1, "asked once");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d checks failed\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
